<?php

namespace Fneufneu\React\Ldap;

use Evenement\EventEmitter;
use React\EventLoop\LoopInterface;
use React\Socket\ConnectorInterface;
use React\Socket\Connector;
use React\Promise;
use React\Promise\Deferred;
use React\Promise\Timer;
use Fneufneu\React\Ldap\Result;
use Fneufneu\React\Ldap\Request;
use Fneufneu\React\Ldap\Parser;

class Client extends EventEmitter
{
	public $options = array(
		'timeout' => 10,
	);
	private $loop;
	private $connnector;
	private $connected;
	private $stream;
	private $uri;
	private $buffer;
	private $deferred;
	private $requests;
	private $asyncRequests;
	private $parser;

	function __construct(LoopInterface $loop, string $uri, $options = array())
	{
		$this->options = $options + $this->options + array(
			'uri' => $uri,
			'connector' => null,
			'dn' => null,
			'password' => null
		);

		if ($options['connector'] instanceof ConnectorInterface) {
			$this->connector = $options['connector'];
		} else {
			$this->connector = new Connector($loop, array('timeout' => $this->options['timeout']));
		}

		$this->parser = new Parser();
		$this->buffer = '';
		$this->connected = false;
		$this->uri = $uri;
		$this->loop = $loop;
		$this->asyncRequests = new \SplQueue();
	}

	private function sendldapmessage($pdu, $successCode = 0)
	{
		// TODO messageID not avaible now
		printf("[%d] sendldapmessage %d bytes".PHP_EOL,
			$this->messageID - 1, strlen($pdu));
		return $this->stream->write($pdu);
	}
	
	public function handleData($data)
	{
		if ($this->buffer != '') {
			$data = $this->buffer . $data;
			$this->buffer = '';
		}
		//printf("handleData (%d bytes)".PHP_EOL, strlen($data));
		$message = $this->parser->decode($data);
		if (!$message) {
			// incomplet data
			$this->buffer = $data;
			return;
		}

		$result = $this->requests[$message['messageID']];

		if ($message['protocolOp'] == 'bindResponse') {
			if (0 != $message['resultCode']) {
				$this->deferred->reject(new \RuntimeException($message['diagnosticMessage']));
			} else {
				$this->deferred->resolve();
			}
		} elseif (0 != $message['resultCode']) {
			$result->emit('error', array(new \RuntimeException($message['diagnosticMessage'])));
			$this->emit('error', array(new \RuntimeException($message['diagnosticMessage'])));
		} elseif ($message['protocolOp'] == 'extendedResp') {
			$streamEncryption = new \React\Socket\StreamEncryption($this->loop, false);
			$streamEncryption->enable($this->stream)->then(function () {
				$this->deferred->resolve();
			});
			return;
		} elseif ($message['protocolOp'] == 'searchResEntry') {
			$message = $this->searchResEntry($message);
			$result->data[] = $message;
			$result->emit('data', array($message));
			//$this->emit('data', array($message));
		} else {
			if ($result) {
				$result->emit('end', array($result->data));
				unset($this->requests[$message['messageID']]);
			}
		}
		if ($message['protocolOp'] == $this->expectedAnswer) {
			$this->expectedAnswer = '';
			$this->pollRequests();
		}

		//printf('data left: %d bytes'.PHP_EOL, strlen($data));
		if (strlen($data) > 0)
			$this->handleData($data);
		
	}

	private function searchResEntry($response)
	{
		$res = $response['attributes'];
		foreach ($res as $k => $v) {
			if (is_array($v) and 1 == count($v))
				$res[$k] = array_shift($v);
		}
		$res['dn'] = $response['objectName'];
		return $res;
	}

	private function connect()
	{
		$url = $this->options['uri'];

		$defaultport = array(null => '389', 'ldap' => '389', 'ldaps' => '636', 'ldaptls' => '389');
		if (! preg_match('/^(?:(ldap(?:|s|tls))(?::\/\/))?(.+?):?(\d+)?$/', $url, $d)) {
			throw new \InvalidArgumentException('invalid uri: '.$url);
		}
		list($dummy, $protocol, $address, $port) = $d;
		if (!$port)
			$port = $defaultport[$protocol];
		$transport = $protocol == 'ldaps' ? 'tls://' : 'tcp://';
		#print_r("$transport$address:$port");

		// TODO
		//if ($protocol == 'ldaptls')
		//	return $this->startTLS();

		$streamRef =& $this->stream;
	 	$promise = $this->connector->connect("$transport$address:$port")
			->then(function (\React\Socket\ConnectionInterface $stream) use (&$streamRef) {
				$streamRef = $stream;
				$stream->on('data', array($this, 'handleData'));
				$stream->on('end', function () {
					echo "connection ended".PHP_EOL;
				});
				$stream->on('close', function () {
					echo "connection closed".PHP_EOL;
					$this->connected = false;
					$this->emit('end');
				});
				$stream->on('error', function (Exception $e) {
					echo "connection error ".$e->getMessage().PHP_EOL;
					$this->emit('error', array($e));
				});
				$this->connected = true;
				$this->pollRequests();
			}, function (Exception $error) {
				echo "error: ".$error->getMessage().PHP_EOL;
				$this->deferred->reject($error);
			});

		return $promise;
	}

	public function bind($bind_rdn = NULL, $bind_password = NULL)
	{
		$this->deferred = new Deferred();

		$request = new Request\Bind($this->messageID++, $bind_rdn, $bind_password);

		if ($this->connected) {
			echo "already connected, sending bindRequest".PHP_EOL;
			$this->sendldapmessage($request->toString());
		} else {
			$this->connect()->done(function () use ($bind_rdn, $bind_password) {
				echo "connected, sending bindRequest".PHP_EOL;
				$this->sendldapmessage($request->toString());
			});
		}

		return Timer\timeout($this->deferred->promise(), $this->options['timeout'], $this->loop);
	}

	public function unbind()
	{
		$request = new Request\Unbind($this->messageID++);

		return $this->sendldapmessage($request->toString());
	}

	public function startTLS()
	{
		$this->deferred = new Deferred();

		$this->connect()->done(function () use ($bind_rdn, $bind_password) {
			$starttls = new Request\StartTls($this->messageID++);
			$result = new Result();
			$this->requests[$this->messageID] = $result;
			$this->sendldapmessage($starttls->toString());
		});

		return Timer\timeout($this->deferred->promise(), $this->options['timeout'], $this->loop);
	}

	/**
	 * options: base, filter
	 */
	public function search($options)
	{
		echo "new Request\Search\n";
		$request = new Request\Search($this->messageID++, $options);
		echo "Request\Search OK\n";

		$this->asyncRequests->enqueue($request);
		printf("asyncRequests=%d\n", $this->asyncRequests->count());
		$result = new Result();
		$this->requests[$request->messageId] = $result;
		$this->pollRequests();

		return $result;
	}

	private function pollRequests()
	{
		echo "pollRequests".PHP_EOL;
		if ($this->asyncRequests->isEmpty())
			return;
		if (!$this->connected)
			return;
		if ('' != $this->expectedAnswer)
			return;
		echo ".".PHP_EOL;

		$request = $this->asyncRequests->dequeue();
		$this->expectedAnswer = $request->expectedAnswer;
		$this->sendldapmessage($request->toString());
	}
	/*
	public function nextentry()
	{
		unset($this->cookie);
		$response = $this->receiveldapmessage();
		if ($response['protocolOp'] == 'searchResEntry')
			return self::searchResEntry($response);

		$this->status = $response;
		$this->handleresult();
		foreach($response['controls'] as $control) {
			if ($control['controlType'] == '1.2.840.113556.1.4.319') {
				$cookiepdu = $control['controlValue'];
				$struct = self::berdecode($cookiepdu, strlen($cookiepdu));
				$this->cookie = $struct[0]['value'][1]['value'];
			}
		}
		return false;
	}

	public function getpage($base, $filter, $attributes, $paged = false)
	{
		if ($paged && !$this->cookie) return false;
		$this->search($base, $filter, $attributes);
		while ($entry = $this->nextentry()) {
			$res[] = $entry;
		}
		return $res;
	}
	*/

	public function modify($dn, $changes)
	{ # $changes is array of mods
		$ops = array('add' => 0, 'delete' => 1, 'replace' => 2);
		$pdu = '';
		foreach ($changes as $operation) {
			foreach ($operation as $type => $modification) {
				$pdu = "";
				foreach ($modification as $attributeDesc => $attributeValues) {
					foreach ($attributeValues as $attributeValue) {
						$pdu .= self::octetstring($attributeValue);
					}
					$pdu = self::sequence(self::octetstring($attributeDesc) . self::set($pdu));
				}
				$pdux .= self::sequence(self::enumeration($ops[$type]) . $pdu);
			}
		}
		$pdu = self::LDAPMessage(self::modifyRequest, self::octetstring($dn) . self::sequence($pdux));
		return $this->sendldapmessage($pdu);
	}

	public function add($entry, $attributes)
	{
		foreach ($attributes as $attributeDesc => $attributeValues) {
			$pdu = '';
			if (!is_array($attributeValues)) $attributeValues = array($attributeValues);
			foreach ($attributeValues as $attributeValue) {
				$pdu .= self::octetstring($attributeValue);
			}
			$pdux .= self::sequence(self::octetstring($attributeDesc) . self::set($pdu));
		}
		$pdu = self::LDAPMessage(self::addRequest, self::octetstring($entry) . self::sequence($pdux));
		return $this->sendldapmessage($pdu);
	}

	public function del($dn)
	{
		$pdu = self::sequence(self::integer($this->messageID++) . self::application(self::delRequest, $dn, false));
		return $this->sendldapmessage($pdu);
	}

	public function modDN($entry, $newrdn, $deleteoldrnd = true, $newsuperior = '')
	{
		$pdu = self::LDAPMessage(self::modDNRequest, self::octetstring($entry)
			 . self::octetstring($newrdn)
			 . self::boolean($deleteoldrnd)
			 . ($newsuperior ? "\x80" . self::len($newsuperior) . $newsuperior : ''));
		return $this->sendldapmessage($pdu);
	}

	public function compare($entry, $attributeDesc, $assertionValue)
	{
		$payload = self::sequence(self::octetstring($attributeDesc) . self::octetstring($assertionValue));
		$pdu = self::LDAPMessage(self::compareRequest, self::octetstring($entry) .  $payload); #. "\xa3" .
		return $this->sendldapmessage($pdu, self::compareTrue);
	}

	public function pp($base, $filter = 'objectclass=*', $attributes = array())
	{
		$c = 0;
		$indent = 30;
		$paged = 0;
		while ($entries = $this->getpage($base, $filter, $attributes, $paged++)) {
			#continue;
			foreach ((array)$entries as $entry) {
				printf("\n%$indent" . "s: %s\n", 'c', $c++);
				printf("%$indent" . "s: %s\n", 'dn', $entry['dn']);
				unset($entry['dn']);
				ksort($entry);
				foreach ($entry as $attr => $vals) {
					foreach ($vals as $val) {
						if (preg_match("/[[:cntrl:]]/", $val)) $val = '* ' . bin2hex($val);
						printf("%$indent" . "s: %s\n", $attr, $val);
						$attr = '';
					}
				}
			}
		}
		$status = $this->status();
		if ($status['resultCode']) print_r($status);
	}
}
