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
				$this->startTlsDeferred->resolve();
			});
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
			$this->queueRequest($request);
		} else {
			$this->connect()->done(function () use ($bind_rdn, $bind_password, $request) {
				echo "connected, sending bindRequest".PHP_EOL;
				$this->queueRequest($request);
			});
		}

		return Timer\timeout($this->deferred->promise(), $this->options['timeout'], $this->loop);
	}

	public function unbind()
	{
		$request = new Request\Unbind($this->messageID++);

		return $this->queueRequest($request);
	}

	public function startTLS()
	{
		$this->startTlsDeferred = new Deferred();

		$this->connect()->done(function () use ($bind_rdn, $bind_password) {
			$starttls = new Request\StartTls($this->messageID++);
			$this->queueRequest($starttls);
		});

		return Timer\timeout($this->startTlsDeferred->promise(), $this->options['timeout'], $this->loop);
	}

	/**
	 * options: base, filter
	 */
	public function search($options)
	{
		$request = new Request\Search($this->messageID++, $options);

		return $this->queueRequest($request);
	}

	private function queueRequest($request)
	{
		$this->asyncRequests->enqueue($request);
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
	{
		$request = new Request\Modify($this->messageID++, $dn, $changes);

		return $this->queueRequest($request);
	}

	public function add($entry, $attributes)
	{
		$request = new Request\Add($this->messageID++, $entry, $attributes);

		return $this->queueRequest($request);
	}

	public function delete($dn)
	{
		$request = new Request\Delete($this->messageID++, $dn);

		return $this->queueRequest($request);
	}

	public function modDN($entry, $newrdn, $deleteoldrnd = true, $newsuperior = '')
	{
		$request = new Request\ModDn($this->messageID++, $newrdn, $deleteoldrnd, $newsuperior);

		return $this->queueRequest($request);
	}

	public function compare($entry, $attributeDesc, $assertionValue)
	{
		$request = new Request\Compare($this->messageID++, $entry, $attributeDesc, $assertionValue);

		return $this->queueRequest($request);
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
