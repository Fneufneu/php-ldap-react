<?php

namespace Fneufneu\React\Ldap;

use React\EventLoop\LoopInterface;
use React\Socket\ConnectorInterface;
use React\Socket\Connector;
use React\Promise;
use React\Promise\Deferred;
use Fneufneu\React\Ldap\Result;

class Client extends Ldap
{
	public $status;
	public $options = array(
		'sizelimit' => 0,
		'timelimit' => 0,
		'scope' => self::wholeSubtree,
		'typesonly' => false,
		'pagesize' => 0,
		'resultfilter' => '',
	);
	private $connnector;
	private $connected;
	private $stream;
	private $uri;
	private $buffer;
	private $bindDeferred;
	private $requests;

	// function __construct($server, $dn = null, $pw = null)
	function __construct(LoopInterface $loop, string $uri, $options = array())
	{
		parent::__construct();

		$this->options = $options + $this->options + array(
			'uri' => $uri,
			'connector' => null,
			'dn' => null,
			'password' => null
		);

		if ($options['connector'] instanceof ConnectorInterface) {
			$this->connector = $options['connector'];
		} else {
			$this->connector = new Connector($loop);
		}

		$this->connected = false;
		$this->uri = $uri;
	}

	static function filter($filter)
	{
		# extensibleMatch not supported ...
		if (!preg_match("/^\(.*\)$/", $filter)) $filter = '(' . $filter . ')';
		$elements = preg_split("/(\(|\)|~=|>=|<=|=\*\)|\*|=|&|\||!|\\\\[a-z0-9]{2})/i", $filter, -1, PREG_SPLIT_DELIM_CAPTURE + PREG_SPLIT_NO_EMPTY);
		$i = 0;
		$res = self::dofilter($elements, $i);
		if ($i - sizeof($elements) != 1)
			throw new \InvalidArgumentException("Unmatched ) or (  in filter: $filter");
		return self::filter2ber($res);
	}

	static function dofilter(&$elements, &$i)
	{
		$res = array();
		while ($element = $elements[$i++]) {
			$unescapedelement = $element;
			if (preg_match("/^\\\\([0-9a-z]{2})$/i", $element, $d)) {
				$unescapedelement = chr(hexdec($d[1]));
			}
			if ($element == '(') $res['filters'][] = self::dofilter($elements, $i);
			elseif ($element == ')') break;
			elseif (in_array($element, array('&', '|', '!'))) $res['op'] = $element;
			elseif (in_array($element, array('=', '~=', '>=', '<=', '=*)'))) {
				$res['filtertype'] = $element;
				if ($element == '=*)') break;
			} elseif ($element == '*') {
				$res['filtertype'] = $element;
				unset($res['final']);
				unset($res['assertionValue']);
			} elseif ($res['filtertype'] == '*') $res['final'] .= $res['any'][] .= $unescapedelement;
			elseif ($res['filtertype']) $res['initial'] = $res['assertionValue'] .= $unescapedelement;
			else $res['attributeDesc'] .= $unescapedelement;
		}
		if ($res['final']) array_pop($res['any']);
		return $res;
	}

	static function filter2ber($filter)
	{
		#print_r($filter);
		$ops = array('&' => "\xa0", '|' => "\xa1", '!' => "\xa2", '*' => "\xa4", '=' => "\xa3", '~=' => "\xa8", '>=' => '\xa5', '<=' => "\xa6",);
		foreach ($filter['filters'] as $f) {
			if ($f['op']) $res .= self::filter2ber($f);
			else {
				if ('=*)' == $f['filtertype']) {
					$res .= self::choice(7) . self::len($f['attributeDesc']) . $f['attributeDesc'];
				} elseif ('*' == $f['filtertype']) {
					$payload = $f['initial'] ? "\x80" . self::len($f['initial']) . $f['initial'] : '';
					foreach ((array)$f['any'] as $any) $payload .= "\x81" . self::len($any) . $any;
					$payload .= $f['final'] ? "\x82" . self::len($f['final']) . $f['final'] : '';
					$payload = self::octetstring($f['attributeDesc']) . self::sequence($payload);
					$res .= "\xa4" . self::len($payload) . $payload;
				} else {
					$payload = self::octetstring($f['attributeDesc']) . self::octetstring($f['assertionValue']);
					$res .= $ops[$f['filtertype']] . self::len($payload) . $payload;
				}
			}
		}
		if ($op = $filter['op']) return $ops[$op] . self::len($res) . $res;
		return $res;
	}

	private function handleresult($successCode = 0, $resultCode = null, $diagnosticMessage = null) {
		if ($resultCode == null) {
			$status = $this->status();
			$resultCode = $status['resultCode'];
			$diagnosticMessage = $status['diagnosticMessage'];
		} 
		if ($resultCode != $successCode && false)
			throw new Exception($diagnosticMessage, $resultCode);

		if ($this->status['protocolOp'] == 'searchResEntry')
			return self::searchResEntry($this->status);

		return $resultCode;
	}
	
	private function sendldapmessage($pdu, $successCode = 0)
	{
		printf("[%d] sendldapmessage %d bytes".PHP_EOL,
			$this->messageID - 1, strlen($pdu));
		return $this->stream->write($pdu);
	}
	
	public function result()
	{
		$this->status = $this->receiveldapmessage();
		$successCode = $this->successCode;
		unset($this->successCode);
		return $this->handleresult($successCode);
	}
	
	public function handleData($data)
	{
		printf("handleData (%d bytes)".PHP_EOL, strlen($data));
		$pdu = substr($data, 0, 2);
		$data = substr($data, 2);
		$lenlen = ord($pdu[1]);
		if ($lenlen > 0x80) {
			$pdu .= substr($data, 0, $lenlen - 0x80);
			$data = substr($data, $lenlen - 0x80);
		}
		$i = 1;
		$len = self::ber_valuelength($pdu, $i);
		$prelen = strlen($pdu);
		$pdu .= substr($data, 0, $len);
		$data = substr($data, $len);
		#self::dump($pdu);
		$message = self::berdecode($pdu, $prelen + $len);
		$message = $this->pretty($message);
		//var_dump($message);

		$result = $this->requests[$message['messageID']];
		if (0 != $message['resultCode']) {
			$this->emit('error', array(new \RuntimeException('Whoops')));
		} elseif ($message['protocolOp'] == 'bindResponse') {
			var_dump($message);
			// TODO check error
			echo "bindDeferred->resolve()".PHP_EOL;
			$this->bindDeferred->resolve();
		} elseif ($message['protocolOp'] == 'searchResEntry') {
			//$this->emit('data', array(self::searchResEntry($message)));
			$message = self::searchResEntry($message);
			$result->data[] = $message;
			$result->emit('data', array($message));
		} else {
			var_dump($message);
			//$result-> = $message['resultCode'];
			if ($result) {
				$result->emit('end', array($result->data));
				unset($this->requests[$message['messageID']]);
			}
		}
		printf('data left: %d bytes'.PHP_EOL, strlen($data));
		if (strlen($data) > 0)
			$this->handleData($data);
		
	}

	static function searchResEntry($response)
	{
		$res = $response['attributes'];
		foreach ($res as $k => $v) {
			if (is_array($v) and 1 == count($v))
				$res[$k] = array_shift($v);
		}
		$res['dn'] = $response['objectName'];
		return $res;
	}

	public function status()
	{
		return $this->status;
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
				echo "connector->connec()->then()".PHP_EOL;
				$streamRef = $stream;
				$stream->on('data', array($this, 'handleData'));
				$stream->on('end', function () {
					echo "connection ended".PHP_EOL;
				});
				$stream->on('close', function () {
					echo "connection closed".PHP_EOL;
					$this->emit('end');
				});
				$stream->on('error', function (Exception $e) {
					echo "connection error ".$e->getMessage().PHP_EOL;
					$this->emit('error', array($e));
				});
				$this->connected = true;
			}, function (Exception $error) {
				echo "error: ".$error->getMessage().PHP_EOL;
				$this->bindDeferred->reject($error);
			});

		return $promise;
	}

	protected function bindRequest($bind_rdn = NULL, $bind_password = NULL, $controls = '')
	{
		return self::LDAPMessage(self::bindRequest,
			 self::integer(self::version3)
			 . self::octetstring($bind_rdn)
			 . "\x80" . self::len($bind_password) . $bind_password,
#			. self::contextstring(0, $bind_password),
			 $controls);
	}

	protected function searchRequest($base, $filter, $attributes, $controls = '')
	{
		return self::LDAPMessage(self::searchRequest,
			 self::octetstring($base)
			 . self::enumeration($this->options['scope'])
			 . self::enumeration($this->options['derefaliases'])
			 . self::integer($this->options['sizelimit'])
			 . self::integer($this->options['timelimit'])
			 . self::boolean($this->options['typesonly'])
			 . $filter
			 . self::attributes($attributes),
			 $controls);
	}

	public function bind($bind_rdn = NULL, $bind_password = NULL)
	{
		if ($this->connected) {
			return Promise\reject(new \Exception('already connected, not supported'));
		}
		echo "bind: connect()".PHP_EOL;
		$this->bindDeferred = new Deferred();
		/* TODO timeout but need $loop
		$loop->addTimer(3, function () {
			$this->stream->close();
			$this->bindDeferred->reject(new \React\Promise\Timer\TimeoutException('timeout'));
		}); */
		$this->connect()->then(function () use ($bind_rdn, $bind_password) {
			echo "connect->then()".PHP_EOL;
			$this->sendldapmessage($this->bindRequest($bind_rdn, $bind_password));
			echo ".";
		});

		return $this->bindDeferred->promise();
	}

	public function unbind()
	{
		return $this->sendldapmessage(self::sequence(
			self::integer($this->messageID++)
			. self::application(self::unbindRequest, '', false)));
	}

	public function startTLS()
	{
		$startTLS = '1.3.6.1.4.1.1466.20037';
		$this->sendldapmessage(self::LDAPMessage(self::extendedReq, "\x80" . self::len($startTLS) . $startTLS));
		if ($this->result()
			|| !stream_socket_enable_crypto($this->fd, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) return $this->handleresult(0, 1234567890 , "startTLS failed");
	}

	public function search($base, $filter, $attributes = array())
	{
		if (!$this->connected)
			throw \RuntimeException('not connected');

		$controls = '';
		if ($pagesize = $this->options['pagesize']) {
			$controls .= self::pagedResultsControl($pagesize, $this->cookie, true);
		}
		if ($resultfilter = $this->options['resultfilter']) {
			$controls .=  self::matchedValuesControl(self::filter($resultfilter));
		}
		$result = new Result();
		$this->requests[$this->messageID] = $result;
		$message = $this->searchRequest($base, self::filter($filter), $attributes, $controls);
		$this->sendldapmessage($message);
		return $result;
	}

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
