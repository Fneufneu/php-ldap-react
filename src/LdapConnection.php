<?php

namespace Fneufneu\React\Ldap;

use Evenement\EventEmitter;
use Fneufneu\React\Ldap\Parser;
use React\Socket\ConnectionInterface;
use React\Stream\Util;

class LdapConnection extends EventEmitter
{
	private $parser;
	private $buffer;
	private $conn;

	public function __construct(ConnectionInterface $conn)
	{
		$this->conn = $conn;
		$this->parser = new Parser();
		$conn->on('data', [$this, 'handleData']);
		Util::forwardEvents($conn, $this, ['error', 'end', 'close']);
	}

	public function handleData($data)
	{
		if ($this->buffer != '') {
			$data = $this->buffer . $data;
			$this->buffer = '';
		}
		$message = $this->parser->decode($data);
		if (!$message) {
			// incomplet data
			$this->buffer .= $data;
			return;
		}
		//echo "LdapConnection handleData: ".json_encode($message).PHP_EOL;

		$op = $message['protocolOp'];
		$p = strpos($op, 'Request');
		if ($p !== false)
			$op = substr($op, 0, $p);

		$events = $this->listeners($op);
		if (empty($events)) {
			$op = array_search("${op}Request", $this->parser->int2protocolOp);
			if ($op == 3)
				++$op;
			$this->write(new Response($message['messageID'], 1 + $op, 1, '', 'not implemented'));
		} else {
			$this->emit($op, [$message]);
		}
		
		if (strlen($data) > 0)
			$this->handleData($data);
	}

	public function write($data)
	{
		return $this->conn->write($this->encode($data));
	}

	public function end($data = '')
	{
		return $this->conn->end($this->encode($data));
	}

	private function encode($data)
	{
		// TODO BER encoder ?
		return $data;
	}
}
