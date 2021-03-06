<?php

namespace Fneufneu\React\Ldap;

use Fneufneu\React\Ldap\Ber;

class Request extends Ldap
{
	public $expectedAnswer;
	public $message;
	public $messageId;
	private $answers = array(
		self::bindRequest => 'bindResponse',
		self::searchRequest => 'searchResDone',
		self::modifyRequest => 'modifyResponse',
		self::addRequest => 'addRequest',
		self::delRequest => 'delResponse',
		self::modDNRequest => 'modDNResponse',
		self::compareRequest => 'compareResponse',
		self::extendedReq => 'extendedResp',
	);

	public function __construct($messageId, $protocolOp, $pdu, $controls = '')
	{

		if (!array_key_exists($protocolOp, $this->answers))
			throw new \InvalidArgumentException('invalid protocolOp');

		$this->messageId = $messageId;
		$this->expectedAnswer = $this->answers[$protocolOp];
		$this->message = $this->ldapMessage($messageId, $protocolOp, $pdu, $controls);	
	}

	public function toString()
	{
		return $this->message;
	}
}

