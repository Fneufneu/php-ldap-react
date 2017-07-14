<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Request;

class StartTls extends Request
{
	public function __construct($messageId)
	{
		$protocolOp = self::extendedReq;
		$startTLS = '1.3.6.1.4.1.1466.20037';
		$pdu = "\x80" . self::len($startTLS) . $startTLS;

		parent::__construct($messageId, $protocolOp, $pdu);
	}

}

