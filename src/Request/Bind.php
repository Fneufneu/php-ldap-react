<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Ber;
use Fneufneu\React\Ldap\Request;

class Bind extends Request
{
	public function __construct($messageId, $bind_dn = null, $bind_password = null)
	{
		$protocolOp = self::bindRequest;
		$pdu = Ber::integer(self::version3)
			 . Ber::octetstring($bind_dn)
			 . "\x80" . Ber::len($bind_password) . $bind_password;

		parent::__construct($messageId, $protocolOp, $pdu);
	}
}

