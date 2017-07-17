<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Ber;
use Fneufneu\React\Ldap\Request;

class ModDn extends Request
{
	public function __construct($messageId, $entry, $newrdn, $deleteoldrnd = true, $newsuperior = '')
	{
		$protocolOp = self::modDNRequest;
		$pdu = Ber::octetstring($entry)
			 . Ber::octetstring($newrdn)
			 . Ber::boolean($deleteoldrnd)
			 . ($newsuperior ? "\x80" . Ber::len($newsuperior) . $newsuperior : '');

		parent::__construct($messageId, $protocolOp, $pdu);
	}

}

