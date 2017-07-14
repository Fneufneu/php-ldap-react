<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Request;

class ModDn extends Request
{
	public function __construct($messageId, $entry, $newrdn, $deleteoldrnd = true, $newsuperior = '')
	{
		$protocolOp = self::modDNRequest;
		$pdu = self::octetstring($entry)
			 . self::octetstring($newrdn)
			 . self::boolean($deleteoldrnd)
			 . ($newsuperior ? "\x80" . self::len($newsuperior) . $newsuperior : '');

		parent::__construct($messageId, $protocolOp, $pdu);
	}

}

