<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Request;

class Compare extends Request
{
	public function __construct($messageId, $entry, $attributeDesc, $assertionValue)
	{
		$protocolOp = self::compareRequest;
		$payload = self::sequence(self::octetstring($attributeDesc) . self::octetstring($assertionValue));
		$pdu = self::octetstring($entry) .  $payload);

		parent::__construct($messageId, $protocolOp, $pdu);
	}

}

