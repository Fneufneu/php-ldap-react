<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Ber;
use Fneufneu\React\Ldap\Request;

class Compare extends Request
{
	public function __construct($messageId, $entry, $attributeDesc, $assertionValue)
	{
		$protocolOp = self::compareRequest;
		$payload = Ber::sequence(Ber::octetstring($attributeDesc) . Ber::octetstring($assertionValue));
		$pdu = Ber::octetstring($entry) .  $payload;

		parent::__construct($messageId, $protocolOp, $pdu);
	}

}

