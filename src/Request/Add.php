<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Ber;
use Fneufneu\React\Ldap\Request;

class Add extends Request
{
	public function __construct($messageId, $entry, array $attributes)
	{
		foreach ($attributes as $attributeDesc => $attributeValues) {
			$pdu = '';
			if (!is_array($attributeValues)) $attributeValues = array($attributeValues);
			foreach ($attributeValues as $attributeValue) {
				$pdu .= Ber::octetstring($attributeValue);
			}
			$pdux .= Ber::sequence(Ber::octetstring($attributeDesc) . Ber::set($pdu));
		}
		$protocolOp = self::addRequest;
		$pdu = Ber::octetstring($entry) . Ber::sequence($pdux);

		parent::__construct($messageId, $protocolOp, $pdu);
	}
}

