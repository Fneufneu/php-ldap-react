<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Request;

class Add extends Request
{
	public function __construct($messageId, $entry, array $attributes)
	{
		foreach ($attributes as $attributeDesc => $attributeValues) {
			$pdu = '';
			if (!is_array($attributeValues)) $attributeValues = array($attributeValues);
			foreach ($attributeValues as $attributeValue) {
				$pdu .= self::octetstring($attributeValue);
			}
			$pdux .= self::sequence(self::octetstring($attributeDesc) . self::set($pdu));
		}
		$protocolOp = self::addRequest;
		$pdu = self::octetstring($entry) . self::sequence($pdux);

		parent::__construct($messageId, $protocolOp, $pdu);
	}
}

