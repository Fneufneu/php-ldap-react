<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Request;

class Modify extends Request
{
	public function __construct($messageId, $dn, $changes)
	{
		$protocolOp = self::modifyRequest;
		# $changes is array of mods
		$ops = array('add' => 0, 'delete' => 1, 'replace' => 2);
		$pdu = '';
		foreach ($changes as $operation) {
			foreach ($operation as $type => $modification) {
				$pdu = "";
				foreach ($modification as $attributeDesc => $attributeValues) {
					foreach ($attributeValues as $attributeValue) {
						$pdu .= self::octetstring($attributeValue);
					}
					$pdu = self::sequence(self::octetstring($attributeDesc) . self::set($pdu));
				}
				$pdux .= self::sequence(self::enumeration($ops[$type]) . $pdu);
			}
		}
		$pdu = self::octetstring($dn) . self::sequence($pdux);

		parent::__construct($messageId, $protocolOp, $pdu);
	}

}

