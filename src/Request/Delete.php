<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Ber;
use Fneufneu\React\Ldap\Request;

class Delete extends Request
{
	public function __construct($messageId, $dn)
	{
		$this->expectedAnswer = 'delResponse';
		$this->message = Ber::sequence(Ber::integer($this->messageID++)
			. Ber::application(self::delRequest, $dn, false));
	}

}

