<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Request;

class Delete extends Request
{
	public function __construct($messageId, $dn)
	{
		$this->expectedAnswer = 'delResponse';
		$this->message = self::sequence(self::integer($this->messageID++)
			. self::application(self::delRequest, $dn, false));
	}

}

