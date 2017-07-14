<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Request;

class Unbind extends Request
{

	public function __construct($messageId)
	{
		$this->message = self::sequence(
			self::integer($messageId)
			. self::application(self::unbindRequest, '', false));
	}
}

