<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Ber;
use Fneufneu\React\Ldap\Request;

class Unbind extends Request
{

	public function __construct($messageId)
	{
		$this->message = Ber::sequence(
			Ber::integer($messageId)
			. Ber::application(self::unbindRequest, '', false));
	}
}

