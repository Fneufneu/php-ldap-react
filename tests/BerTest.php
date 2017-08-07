<?php

namespace Fneufneu\Tests\React\Ldap;

use Fneufneu\React\Ldap\Ber;
use PHPUnit\Framework\TestCase;

class BerTest extends TestCase
{
	public function testInt()
	{
		$this->assertInternalType('string', Ber::int(42));
	}
}
