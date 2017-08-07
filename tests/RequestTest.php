<?php


namespace Fneufneu\Tests\React\Ldap;

use phpseclib\File\ASN1;
use PHPUnit\Framework\TestCase;
use Fneufneu\React\Ldap\Request;

class RequestTest extends TestCase
{
	private $asn1;

	protected function setUp()
	{
		$this->asn1 = new ASN1();
	}

	/**
	 * @dataProvider generateAllRequest
	 */
	public function testValidateGeneratedBer(Request $request)
	{
		$decoded = $this->asn1->decodeBER($request->toString());

		$this->assertInternalType('array', $decoded);
		$this->assertEquals(strlen($request->toString()), $decoded[0]['length']);
	}

	public static function generateAllRequest()
	{
		return [
			[new Request\Add(1, 'cn=test', ['cn' => 'test'])],
			[new Request\Bind(2, 'john@doe.tld', 'password')],
			[new Request\Compare(3, 'cn=test', 'cn', 'test')],
			[new Request\Delete(4, 'cn=test')],
			[new Request\ModDn(5, 'cn=test', 'cn=test, ou=people')],
			[new Request\Modify(6, 'cn=test', [])],
			[new Request\Search(7, ['basedn' => ''])],
			[new Request\StartTls(8)],
			[new Request\Unbind(9)]
		];
	}
}
