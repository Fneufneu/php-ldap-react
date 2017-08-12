<?php


namespace Fneufneu\Tests\React\Ldap;

use phpseclib\File\ASN1;
use PHPUnit\Framework\TestCase;
use Fneufneu\React\Ldap\Ldap;
use Fneufneu\React\Ldap\Response;

class ResponseTest extends TestCase
{
	private $asn1;

	protected function setUp()
	{
		$this->asn1 = new ASN1();
	}

	/**
	 * @dataProvider generateAllResponse
	 */
	public function testValidateGeneratedBer(Response $resp)
	{
		$decoded = $this->asn1->decodeBER((string) $resp);

		$this->assertInternalType('array', $decoded);
		$this->assertEquals(strlen((string) $resp), $decoded[0]['length']);
	}

	public static function generateAllResponse()
	{
		return [
			[new Response(1, Ldap::bindResponse)],
			[new Response(2, Ldap::searchResDone, 0, '', '')],
			[new Response(3, Ldap::addResponse, 1, '', 'not implemented')],
		];
	}
}
