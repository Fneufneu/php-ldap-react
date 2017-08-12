<?php


namespace Fneufneu\Tests\React\Ldap;

use PHPUnit\Framework\TestCase;
use Fneufneu\React\Ldap\Client;
use Fneufneu\React\Ldap\Parser;
use React\EventLoop\LoopInterface;

class ClientTest extends TestCase
{
	private $bindRequest;

	protected function setUp()
	{
		$this->bindRequest = base64_decode('MCACAQFgGwIBAwQMam9obkBkb2UudGxkgAhwYXNzd29yZA==');
	}

	public function testHandleDataOneMessage()
	{
		$loop = $this->getMockBuilder(LoopInterface::class)->getMock();

		$client = $this->getMockBuilder(Client::class)
			->setConstructorArgs([$loop, ''])
			->setMethods(['handleMessage'])
			->getMock();

		$client->expects($this->once())
			->method('handleMessage')
			->with($this->arrayHasKey('protocolOp'));

		$client->handleData($this->bindRequest);
	}

	public function testHandleDataPartialMessages()
	{
		$loop = $this->getMockBuilder(LoopInterface::class)->getMock();

		$client = $this->getMockBuilder(Client::class)
			->setConstructorArgs([$loop, ''])
			->setMethods(['handleMessage'])
			->getMock();

		$client->expects($this->exactly(2))
			->method('handleMessage')
			->with($this->arrayHasKey('protocolOp'));

		$client->handleData($this->bindRequest
			. $this->bindRequest
			. substr($this->bindRequest, 0, 5));
	}

}
