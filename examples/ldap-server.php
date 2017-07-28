<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/Ber.php';
require __DIR__ . '/../src/Parser.php';
require __DIR__ . '/../src/Ldap.php';
require __DIR__ . '/../src/Server.php';
require __DIR__ . '/../src/Response.php';
require __DIR__ . '/../src/LdapConnection.php';

use Fneufneu\React\Ldap\Ldap;
use Fneufneu\React\Ldap\Ber;
use Fneufneu\React\Ldap\Response;


$loop = React\EventLoop\Factory::create();

$server = new Fneufneu\React\Ldap\Server(function ($client) {
	echo "new client" . PHP_EOL;
	$client->on('bind', function ($infos) use ($client) {
		echo "new bindRequest: " . json_encode($infos) . PHP_EOL;
		$resp = new Response($infos['messageID'], Ldap::bindResponse);
		$client->write($resp);
	});
	$client->on('unbind', function ($infos) use ($client) {
		$client->end();
	});
	$client->on('search', function ($infos) use ($client) {
		echo "new search: " . json_encode($infos) . PHP_EOL;
		$client->write(new Response($infos['messageID'], Ldap::searchResDone, 0, '', ''));
	});
	$client->on('add', function ($infos) use ($client) {
		$client->write(new Response($infos['messageID'], Ldap::addResponse, 1, '', 'not implemented'));
	});
});

$socket = new React\Socket\Server('0.0.0.0:33389', $loop);
$server->listen($socket);

$loop->run();
