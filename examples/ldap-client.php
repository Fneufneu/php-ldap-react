<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/Parser.php';
require __DIR__ . '/../src/Ldap.php';
require __DIR__ . '/../src/Result.php';
require __DIR__ . '/../src/Client.php';


$loop = React\EventLoop\Factory::create();

$loop->addTimer(7, function () use ($loop) {
	$loop->stop();
});

$client = new Fneufneu\React\Ldap\Client($loop, 'ldap://ldap.blabla.com');
$client->on('data', function ($data) {
	echo "data received: ".var_export($data, true).PHP_EOL;
});
$client->on('error', function ($e) use ($loop) {
	echo "cmd failed: ".$e->getMessage().PHP_EOL;
	$loop->stop();
});
$client->on('end', function () use ($loop) {
	echo "client end".PHP_EOL;
	$loop->stop();
});
$client->startTLS()->then(function () use ($client, $loop) {
	$client->bind('blabla', 'blabla')->then(function () use ($client, $loop) {
		$results = $client->search("cn=blabla", "(&(uid=*)(mail=m*))", array('uid', 'cn', 'mail'));
		$results->on('data', function ($data) {
			echo "result: ";
			var_dump($data);
		});
		$results->on('end', function ($data) use ($client) {
			printf('nb result: %d'.PHP_EOL, count($data));
			$client->unbind();
		});
	}, function ($e) use ($loop) {
		echo "bind failed: ".$e->getMessage().PHP_EOL;
		$loop->stop();
	});
});

$loop->run();
