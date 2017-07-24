<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/Ber.php';
require __DIR__ . '/../src/Parser.php';
require __DIR__ . '/../src/Ldap.php';
require __DIR__ . '/../src/Result.php';
require __DIR__ . '/../src/Request.php';
require __DIR__ . '/../src/Request/Search.php';
require __DIR__ . '/../src/Request/Bind.php';
require __DIR__ . '/../src/Request/Unbind.php';
require __DIR__ . '/../src/Request/StartTls.php';
require __DIR__ . '/../src/Client.php';

$loop = React\EventLoop\Factory::create();

$loop->addTimer(7, function () use ($loop) {
	$loop->stop();
});

$client = new Fneufneu\React\Ldap\Client($loop, 'ldap://blabla.com');
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
$client->bind('blabla', 'blabla75')->then(function () use ($client, $loop) {
	echo "binded\n";
	$results = $client->search([
		'base' => "cn=blabla",
		'filter' => "(&(uid=*)(mail=y*))",
		'attributes' => ['uid', 'cn', 'mail'],
	]);
	$results2 = $client->search([
		'base' => "cn=blabla",
		'filter' => "(&(uid=*)(mail=m*))",
		'attributes' => ['uid', 'cn', 'mail'],
	]);
	$results3 = $client->search([
		'base' => "cn=blabla",
		'filter' => "(&(uid=*)(mail=a*))",
		'attributes' => ['uid', 'cn', 'mail'],
	]);

	$print_data = function ($data) {
		static $h = false;
		if (!$h) {
			$h = true;
			echo "|";
			foreach ($data as $k => $v)
				printf(" %'. 22s |", $k);
			echo PHP_EOL;
		}
		echo "|";
		foreach ($data as $k => $v)
			printf(" %'. 22s |", $v);
		echo PHP_EOL;
	};
	$print_end = function ($data) {
		printf('nb result: %d'.PHP_EOL, count($data));
	};
	$results->on('data', $print_data);
	$results->on('end', $print_end);
	$results2->on('data', $print_data);
	$results2->on('end', $print_end);
	$results3->on('data', $print_data);
	$results3->on('end', $print_end);
	$client->unbind();
}, function ($e) use ($loop) {
	echo "bind failed: ".$e->getMessage().PHP_EOL;
	$loop->stop();
});

$loop->run();
