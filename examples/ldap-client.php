<?php

require __DIR__ . '/../vendor/autoload.php';

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
$client->bind('blabla', 'blabla75')->then(function ($client) {
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
		echo json_encode($data) . PHP_EOL;
	};
	$print_end = function () {
		printf('end'.PHP_EOL);
	};
	$print_close = function () {
		printf('close'.PHP_EOL);
	};
	$print_error = function ($e) {
		echo 'error: '.$e->getMessage().PHP_EOL;
	};
	$results->on('data', $print_data)
		->on('end', $print_end)
		->on('close', $print_close)
		->on('error', $print_error);
	$results2->on('data', $print_data)
		->on('end', $print_end)
		->on('close', $print_close)
		->on('error', $print_error);
	$results3->on('data', $print_data)
		->on('end', $print_end)
		->on('close', $print_close)
		->on('error', $print_error);
	$client->unbind();
}, function ($e) use ($loop) {
	echo "bind failed: ".$e->getMessage().PHP_EOL;
	$loop->stop();
});

$loop->run();
