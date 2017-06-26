<?php

require __DIR__ . '/../vendor/BigInteger.php';
require __DIR__ . '/../src/Ldap.php';
require __DIR__ . '/../src/Client.php';



$client = new \Fneufneu\React\Ldap\Client('ldap://127.0.0.1', 'blabla', 'mypassword');
$client->result();
// ret "0"
$client->search("ou=toto.com", "(&(uid=*)(mail=m*))", array('uid', 'cn', 'mail'));
$ret = $client->result();
// null or "2" with a bad filter
var_dump($ret);

while ($ret = $client->nextentry())
	var_dump($ret);
$client->unbind();
