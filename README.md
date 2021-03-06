# php-ldap-react
Asynchronous LDAP client built on top of ReactPHP

## Quickstart example

```php
$loop = React\EventLoop\Factory::create();
$client = new Fneufneu\React\Ldap\Client($loop, 'ldap://myhost.com');
$client->bind('user', 'password')->then(function ($client) {
    $res = $client->search([
        'base' => 'cn=foo, o=example',
        'filter' => 'mail=*',
    ]);
    $res->on('data', function ($data) {
        echo json_encode($data) . PHP_EOL;
    });
    $client->unbind();
});
$loop->run();
```
## Client usage

The `Client` class is the main class in this package that let you connect to
a LDAP Server.

```php
$client = new Client($loop, 'ldap://host', $options);
```

The constructor needs
- an [`EventLoop`](https://github.com/reactphp/event-loop)
- an URI to the LDAP host (`ldap://myhost.com:389`, `ldaptls://yourhost.fr`, `ldaps://mycomp.com`)
- an optional array of options

### Supported options

| option | description |
| ------ | ----------- |
| connector | a custom React\Socket\ConnectorInterface |
| timeout | timeout in sec for default Connector, connect() and bind() request |

### Events

The client emit usual event: end, close and error:

```php
$client->on('end', function () {
    echo "client's connection ended" . PHP_EOL;
});

$client->on('close', function () {
    echo "client's connection closed" . PHP_EOL;
});

$client->on('error', function (Exception $e) {
    echo 'error: '.$e->getMessage() . PHP_EOL;
});
```

### bind()

bind call connect() and return a promise.

```php
$client->bind('toto', 'password')->done(function ($client) {
    echo 'successfuly binded' . PHP_EOL;
}, function (Exception $e) {
    echo 'bind failed with error: ' . $e->getMessage() . PHP_EOL;
});
```

### unbind()

Send an unbind() request to the server.

The server will usually disconnect the client just after.

### search()

Performs a ldap_search and return a Result object see [Result usage](#result-usage)

The `search(array): Result` method takes an array of options.

| option | type | default value | description |
| ------ | ---- | ------- | ------ |
| base | string | no default | *mandatory* The base DN |
| filter | string | (objectclass=*) | The search filter |
| attributes | array | [] | An array of the required attributes |
| scope | enum | Ldap::wholeSubtree | Ldap::wholeSubtree, Ldap::singleLevel, Ldap::baseObject |
| pagesize | int | 0 | enable automatic paging |
| sizelimit | int | 0 | Enables you to limit the count of entries fetched. Setting this to 0 means no limit |
| timelimit | int | 0 | Sets the number of seconds how long is spend on the search. Setting this to 0 means no limit |
| ~~typesonly~~ | bool | false | ~~set to true if only attribute types are wanted~~ (not supported) |
| derefaliases | enum | Ldap::never | Specifies how aliases should be handled during the search (`Ldap::never`, `ldap::searching`, `Ldap::finding`, `Ldap:always`) |
| resultfilter | ? | ? | ? |

#### Paging

In order to retrieve results beyond the usual 1000 limits, you can set pagesize to an int > 0 to page results.

When enabled, the Client use an internal mechanisms to automate the process and perform as many search() as necessary.

### add()

:heavy_exclamation_mark: **not tested**

```php
add(string $dn, array entry): Result
```

### modify()

:heavy_exclamation_mark: **not tested**

```php
modify(string $dn, array changes): Result
```

example:

```php
$result = $client->modify('cn=test', [
    ['add' => ['mail' => ['john@doe.com']],
    ['delete' => ['email' => ['john@doe.com']],
    ['replace' => ['sn' => ['John']],
    ],
]);
```

### delete()

```php
delete(string $dn): Result
```

### modDN()

:heavy_exclamation_mark: **not tested**

```php
modDN(string $dn, string $newDn, bool $deleteOldDn, string $newSuperior): Result
```

### compare()

:heavy_exclamation_mark: **not tested**

```php
compare(string $dn, string $attribute, string $value): Result
```

## Result usage

`Result` emit usual event: data, end and error:

```php
$result->on('data', function ($data) {
    // one search entry
});

$result->on('end', function ($data) {
    // all search entries or an empty array if none
});

$result->on('error', function (Exception $e) {
    echo 'error: '.$e->getMessage() . PHP_EOL;
});
```

## Server usage

See [examples](examples).
