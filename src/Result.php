<?php

namespace Fneufneu\React\Ldap;

use Evenement\EventEmitter;
use React\Stream\ReadableStreamInterface;
use React\Stream\Util;
use React\Stream\WritableStreamInterface;

class Result extends EventEmitter implements ReadableStreamInterface
{
	private $readable = true;

	public function __construct()
	{
	}

	public function error(\Exception $e) {
		if (!$this->readable)
			return;

		$this->emit('error', [$e]);
		$this->close();
	}

	public function data($data) {
		if (!$this->readable)
			return;

		$this->emit('data', [$data]);
	}

	public function end() {
		if (!$this->readable)
			return;

		$this->emit('end');
		$this->close();
	}

	public function close() {
		if (!$this->readable)
			return;

		$this->readable = false;

		$this->emit('close');
		$this->removeAllListeners();
	}

	public function isReadable() {
		return $this->readable;
	}

	public function pause() {
		// NYI
	}

	public function resume() {
		// NYI
	}

	public function pipe(WritableStreamInterface $dest, array $options = array()) {
		Util::pipe($this, $dest, $options);

		return $dest;
	}
}

