<?php

namespace Fneufneu\React\Ldap;

use phpseclib\File\ASN1;

class Ber
{
	const universal = 0x00;
	const application = 0x40;
	const context = 0x80;
	const private_  = 0xc0;

	static function sequence($pdu)
	{
		return "\x30" . self::len($pdu) . $pdu;
	}

	static function set($pdu)
	{
		return "\x31" . self::len($pdu) . $pdu;
	}

	static function application($no, $pdu, $constructed = true)
	{
		return pack('C', self::application | $no | ($constructed ? 0x20 : 0)) . self::len($pdu) . $pdu;
	}

	static function boolean($i)
	{
		return "\x01\x01" . ($i ? "\xff" : "\x00");
	}

	static function integer($i)
	{
		return "\x02" . self::int($i);
	}

	static function octetstring($s)
	{
		return "\x04" . self::len($s) . $s;
	}

	static function contextstring($no, $s)
	{
		return pack('C', self::context | $no) . self::len($s) . $s;
	}

	static function context($no)
	{
		return pack('C', self::context | $no | 0x20);
	}

	static function enumeration($i)
	{
		return "\x0a" . self::int($i);
	}

	static function choice($no)
	{
		return pack('C', self::context | $no);
	}

	static function int($i)
	{
		# for now only supports positive integers
		#return pack('CN', 0x04, $i);
		if ($i <= 255) $res = pack('CC', 0x01, $i);
		elseif ($i <= 32767) $res = pack('Cn', 0x02, $i);
		else $res = pack('CN', 0x04, $i);
		return $res;
	}


	static function len($i)
	{
		return ASN1::_encodeLength(strlen($i));
	}

	static function dump($pdu)
	{
		$i = 0;
		foreach ((array)str_split($pdu) as $x) {
			$c = $i % 16;
			if ($c == 0) printf("\n  %04x:  ", $i);
			if ($c == 8) print " ";
			printf("%02x ", ord($x));
			if ($x > ' ' && $x <= '~') $xtra .= $x;
			else $xtra .= ".";
			if ($c == 15) {
				print "  " . $xtra;
				$xtra = "";
			}
			$i++;
		}
		if ($c != 15) print "  " . str_repeat('   ', 15 - $c) . $xtra;
		print "\n";
	}
}

