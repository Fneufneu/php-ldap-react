<?php

namespace Fneufneu\React\Ldap;

use phpseclib\Math\BigInteger;

class Ber
{
	const universal	 = 0x00;
	const application   = 0x40;
	const context	   = 0x80;
	const private_	  = 0xc0;

	static function berdecode($buffer, $maxlen)
	{
		$i = 0;
		return self::berdecode_($buffer, $i, $maxlen);
	}

	static function berdecode_($buffer, &$i, $maxlen)
	{
		$res = array();
		while ($i < $maxlen) {
			$byte = ord($buffer[$i++]);
			$struct = array();
			$tag = $struct['tag'] = $byte & 0x1f;
			$class = $struct['class'] = $byte & 0xc0;
			$constructed = $struct['constructed'] = $byte & 0x20;
			$len = $struct['len'] = self::ber_valuelength($buffer, $i);
			if ($constructed) {
				$struct['value'] = self::berdecode_($buffer, $i, $len + $i);
			} else {
				$value = substr($buffer, $i, $len);
				if ($class != 64) {
					if ($tag == 2 || $tag == 10) { # ints and enums
						$value = new BigInteger($value, 256);
						$value = $value->toString();
					} elseif ($tag == 1) {
						$value = ord($value) != 0;
					}
				}
				$struct['value'] = $value;
				$struct['value_'] = bin2hex($struct['value']);
				$i += $len;
			}
			$res[] = $struct;
		}
		return $res;
	}

	static function ber_valuelength($buffer, &$i)
	{
		$byte = ord($buffer[$i++]);
		$len = $byte & 0x7f;
		if ($byte > 0x80) {
			$res = 0;
			for ($c = 0; $c < $len; $c++) {
				$res = $res * 256 + ord($buffer[$i++]);
			}
		} else {
			$res = $len;
		}
		return $res;
	}

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
		$i = strlen($i);
		if ($i <= 127) $res = pack('C', $i);
		elseif ($i <= 255) $res = pack('CC', 0x81, $i);
		elseif ($i <= 65535) $res = pack('Cn', 0x82, $i);
		else $res = pack('CN', 0x84, $i);
		return $res;
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

class Ldap extends Ber
{
	const version3 = 3;

	const baseObject = 0;
	const singleLevel = 1;
	const wholeSubtree = 2;

	const bindRequest = 0;
	const bindResponse = 1;
	const unbindRequest = 2;
	const searchRequest = 3;
	const searchResEntry = 4;
	const searchResDone = 5;
	const searchResRef = 19;
	const modifyRequest = 6;
	const modifyResponse = 7;
	const addRequest = 8;
	const addResponse = 9;
	const delRequest = 10;
	const delResponse = 11;
	const modDNRequest = 12;
	const modDNResponse = 13;
	const compareRequest = 14;
	const compareResponse = 15;
	const abandonRequest = 16;
	const extendedReq = 23;
	const extendedResp = 24;
	
	const and_ = 0;
	const or_ = 1;
	const not_ = 2;
	const equalityMatch = 3;
	const substrings = 4;
	const greaterOrEqual = 5;
	const lessOrEqual = 6;
	const present = 7;
	const approxMatch = 8;
	const extensibleMatch = 9;

	const compareFalse = 5;
	const compareTrue = 6;

	protected $messageID = 0;
	protected $int2protocolOp = array(
		'bindRequest', 'bindResponse', 'unbindRequest', 'searchRequest', 'searchResEntry', 'searchResDone', 'modifyRequest', 'modifyResponse',
		'addRequest', 'addResponse', 'delRequest', 'delResponse', 'modDNRequest', 'modDNResponse', 'compareRequest', 'compareResponse',
		19 => 'searchResRef', 23 => 'extendedReq', 24 => 'extendedResp',
	);

	protected $protocolOp2int;

	protected $fd;
	protected $cookie = '';
	
	function __construct() {
		$this->protocolOp2int = array_flip($this->int2protocolOp);
	}
	
	protected function receiveldapmessage()
	{
		$pdu = fread($this->fd, 2);
		if ($pdu == '') throw new Exception('timeout on socket');
		$lenlen = ord($pdu[1]);
		if ($lenlen > 0x80) { $pdu .= fread($this->fd, $lenlen - 0x80); }
		$i = 1;
		$len = self::ber_valuelength($pdu, $i);
		$prelen = strlen($pdu);
		$pdu .= fread($this->fd, $len);
		#self::dump($pdu);
		$message = self::berdecode($pdu, $prelen + $len);
		$message = $this->pretty($message);
		return $message;
	}

	static function control($controlType, $criticality = false, $controlValue = '')
	{
		return self::octetstring($controlType) . ($criticality ? self::boolean($criticality) : '') . self::octetstring($controlValue);
	}

	protected function attributes($attributes)
	{
		foreach ($attributes as $attribute) {
			$pdu .= self::octetstring($attribute);
		}
		return self::sequence($pdu);
	}

	protected function LDAPMessage($protocolOp, $pdu, $controls = '')
	{
		return self::sequence(self::integer($this->messageID++) . self::application($protocolOp, $pdu) . ($controls ? "\xA0" . self::len($controls) . $controls : ''));
	}

	static function matchedValuesControl($filter = '', $criticality = false)
	{
		return self::sequence(self::control('1.2.826.0.1.3344810.2.3', $criticality, self::sequence($filter)));
	}

	static function pagedResultsControl($size, $cookie = '', $criticality = false)
	{
		return self::sequence(self::control('1.2.840.113556.1.4.319', $criticality, self::sequence(self::integer($size) . self::octetstring($cookie))));
	}

	private function pretty($message) {
		$message = $message[0]['value'];
		$tag = $message[1]['tag'];
		$op = $message[1]['value'];
		if ($tag == 10) { # delRequest has "inline" value - fake a real structure
			$op = array(array('value' => $op));
		}
		
		$structs = array(
			self::bindRequest => array('version', 'name', 'authentication'),
			self::bindResponse => array('resultCode', 'matchedDN', 'diagnosticMessage'),
			self::unbindRequest => array(),
			self::searchRequest => array('baseObject', 'scope', 'derefAliases', 'sizeLimit', 'timeLimit', 'typesOnly', 'filter' => 'Filter', 'attributes' => 'AttributeSelection'),
			self::searchResEntry => array('objectName', 'attributes' => 'PartialAttributeList'),
			self::searchResDone => array('resultCode', 'matchedDN', 'diagnosticMessage'),
			self::modifyRequest => array('object', 'changes' => 'Changes'),
			self::modifyResponse => array('resultCode', 'matchedDN', 'diagnosticMessage'),
			self::addRequest => array('entry', 'attributes' => 'PartialAttributeList'),
			self::addResponse => array('resultCode', 'matchedDN', 'diagnosticMessage'),
			self::delRequest => array('LDAPDN'),
			self::delResponse => array('resultCode', 'matchedDN', 'diagnosticMessage'),
			self::modDNRequest => array('entry', 'newrdn', 'deleteoldrdn', 'newSuperior'),
			self::modDNResponse => array('resultCode', 'matchedDN', 'diagnosticMessage'),
			self::compareRequest => array('entry', 'ava' => 'AttributeValueAssertion'),
			self::compareResponse => array('resultCode', 'matchedDN', 'diagnosticMessage'),
			self::abandonRequest => array('MessageID'),
			self::extendedReq => array('requestName', 'requestValue'),
			self::extendedResp => array('resultCode', 'matchedDN', 'diagnosticMessage', 'responseName', 'responseValue'),
		);
		
		$i = 0;
		foreach ($structs[$tag] as $j => $name) {
			if (is_int($j)) $pp[$name] = $op[$i++]['value'];
			else $pp[$j] = $this->{$name.'_'}($op[$i++]);
		}
		$pp['controls'] = $this->Controls_($message[2]);
		$pp['messageID'] = $message[0]['value'];
		$pp['protocolOp'] = $this->int2protocolOp[$tag];
		return $pp;
	}
	
	private function Filter_($op) {
		$choices = array('and', 'or', 'not', 'equalityMatch', 'substrings', 'greaterOrEqual', 'lessOrEqual', 'present', 'approxMatch', 'extensibleMatch');
		$structs = array('and' => 'Filter', 'or' => 'Filter', 'not' => 'Filter', 'equalityMatch' => 'AttributeValueAssertionx', 'substrings' => 'SubstringFilter', 'greaterOrEqual' =>  'AttributeValueAssertionx',
							'lessOrEqual' => 'AttributeValueAssertionx', 'present' => 'AttributeDescription', 'ApproxMatch' => 'MatchingRuleAssertion');
		$key = $choices[$op['tag']];
		$function = $structs[$key];
		if ($key == 'and' || $key == 'or') {
			foreach($op['value'] as $filter) {
				$res[$key][] = $this->{$function.'_'}($filter);
			}
			return $res;
		}
		return array($key => $this->{$function.'_'}($op['value']));
   }
   
   	private function SubstringFilter_($op) {
   		$res['type'] = $op[0]['value'];
   		foreach($op[1]['value'] as $string) {
   			$tag = $string['tag'];
   			if ($tag == 0) $res['initial'] = $string['value'];
   			elseif ($tag = 1) $res['any'][] = $string['value'];
   			else $res['final'] = $string['value'];
   		}
   		return $res;
   	}
   
   private function AttributeValueAssertion_($op) {
   		return array("attributeDesc" => $op['value'][0]['value'], 'assertionValue' => $op['value'][1]['value']);
   }
   
   private function AttributeValueAssertionx_($op) {
   		return array("attributeDesc" => $op[0]['value'], 'assertionValue' => $op[1]['value']);
   }
   
   private function AttributeSelection_($op) {
		$res = array();
   		foreach($op['value'] as $attribute) {
   			$res[] = $attribute['value'];
   		}
		return $res;
	}
	
	private function PartialAttributeList_($op) {
		foreach($op['value'] as $attribute) {
			$attributeDesc = $attribute['value'][0]['value'];
			foreach ($attribute['value'][1]['value'] as $value) {
				$res[$attributeDesc][] = $value['value'];
			}
		}
		return $res;
	}
	
	private function Changes_($op) {
		$ops = array('add', 'delete', 'replace');
		foreach($op['value'] as $operation) {
			$adddelrep = $ops[$operation['value'][0]['value']];
			foreach($operation['value'][1] as $attrs) {
				$attributeDesc = $attrs[0]['value'];
				foreach((array)$attrs[1]['value'] as $value) {
					$res[$adddelrep][$attributeDesc][] = $value['value'];
				}
			}
		}
		return $res;
	}
	
	private function Controls_($controls) {
		$res = array();

		if (!is_array($controls['value']))
			return $res;

		foreach($controls['value'] as $control) {
			$ctrl['controlType'] = $control['value'][0]['value'];
			$ctrl['controlValue'] = $control['value'][1]['value'];
			$res[] = $ctrl;
		}
		return $res;
	}
}

