<?php

namespace Fneufneu\React\Ldap;

use Fneufneu\React\Ldap\Ber;
use phpseclib\Math\BigInteger;
use Evenement\EventEmitter;
use phpseclib\File\ASN1;

class Ldap
{
	const version3 = 3;

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

	/*
	 * Search scope enum
	 */
	const baseObject = 0;
	const singleLevel = 1;
	const wholeSubtree = 2;

	/*
	 * Search deferAliases enum
	 */
	const never = 0;
	const searching = 1;
	const finding = 2;
	const always = 3;

	protected $messageID = 1;
	protected $int2protocolOp = array(
		'bindRequest',
		'bindResponse',
		'unbindRequest',
		'searchRequest',
		'searchResEntry',
		'searchResDone',
		'modifyRequest',
		'modifyResponse',
		'addRequest',
		'addResponse',
		'delRequest',
		'delResponse',
		'modDNRequest',
		'modDNResponse',
		'compareRequest',
		'compareResponse',
		19 => 'searchResRef',
		23 => 'extendedReq',
		24 => 'extendedResp',
	);

	protected $protocolOp2int;

	protected $fd;
	protected $cookie = '';
	
	function __construct() {
		$this->protocolOp2int = array_flip($this->int2protocolOp);
	}
	
	static function filter($filter)
	{
		# extensibleMatch not supported ...
		if (!preg_match("/^\(.*\)$/", $filter)) $filter = '(' . $filter . ')';
		$elements = preg_split("/(\(|\)|~=|>=|<=|=\*\)|\*|=|&|\||!|\\\\[a-z0-9]{2})/i", $filter, -1, PREG_SPLIT_DELIM_CAPTURE + PREG_SPLIT_NO_EMPTY);
		$i = 0;
		$res = self::dofilter($elements, $i);
		if ($i - sizeof($elements) != 1)
			throw new \InvalidArgumentException("Unmatched ) or (  in filter: $filter");
		return self::filter2ber($res);
	}

	static function dofilter(&$elements, &$i)
	{
		$res = array();
		while ($element = $elements[$i++]) {
			$unescapedelement = $element;
			if (preg_match("/^\\\\([0-9a-z]{2})$/i", $element, $d)) {
				$unescapedelement = chr(hexdec($d[1]));
			}
			if ($element == '(') $res['filters'][] = self::dofilter($elements, $i);
			elseif ($element == ')') break;
			elseif (in_array($element, array('&', '|', '!'))) $res['op'] = $element;
			elseif (in_array($element, array('=', '~=', '>=', '<=', '=*)'))) {
				$res['filtertype'] = $element;
				if ($element == '=*)') break;
			} elseif ($element == '*') {
				$res['filtertype'] = $element;
				unset($res['final']);
				unset($res['assertionValue']);
			} elseif ($res['filtertype'] == '*') $res['final'] .= $res['any'][] .= $unescapedelement;
			elseif ($res['filtertype']) $res['initial'] = $res['assertionValue'] .= $unescapedelement;
			else $res['attributeDesc'] .= $unescapedelement;
		}
		if ($res['final']) array_pop($res['any']);
		return $res;
	}

	static function filter2ber($filter)
	{
		#print_r($filter);
		$ops = array('&' => "\xa0", '|' => "\xa1", '!' => "\xa2", '*' => "\xa4", '=' => "\xa3", '~=' => "\xa8", '>=' => '\xa5', '<=' => "\xa6",);
		foreach ($filter['filters'] as $f) {
			if ($f['op']) $res .= self::filter2ber($f);
			else {
				if ('=*)' == $f['filtertype']) {
					$res .= Ber::choice(7) . Ber::len($f['attributeDesc']) . $f['attributeDesc'];
				} elseif ('*' == $f['filtertype']) {
					$payload = $f['initial'] ? "\x80" . Ber::len($f['initial']) . $f['initial'] : '';
					foreach ((array)$f['any'] as $any) $payload .= "\x81" . Ber::len($any) . $any;
					$payload .= $f['final'] ? "\x82" . Ber::len($f['final']) . $f['final'] : '';
					$payload = Ber::octetstring($f['attributeDesc']) . Ber::sequence($payload);
					$res .= "\xa4" . Ber::len($payload) . $payload;
				} else {
					$payload = Ber::octetstring($f['attributeDesc']) . Ber::octetstring($f['assertionValue']);
					$res .= $ops[$f['filtertype']] . Ber::len($payload) . $payload;
				}
			}
		}
		if ($op = $filter['op']) return $ops[$op] . Ber::len($res) . $res;
		return $res;
	}
	static function control($controlType, $criticality = false, $controlValue = '')
	{
		return Ber::octetstring($controlType) . ($criticality ? Ber::boolean($criticality) : '') . Ber::octetstring($controlValue);
	}

	protected function attributes(array $attributes)
	{
		foreach ($attributes as $attribute) {
			$pdu .= Ber::octetstring($attribute);
		}
		return Ber::sequence($pdu);
	}

	protected function ldapMessage($messageId, $protocolOp, $pdu, $controls = '')
	{
		return Ber::sequence(Ber::integer($messageId)
			. Ber::application($protocolOp, $pdu)
			. ($controls ? "\xA0" . Ber::len($controls) . $controls : ''));
	}

	static function matchedValuesControl($filter = '', $criticality = false)
	{
		return Ber::sequence(self::control('1.2.826.0.1.3344810.2.3', $criticality, Ber::sequence($filter)));
	}

	static function pagedResultsControl($size, $cookie = '', $criticality = false)
	{
		return Ber::sequence(self::control('1.2.840.113556.1.4.319', $criticality, Ber::sequence(Ber::integer($size) . Ber::octetstring($cookie))));
	}

	public function pretty($message) {
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

