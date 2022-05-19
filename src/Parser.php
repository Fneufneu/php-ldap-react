<?php

namespace Fneufneu\React\Ldap;

use phpseclib\Math\BigInteger;
use phpseclib\File\ASN1;

class Parser
{

	public $int2protocolOp = array(
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

	private $asn1;

	public function __construct()
	{
		$this->asn1 = new ASN1();
	}

	public function decode(&$data)
	{
		$decoded = $this->asn1->decodeBER($data);

		if ($decoded[0] === false)
			return false;

		$data = substr($data, $decoded[0]['length']);

		return $this->pretty($decoded);
	}

	/**
	 * value => content
	 * tag => constant
	 */
	public function pretty($message)
	{
		$message = $message[0]['content'];
		$tag = $message[1]['constant'];
		$op = $message[1]['content'];
		if ($tag == 10) { # delRequest has "inline" value - fake a real structure
			$op = array(array('content' => $op));
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
		if (is_array($structs[$tag]))
		foreach ($structs[$tag] as $j => $name) {
			if (is_int($j))
				$pp[$name] = $op[$i++]['content'];
			else
				$pp[$j] = $this->{$name.'_'}($op[$i++]);
		}
		// TODO adapter Controls_
        if (isset($message[2])) {
            $pp['controls'] = $this->Controls_($message[2]);
        } else {
            $pp['controls'] = [];
        }

		$pp['messageID'] = $message[0]['content'];
		$pp['protocolOp'] = $this->int2protocolOp[$tag];

		foreach ($pp as $k => $v)
			if (is_object($v)
			and is_a($v, 'phpseclib\Math\BigInteger'))
				$pp[$k] = $v->toString();

		return $pp;
	}

	private function Filter_($op) {
		$choices = array('and', 'or', 'not', 'equalityMatch', 'substrings', 'greaterOrEqual', 'lessOrEqual', 'present', 'approxMatch', 'extensibleMatch');
		$structs = array('and' => 'Filter', 'or' => 'Filter', 'not' => 'Filter', 'equalityMatch' => 'AttributeValueAssertionx', 'substrings' => 'SubstringFilter', 'greaterOrEqual' =>  'AttributeValueAssertionx',
							'lessOrEqual' => 'AttributeValueAssertionx', 'present' => 'AttributeDescription', 'ApproxMatch' => 'MatchingRuleAssertion');
		$key = $choices[$op['constant']];
		$function = $structs[$key];
		if ($key == 'and' || $key == 'or') {
			foreach($op['content'] as $filter) {
				$res[$key][] = $this->{$function.'_'}($filter);
			}
			return $res;
		}
		return array($key => $this->{$function.'_'}($op['content']));
	}

	private function SubstringFilter_($op) {
		$res['type'] = $op[0]['content'];
		foreach($op[1]['content'] as $string) {
			$tag = $string['constant'];
			if ($tag == 0) $res['initial'] = $string['content'];
			elseif ($tag = 1) $res['any'][] = $string['content'];
			else $res['final'] = $string['content'];
		}
		return $res;
	}

	private function AttributeValueAssertion_($op) {
			return array("attributeDesc" => $op['content'][0]['content'], 'assertionValue' => $op['content'][1]['content']);
	}

	private function AttributeValueAssertionx_($op) {
			return array("attributeDesc" => $op[0]['content'], 'assertionValue' => $op[1]['content']);
	}

	private function AttributeSelection_($op) {
		$res = array();
		foreach($op['content'] as $attribute) {
			$res[] = $attribute['content'];
		}
		return $res;
	}

	private function AttributeDescription_($op) {
		// TODO if not a string ?
		return $op;
	}
	
	private function PartialAttributeList_($op) {
		foreach($op['content'] as $attribute) {
			$attributeDesc = $attribute['content'][0]['content'];
			if (!is_array($attribute['content'][1]['content'])) {
				var_dump($attribute);
				continue;
			}
			foreach ($attribute['content'][1]['content'] as $value) {
				$res[$attributeDesc][] = $value['content'];
			}
		}
		return $res;
	}
	
	private function Changes_($op) {
		$ops = array('add', 'delete', 'replace');
		foreach($op['content'] as $operation) {
			$adddelrep = $ops[$operation['content'][0]['content']];
			foreach($operation['content'][1] as $attrs) {
				$attributeDesc = $attrs[0]['content'];
				foreach((array)$attrs[1]['content'] as $content) {
					$res[$adddelrep][$attributeDesc][] = $content['content'];
				}
			}
		}
		return $res;
	}
	
	private function Controls_($controls) {
		$res = array();

		if (!is_array($controls['content']))
			return $res;

		foreach($controls['content'] as $control) {
			$controlType = $control['content'][0]['content'];
			$criticality = $control['content'][1]['content'];
			$controlValue = $control['content'][2]['content'];
			if ('1.2.840.113556.1.4.319' == $controlType) {
				$controlValue = $this->asn1->decodeBER($controlValue);
				$controlValue = $controlValue[0]['content'][1]['content'];
			}
			$res[$controlType] = $controlValue;
		}

		return $res;
	}
}

