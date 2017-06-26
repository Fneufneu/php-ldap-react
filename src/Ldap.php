<?php
error_reporting(E_STRICT);
error_reporting(E_ALL);

require('BigInteger.php');

/*
 todo:
 
 serverside StartTLS.
 √ asynch operation


*/ 


class ber
{
    const universal     = 0x00;
    const application   = 0x40;
    const context       = 0x80;
    const private_      = 0xc0;

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
						$value = new Math_BigInteger($value, 256);
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

class ldap extends ber
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
		foreach($controls['value'] as $control) {
			$ctrl['controlType'] = $control['value'][0]['value'];
			$ctrl['controlValue'] = $control['value'][1]['value'];
			$res[] = $ctrl;
		}
		return $res;
    }
}

class ldapserver extends ldap
{    
    function __construct($transport) {
        parent::__construct();
        $this->fd = stream_socket_server($transport, $errno, $errstr);
        if (!$this->fd) {
            die("$errstr ($errno)\n");
        } 
    }

    public function serverequests() 
    {
    	print_r("serverequests ...\n");
		while ($client = stream_socket_accept($this->fd)) {
    #		$pid = pcntl_fork();
    #		if ($pid == -1) {
    #			 die('could not fork');
    #		} else if ($pid) {
    #			 // we are the parent
    #			 fclose($client);
    #			 #pcntl_wait($status); //Protect against Zombie children
    #		} else {
                fclose($this->fd);
                $this->fd = $client;
                while(1) {
                    $message = $this->receiveldapmessage();
                    $protocolOp = $message['protocolOp'];
                    $this->$protocolOp($message);
                    if ($protocolOp == 'unbindRequest') return;
                }
     #      }
        }
    }
    
    public function __call($operation, $args) {
    	$message = $args[0];
    	$msgid = $message['messageID'];
        $pdu = self::sequence(self::integer($msgid) . self::application($this->protocolOp2int[$operation]+1 , self::ldapResult())); # . ($controls ? "\xA0" . self::len($controls) . $controls : ''));
		#self::dump($pdu);
        fwrite($this->fd, $pdu);
    }
    
	static function ldapResult($resultCode = 0, $matchedDN = '',	$diagnosticMessage = '') {
		return self::enumeration($resultCode) . self::octetstring($matchedDN) . self::octetstring($diagnosticMessage);
	}
	
	static function array2PartialAttributeList($entry) {
	    $pdux = '';
		foreach ($entry as $attributeDesc => $attributeValues) {
			$pdu = '';
			foreach($attributeValues as $attributeValue) {
				$pdu .= self::octetstring($attributeValue);
			}
			$pdux .= self::sequence(self::octetstring($attributeDesc) . self::set($pdu));
		}
		return self::sequence($pdux);
	}
    
    protected function searchRequest($message)
    {
    	$msgid = $message[0]['value'][0]['value'];
        $entry = array('cn' => array('Mads Freek Petersen'), 'x' => array('værdi1', 'værdi2'));
        $PartialAttributeList = self::array2PartialAttributeList($entry);
        $pdu = self::sequence(self::integer($msgid) . self::application($this->protocolOp2int['searchResEntry'] , self::octetstring('ou=dn') . $PartialAttributeList));
        fwrite($this->fd, $pdu);
        $pdu = self::sequence(self::integer($msgid) . self::application($this->protocolOp2int['searchResDone'] , self::ldapResult()));
        fwrite($this->fd, $pdu);
    }
    
    protected function extendedReq($Req)
    { #STREAM_CRYPTO_METHOD_TLS_SERVER
    
    }
    
/*
    protected function bindRequest($Request) {};
    protected function bindResponse($Response) {};
    protected function unbindRequest($Request) {};
    protected function searchRequest($Request) {};
    protected function searchResEntry($ResEntry) {};
    protected function searchResDone($ResDone) {};
    protected function searchResRef($ResRef) {};
    protected function modifyRequest($Request) {};
    protected function modifyResponse($Response) {};
    protected function addRequest($Request) {};
    protected function addResponse($Response) {};
    protected function delRequest($Request) {};
    protected function delResponse($Response) {};
    protected function modDNRequest($Request) {};
    protected function modDNResponse($Response) {};
    protected function compareRequest($Request) {};
    protected function compareResponse($Response) {};
    protected function abandonRequest($Request) {};
    protected function extendedReq($Req) {};
    protected function extendedResp($Resp) {};
*/  

}

class ldapclient extends ldap
{
    public $status;
    public $options = array(
        'sizelimit' => 0,
        'timelimit' => 0,
        'scope' => self::wholeSubtree,
        'typesonly' => false,
        'pagesize' => 0,
        'resultfilter' => '',
    );

    function __construct($server, $dn = null, $pw = null)
    {
        parent::__construct();
        $this->connect($server);
        $this->bind($dn, $pw);
    }

    static function filter($filter)
    {
        # extensibleMatch not supported ...
        if (!preg_match("/^\(.*\)$/", $filter)) $filter = '(' . $filter . ')';
        $elements = preg_split("/(\(|\)|~=|>=|<=|=\*\)|\*|=|&|\||!|\\\\[a-z0-9]{2})/i", $filter, -1, PREG_SPLIT_DELIM_CAPTURE + PREG_SPLIT_NO_EMPTY);
        $i = 0;
        $res = self::dofilter($elements, $i);
        if ($i - sizeof($elements) != 1) $this->handleresult(0, 1234567890 , "Unmatched ) or (  in filter: $filter");
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
                    $res .= self::choice(7) . self::len($f['attributeDesc']) . $f['attributeDesc'];
                } elseif ('*' == $f['filtertype']) {
                    $payload = $f['initial'] ? "\x80" . self::len($f['initial']) . $f['initial'] : '';
                    foreach ((array)$f['any'] as $any) $payload .= "\x81" . self::len($any) . $any;
                    $payload .= $f['final'] ? "\x82" . self::len($f['final']) . $f['final'] : '';
                    $payload = self::octetstring($f['attributeDesc']) . self::sequence($payload);
                    $res .= "\xa4" . self::len($payload) . $payload;
                } else {
                    $payload = self::octetstring($f['attributeDesc']) . self::octetstring($f['assertionValue']);
                    $res .= $ops[$f['filtertype']] . self::len($payload) . $payload;
                }
            }
        }
        if ($op = $filter['op']) return $ops[$op] . self::len($res) . $res;
        return $res;
    }

    private function handleresult($successCode = 0, $resultCode = null, $diagnosticMessage = null) {
        if ($resultCode == null) {
            $status = $this->status();
            $resultCode = $status['resultCode'];
            $diagnosticMessage = $status['diagnosticMessage'];
        } 
        if ($resultCode != $successCode && false) throw new Exception($diagnosticMessage, $resultCode);
        return $resultCode;
    }
    
    private function sendldapmessage($pdu, $successCode = 0)
    {
        if (isset($this->successCode)) throw new Exception('You need to call result() before sending a new request ...');
        fwrite($this->fd, $pdu);
        $this->successCode = $successCode;
    }
    
    public function result() {
        $this->status = $this->receiveldapmessage();
        $successCode = $this->successCode;
        unset($this->successCode);
        return $this->handleresult($successCode);
    }
    
    static function searchResEntry($response)
    {
        $res = $response['attributes'];
        $res['dn'] = $response['objectName'];
        return $res;
    }

    public function status()
    {
        return $this->status;
    }

    public function connect($url)
    {
        $defaultport = array(null => '389', 'ldap' => '389', 'ldaps' => '636', 'ldaptls' => '389');
        if (preg_match('/^(?:(ldap(?:|s|tls))(?::\/\/))?(.+?):?(\d+)?$/', $url, $d)) {
            list($dummy, $protocol, $address, $port) = $d;
            if (!$port) $port = $defaultport[$protocol];
            $transport = $protocol == 'ldaps' ? 'tls://' : 'tcp://';
            #print_r("$transport$address:$port");
            $this->fd = @stream_socket_client("$transport$address:$port", $errno, $errstr, 10, STREAM_CLIENT_CONNECT);
            # can be false while $errorno == 0 if error happens before the actual connect eg. dns error - thus the 1234567890 errorno
            if ($this->fd === false) return $this->handleresult(0, $errno === 0 ? 1234567890 : $errno, $errstr);
            if ($protocol == 'ldaptls') return $this->startTLS();
            return 0;
        } else {
            return $this->handleresult(0, 1234567890 , "$url not valid");
        }
    }

    protected function bindRequest($bind_rdn = NULL, $bind_password = NULL, $controls = '')
    {
        return self::LDAPMessage(self::bindRequest,
                                 self::integer(self::version3)
                                 . self::octetstring($bind_rdn)
                                 . "\x80" . self::len($bind_password) . $bind_password,
#                                . self::contextstring(0, $bind_password),
                                 $controls);
    }

    protected function searchRequest($base, $filter, $attributes, $controls = '')
    {
        return self::LDAPMessage(self::searchRequest,
                                 self::octetstring($base)
                                 . self::enumeration($this->options['scope'])
                                 . self::enumeration($this->options['derefaliases'])
                                 . self::integer($this->options['sizelimit'])
                                 . self::integer($this->options['timelimit'])
                                 . self::boolean($this->options['typesonly'])
                                 . $filter
                                 . self::attributes($attributes),
                                 $controls);
    }

    public function bind($bind_rdn = NULL, $bind_password = NULL)
    {
        return $this->sendldapmessage($this->bindRequest($bind_rdn, $bind_password));
    }

    public function unbind()
    {
        $this->sendldapmessage(self::sequence(self::integer($this->messageID++) . self::application(self::unbindRequest, '', false)));
        fclose($this->fd);
    }

    public function startTLS()
    {
        $startTLS = '1.3.6.1.4.1.1466.20037';
        $this->sendldapmessage(self::LDAPMessage(self::extendedReq, "\x80" . self::len($startTLS) . $startTLS));
        if ($this->result()
            || !stream_socket_enable_crypto($this->fd, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) return $this->handleresult(0, 1234567890 , "startTLS failed");
    }

    public function search($base, $filter, $attributes)
    {
        $controls = '';
        if ($pagesize = $this->options['pagesize']) {
            $controls .= self::pagedResultsControl($pagesize, $this->cookie, true);
        }
        if ($resultfilter = $this->options['resultfilter']) {
            $controls .=  self::matchedValuesControl(self::filter($resultfilter));
        }
        $this->sendldapmessage($this->searchRequest($base, self::filter($filter), $attributes, $controls));
    }

    public function nextentry()
    {
        unset($this->cookie);
        $response = $this->receiveldapmessage();
        if ($response['protocolOp'] == 'searchResEntry') {
            return self::searchResEntry($response);
        } else {
            $this->status = $response;
            $this->handleresult();
            foreach($response['controls'] as $control) {
            	if ($control['controlType'] == '1.2.840.113556.1.4.319') {
            		$cookiepdu = $control['controlValue'];
            		$struct = self::berdecode($cookiepdu, strlen($cookiepdu));
            		$this->cookie = $struct[0]['value'][1]['value'];
            	}
            }
            return false;
        }
    }

    public function getpage($base, $filter, $attributes, $paged = false)
    {
        if ($paged && !$this->cookie) return false;
        $this->search($base, $filter, $attributes);
        while ($entry = $this->nextentry()) {
            $res[] = $entry;
        }
        return $res;
    }

    public function modify($dn, $changes)
    { # $changes is array of mods
        $ops = array('add' => 0, 'delete' => 1, 'replace' => 2);
        $pdu = '';
        foreach ($changes as $operation) {
            foreach ($operation as $type => $modification) {
                $pdu = "";
                foreach ($modification as $attributeDesc => $attributeValues) {
                    foreach ($attributeValues as $attributeValue) {
                        $pdu .= self::octetstring($attributeValue);
                    }
                    $pdu = self::sequence(self::octetstring($attributeDesc) . self::set($pdu));
                }
                $pdux .= self::sequence(self::enumeration($ops[$type]) . $pdu);
            }
        }
        $pdu = self::LDAPMessage(self::modifyRequest, self::octetstring($dn) . self::sequence($pdux));
        return $this->sendldapmessage($pdu);
    }

    public function add($entry, $attributes)
    {
        foreach ($attributes as $attributeDesc => $attributeValues) {
            $pdu = '';
            if (!is_array($attributeValues)) $attributeValues = array($attributeValues);
            foreach ($attributeValues as $attributeValue) {
                $pdu .= self::octetstring($attributeValue);
            }
            $pdux .= self::sequence(self::octetstring($attributeDesc) . self::set($pdu));
        }
        $pdu = self::LDAPMessage(self::addRequest, self::octetstring($entry) . self::sequence($pdux));
        return $this->sendldapmessage($pdu);
    }

    public function del($dn)
    {
        $pdu = self::sequence(self::integer($this->messageID++) . self::application(self::delRequest, $dn, false));
        return $this->sendldapmessage($pdu);
    }

    public function modDN($entry, $newrdn, $deleteoldrnd = true, $newsuperior = '')
    {
        $pdu = self::LDAPMessage(self::modDNRequest, self::octetstring($entry)
                                                     . self::octetstring($newrdn)
                                                     . self::boolean($deleteoldrnd)
                                                     . ($newsuperior ? "\x80" . self::len($newsuperior) . $newsuperior : ''));
        return $this->sendldapmessage($pdu);
    }

    public function compare($entry, $attributeDesc, $assertionValue)
    {
        $payload = self::sequence(self::octetstring($attributeDesc) . self::octetstring($assertionValue));
        $pdu = self::LDAPMessage(self::compareRequest, self::octetstring($entry) .  $payload); #. "\xa3" .
        return $this->sendldapmessage($pdu, self::compareTrue);
    }

    public function pp($base, $filter = 'objectclass=*', $attributes = array())
    {
        $c = 0;
        $indent = 30;
        $paged = 0;
        while ($entries = $this->getpage($base, $filter, $attributes, $paged++)) {
            #continue;
            foreach ((array)$entries as $entry) {
                printf("\n%$indent" . "s: %s\n", 'c', $c++);
                printf("%$indent" . "s: %s\n", 'dn', $entry['dn']);
                unset($entry['dn']);
                ksort($entry);
                foreach ($entry as $attr => $vals) {
                    foreach ($vals as $val) {
                        if (preg_match("/[[:cntrl:]]/", $val)) $val = '* ' . bin2hex($val);
                        printf("%$indent" . "s: %s\n", $attr, $val);
                        $attr = '';
                    }
                }
            }
        }
        $status = $this->status();
        if ($status['resultCode']) print_r($status);
    }
}
