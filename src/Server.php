<?php

namespace Fneufneu\React\Ldap;



class Server extends Ldap
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
			fclose($this->fd);
			$this->fd = $client;
			while(1) {
				$message = $this->receiveldapmessage();
				$protocolOp = $message['protocolOp'];
				$this->$protocolOp($message);
				if ($protocolOp == 'unbindRequest') return;
			}
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

