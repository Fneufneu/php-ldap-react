<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Ber;
use Fneufneu\React\Ldap\Request;

class Search extends Request
{
	private $options = array(
		'cookie' => '',
		'filter' => '(objectclass=*)',
		'pagesize' => 0,
		'resultfilter' => '',
		'scope' => self::wholeSubtree,
		'sizelimit' => 0,
		'timelimit' => 0,
		'typesonly' => false,
	);

	public function __construct($messageId, array $options)
	{
		$options += $this->options;

		$protocolOp = self::searchRequest;
		$pdu = Ber::octetstring($options['base'])
			 . Ber::enumeration($options['scope'])
			 . Ber::enumeration($options['derefaliases'])
			 . Ber::integer($options['sizelimit'])
			 . Ber::integer($options['timelimit'])
			 . Ber::boolean($options['typesonly'])
			 . self::filter($options['filter'])
			 . self::attributes($options['attributes']);
		$controls = '';
		if ($pagesize = $options['pagesize']) {
			$controls .= self::pagedResultsControl($pagesize, $options['cookie'], true);
		}
		if ($resultfilter = $options['resultfilter']) {
			$controls .=  self::matchedValuesControl(self::filter($resultfilter));
		}

		parent::__construct($messageId, $protocolOp, $pdu, $controls);
	}

}

