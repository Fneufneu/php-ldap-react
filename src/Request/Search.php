<?php

namespace Fneufneu\React\Ldap\Request;

use Fneufneu\React\Ldap\Request;

class Search extends Request
{
	private $options = array(
		'sizelimit' => 0,
		'timelimit' => 0,
		'scope' => self::wholeSubtree,
		'typesonly' => false,
		'pagesize' => 0,
		'resultfilter' => '',
	);

	public function __construct($messageId, array $options)
	{
		$options += $this->options;

		$protocolOp = self::searchRequest;
		$pdu = self::octetstring($options['base'])
			 . self::enumeration($options['scope'])
			 . self::enumeration($options['derefaliases'])
			 . self::integer($options['sizelimit'])
			 . self::integer($options['timelimit'])
			 . self::boolean($options['typesonly'])
			 . self::filter($options['filter'])
			 . self::attributes($options['attributes']);
		$controls = '';
		if ($pagesize = $options['pagesize']) {
			$controls .= self::pagedResultsControl($pagesize, $this->cookie, true);
		}
		if ($resultfilter = $options['resultfilter']) {
			$controls .=  self::matchedValuesControl(self::filter($resultfilter));
		}

		parent::__construct($messageId, $protocolOp, $pdu, $controls);
	}

}

