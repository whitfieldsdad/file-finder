rule Big_Numbers0
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 20:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}

rule Big_Numbers1
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 32:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{32}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers2
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 48:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{48}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers3
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 64:sized"
		date = "2016-07"
	strings:
        	$c0 = /[0-9a-fA-F]{64}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers4
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 128:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{128}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers5
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 256:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{256}/ fullword wide ascii
	condition:
		$c0
}