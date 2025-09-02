<?php
use Illuminate\Support\Str;
use App\Exceptions\TimeoutException;

function resolveDnsRecord($record, $type = 'A', $exclude = false, $nameserver = false, $resolve_cname = false, $trace = false, $authority = true)
{
    $record = dnsspy_idn_to_ascii($record);

    if ($type == 'NS') {
        $exclude = 'root-servers.net';
    }

    $trace_cmd = '';
    if ($trace == true) {
        # Force a lookup at the root nameservers
        $trace_cmd = '+trace';
    }

    if ($exclude) {
        # Ignore text that matches $exclude
        $cmd_suffix = " | grep -v '". $exclude ."'";
    } else {
        $cmd_suffix = "";
    }

    # NS queries can have their response in the AUTHORITY section of `dig`
    if ($type == 'NS' && $authority == true) {
        $extra_options = " +authority ";
        $cmd_suffix    .= " | sort | uniq ";
    } else {
        $extra_options = " ";
    }


    if ($nameserver) {
        $at_nameserver = " @". $nameserver;
    } else {
            $at_nameserver = " @127.0.0.1";
    }

    $default_options = "+tries=2 +time=2";
    $command = "CHARSET=ASCII /usr/bin/dig +nocookie ". $default_options ." ". $trace_cmd . $extra_options . $at_nameserver ." ". $record ." ". $type ." 2>/dev/null | sort ". $cmd_suffix ." | grep -v RRSIG";

    $output = trim(`$command`);

    if ($type == 'A' && $resolve_cname == false) {
        $type = 'A|CNAME';
    }
    if ($type == 'AAAA' && $resolve_cname == false) {
        $type = 'AAAA|CNAME';
    }

    # If we want to resolve CNAMEs, the regex needs to be broad:
    # a CNAME can point to any kind of hostname, so we're using
    # wildcards here.
    if ($resolve_cname == true && ($type == 'A' || $type == 'AAAA' || $type == 'TXT' || $type == 'CAA')) {
        $record = '.*';   /* For any kind of CNAME value */
    }

    # Special case: record isn't deleted, but nameserver just didn't reply
    # within our timeouts.
    if (stristr($output, 'connection timed out')) {
        throw new TimeoutException();
    }


    // Find the requested record(s)
    // \s = whitespace (tabs + spaces)
    $pattern = "/^(". $record .".)\s+([0-9]+)\s+IN\s+(". $type .")\s+(.*)/im";
    $matches = [];

    preg_match_all($pattern, $output, $matches, PREG_SET_ORDER);

    // Now get the timing information
    $pattern = "/^;; Query time: ([0-9]+) msec/im";
    $timing = [];
    preg_match_all($pattern, $output, $timing, PREG_SET_ORDER);
    if (is_array($timing) && count($timing) > 0) {
        $time = $timing[0][1];
    }

    return [
        'matches' => is_array($matches) ? $matches : [],
        'time' => $time
    ];
    
}

function getAuthoritativeNameservers($domain)
{
    # Walk the root until you find the first authoritative nameserver
    # that replies with a valid set of NS records.
    # See: http://simpledns.com/lookup-dg.aspx
    # Test with:
    # - heymans.org
    # - edu.fm
    # - cronweekly.com
    $domain = dnsspy_idn_to_ascii($domain);
    $command = 'CHARSET=ASCII /usr/bin/dig +tries=2 +time=3 +nocookie +trace -t NS '. $domain;

    $output = trim(`$command`);

    # Special case: record isn't deleted, but nameserver just didn't reply
    # within our timeouts.
    if (stristr($output, 'connection timed out')) {
        throw new TimeoutException();
    }


    # Parse the output
    $response_blocks = explode("bytes from", $output);

    # We now have 'blocks' of NS records, per nameserver that responded them
    # Loop each block, find any that match our required domain, and use the first
    # matching response as the authoritative response.
    $pattern = "/^(". $domain .".)\s+([0-9]+)\s+IN\s+(NS)\s+(.*)/im";

    if (is_array($response_blocks) && count($response_blocks) > 0) {
        foreach ($response_blocks as $block) {
            $matches = [];
            preg_match_all($pattern, $block, $matches, PREG_SET_ORDER);
            if (is_array($matches) && count($matches) > 0) {
                // Requested record(s) found

                $arrReturn = [];
                foreach ($matches as $nameserver) {
                    $arrReturn[] = trim($nameserver[4]);
                }

                sort($arrReturn);

                return $arrReturn;
            }
        }
    }

    return [];
}

function resolveCnameRecord($fullrecord, $nameserver)
{
    return resolveSingleRecord($fullrecord, $nameserver, 'A');
}

function resolveARecord($fullrecord, $nameserver)
{
    return resolveSingleRecord($fullrecord, $nameserver, 'A');
}

function resolveAAAARecord($fullrecord, $nameserver)
{
    return resolveSingleRecord($fullrecord, $nameserver, 'AAAA');
}

function resolveSOARecord($fullrecord, $nameserver)
{
    return resolveSingleRecord($fullrecord, $nameserver, 'SOA');
}

function resolveSOARecordAtRoot($domain)
{
    return resolveSingleRecord($domain, false, 'SOA', false, false, true);
}

function timeDnsResponse($nameserver, $domain)
{
    # Do a SOA check on a particular nameserver, time the response
    $domain = dnsspy_idn_to_ascii($domain);
    $cmd = "CHARSET=ASCII /usr/bin/dig +nocookie +time=2 +tries=2 @". $nameserver ." ". $domain ." SOA";

    $output = trim(`$cmd`);

    $pattern = "/^;; Query time: ([0-9]+) msec/im";

    $matches = [];
    preg_match_all($pattern, $output, $matches, PREG_SET_ORDER);
    if (is_array($matches) && count($matches) > 0) {
        if (array_key_exists(0, $matches) && array_key_exists(1, $matches[0])) {

            $response_time = (int) $matches[0][1];
            if ($response_time == 0) {
                # We got a response, but it might be 0 (because it's _really_ fast)
                # In that case, fake 1 ms
                $response_time = 1;
            }

            return $response_time;
        }
    }

    return 0;
}

function resolveSingleRecord($fullrecord, $nameserver, $type = 'A')
{
    $cname_value = '';
    $matches_cname = resolveDnsRecord($fullrecord, $type, false, $nameserver, true);
    $response_cname = flattenDnsResponse($matches_cname);

    if ($response_cname) {
        $cname_value = $response_cname['value'];
    }

    return $cname_value;
}

function getNsRecords($domain, $nameserver = false)
{
    $nameservers = resolveDnsRecord($domain, 'NS', $exclude = 'root-servers.net', $nameserver, false, false, false);
    if (is_array($nameservers) && count($nameservers) > 0) {
        $arrReturn = [];
        foreach ($nameservers as $nameserver) {
            $arrReturn[] = trim($nameserver[4]);
        }

        sort($arrReturn);

        return $arrReturn;
    } else {
        return false;
    }
}

function flattenDnsResponse($responses)
{
    if (is_array($responses) && count($responses) > 0) {
        # Are we dealing with a single response or multiple?
        if (count($responses) == 1) {
            $record = trim($responses[0][1]);
            $value  = trim($responses[0][4]);
            $ttl    = trim($responses[0][2]);
            $type   = trim($responses[0][3]);
        } else {
            # Multiple values
            if (hasCnameRecords($responses)) {
                $responses = filterCnameRecords($responses);
            }

            $arr_matches = [];
            foreach ($responses as $response) {
                $arr_matches[] = $response[4];
            }

            sort($arr_matches);
            $value  = trim(implode("\n", $arr_matches));
            $record = trim($responses[0][1]);
            $ttl    = trim($responses[0][2]);
            $type   = trim($responses[0][3]);
            unset($arr_matches);
        }

        # Cname and MX targets should be compared & stored case insensitively
        if ($type == 'MX' || $type == 'CNAME') {
            $value = strtolower($value);
        }

        # Records themselves are never case sensitive
        $record = strtolower($record);

        return [
        'record' => $record,
        'value' => $value,
        'ttl' => $ttl,
        'type' => $type,
        ];
    } else {
        return false;
    }
}

function hasCnameRecords($responses)
{
    if (is_array($responses) && count($responses) > 0) {
        foreach ($responses as $response) {
            if ($response[3] == 'CNAME') {
                return true;
            }
        }
    }

    return false;
}

function filterCnameRecords($responses)
{
    $return = [];
    if (is_array($responses) && count($responses) > 0) {
        foreach ($responses as $response) {
            if ($response[3] == 'CNAME') {
                $return[] = $response;
            }
        }
    }

    return $return;
}

function hasDnsWildcard($domain, $type = 'A', $nameserver, $resolve_cname = false)
{
    # Get a random string
    $subdomain = Str::random(25);
    $wildcard = $subdomain .".". $domain;
    $ip = resolveDnsRecord($wildcard, $type, false, $nameserver, $resolve_cname);

    # If the domain has a DNS wildcard, return the value where it points to
    if ($ip) {
        return flattenDnsResponse($ip);
    }

    # No wildcard
    return false;
}

function getCssClassForType($type)
{
    switch ($type) {
        case 'A':
            return 'dnsspy_a';
        break;
        case 'AAAA':
            return 'dnsspy_aaaa';
        break;
        case 'CAA':
            return 'dnsspy_caa';
        break;
        case 'CNAME':
            return 'dnsspy_cname';
        break;
        case 'DNSKEY':
            return 'dnsspy_dnskey';
        break;
        case 'MX':
            return 'dnsspy_mx';
        break;
        case 'NS':
            return 'dnsspy_ns';
        break;
        case 'SRV':
            return 'dnsspy_srv';
        break;
        case 'SOA':
            return 'dnsspy_soa';
        break;
        case 'TXT':
            return 'dnsspy_txt';
        break;
        default:
            return 'success';
    }
}

function getHtmlForType($type)
{
    $class = getCssClassForType($type);
    return '<span class="inline-block rounded-full px-3 py-1 text-sm font-semibold text-white mr-2 '. $class .' dnsspy_label label">'. $type .'</span>';
}

function humanReadableShort($time)
{
    $carbon = new Carbon\Carbon($time);
    $diffForHumans = $carbon->diffForHumans();

    $diffForHumans = str_replace([' seconds', ' second'], 'sec', $diffForHumans);
    $diffForHumans = str_replace([' minutes', ' minute'], 'min', $diffForHumans);
    $diffForHumans = str_replace([' hours', ' hour'], 'h', $diffForHumans);
    $diffForHumans = str_replace([' days', ' day'], 'd', $diffForHumans);

    return $diffForHumans;
}

function doZonetransfer($domain, $nameserver)
{
    $domain = dnsspy_idn_to_ascii($domain);
    $command = "CHARSET=ASCII /usr/bin/dig +nocookie +short +tries=2 +time=4 +noshort @". $nameserver ." AXFR ". $domain ." 2>/dev/null | sort";
    $output = trim(`$command`);

    if (stristr($output, 'Transfer failed.') || stristr($output, 'connection timed out')) {
        # Didn't work
        return false;
    } else {
        # A transfer was made, was it complete? It should have 2x SOA records
        # Ref: https://tools.ietf.org/html/rfc5936
        # An AXFR response that is transferring the zone's contents will
        # consist of a series (which could be a series of length 1) of DNS
        # messages.  In such a series, the first message MUST begin with the
        # SOA resource record of the zone, and the last message MUST conclude
        # with the same SOA resource record.

        $pattern = "/(.*)\s([0-9]+)\sIN\sSOA\s(.*)/";
        $matches = [];
        preg_match_all($pattern, $output, $matches, PREG_SET_ORDER);

        # We need at least 2 SOA records (could be more, if the regex somehow matches the value of a CNAME)
        if (count($matches) < 2) {
            # Not enough SOA records, probably never finished the AXFR
            return false;
        } else {
            # We had at least 2 SOA records, return this as a valid response
            return $output;
        }
    }
}

function parseAxfr($zonedata, $domain)
{
    $lines = explode("\n", $zonedata);
    $return = [];

    foreach ($lines as $line) {
        # Parse each line
        $pattern = "/(.*)\s([0-9]+)\sIN\s(A|AAAA|CNAME|TXT|NS|SOA|DNSKEY|MX|SRV|NS|CAA)\s(.*)/";
        $matches = [];
        preg_match_all($pattern, $line, $matches, PREG_SET_ORDER);
        if (is_array($matches) && count($matches) > 0) {
            $record = flattenDnsResponse($matches);

            # Replace "domain.tld." from the record, keep only the base record
            $record_suffix = $domain .".";
            $pos = strrpos($record['record'], $record_suffix);
            if ($pos !== false) {
                $record['record'] = substr_replace($record['record'], "", $pos, strlen($record_suffix));
            }

            # If the last character of the record is a "dot", remove it
            $record_suffix = ".";
            $pos = strrpos($record['record'], $record_suffix);
            if ($pos !== false) {
                $record['record'] = substr_replace($record['record'], "", $pos, strlen($record_suffix));
            }

            $array_key = $record['record'] .'_'. $record['type'];

            if ($record['type'] == 'SOA') {
                # Only make sure to store 1 SOA record (AXFR can return multiple)
                $return[$array_key] = $record;
            } else {
                if (!array_key_exists($array_key, $return)) {
                    $return[$array_key] = $record;
                } else {
                    $return[$array_key]['value'] .= "\n". $record['value'];
                }
            }
        }
    }

    /*
      array:8 [
        "*_CNAME" => array:4 [
          "record" => "*"
          "value" => "cronweekly.com."
          "ttl" => "3600"
          "type" => "CNAME"
        ]
        "_AAAA" => array:4 [
          "record" => ""
          "value" => "2a03:a800:a1:1952::ff"
          "ttl" => "300"
          "type" => "AAAA"
        ]
      ]
    */

    # Sort each of those multi-line entries, so they look similar to how 'dig' would query them
    # Otherwise, it might show up as out-of-sync records, where it's just a resource ordering issue
    foreach ($return as $key => $value) {
        # Sort the value
        $pieces = explode("\n", $value['value']);
        sort($pieces);

        # Add the value back to $return
        $return[$key]['value'] = implode("\n", $pieces);
    }

    return $return;
}

function parseSoa($soa)
{
    if ($soa) {
        $pieces = explode(" ", $soa);
        if (count($pieces) == 7) {
            return [
                'primary_ns' => $pieces[0],
                'responsible_party' => $pieces[1],
                'serial' => $pieces[2],
                'refresh' => $pieces[3],
                'retry' => $pieces[4],
                'expire' => $pieces[5],
                'minimum' => $pieces[6],
            ];
        }
    }

    return false;
}

function parseDnskey($dnskey)
{
    if ($dnskey) {
        $pieces = explode(" ", $dnskey);
        $return = [
        'key_type' => $pieces[0],
        'protocol' => $pieces[1], /* Must be value 3 */
        'public_key_algoritm' => $pieces[2],
        ];

        $return['public_key'] = '';
        for ($i = 3; $i < count($pieces); $i++) {
            $return['public_key'] .= $pieces[$i] .' ';
        }

        /* Parse the key type: ZSK or KSK? */
        if ($return['key_type'] == 256) {
            $return['key_type_readable'] = 'ZSK';
        } elseif ($return['key_type'] == 257) {
            $return['key_type_readable'] = 'KSK';
        } else {
            $return['key_type_readable'] = 'UNKNOWN';
        }

        /* Parse the algoritm */
        switch ($return['public_key_algoritm']) {
            case 1:
                $return['public_key_algoritm_readable'] = 'RSA/MD5';
                break;
            case 2:
                $return['public_key_algoritm_readable'] = 'Diffie-Hellman';
                break;
            case 3:
                $return['public_key_algoritm_readable'] = 'DSA/SHA-1';
                break;
            case 4:
                $return['public_key_algoritm_readable'] = 'Elliptic Curve';
                break;
            case 5:
                $return['public_key_algoritm_readable'] = 'RSA/SHA-1';
                break;
            case 6:
                $return['public_key_algoritm_readable'] = 'DSA-NSEC3-SHA1';
                break;
            case 7:
                $return['public_key_algoritm_readable'] = 'RSASHA1-NSEC3-SHA1';
                break;
            case 8:
                $return['public_key_algoritm_readable'] = 'RSA/SHA-256';
                break;
            case 10:
                $return['public_key_algoritm_readable'] = 'RSA/SHA-512';
                break;
            case 12:
                $return['public_key_algoritm_readable'] = 'GOST R 34.10-2001';
                break;
            case 13:
                $return['public_key_algoritm_readable'] = 'ECDSA Curve P-256 with SHA-256';
                break;
            case 14:
                $return['public_key_algoritm_readable'] = 'ECDSA Curve P-384 with SHA-384';
                break;
            case 15:
                $return['public_key_algoritm_readable'] = 'Ed25519';
                break;
            case 16:
                $return['public_key_algoritm_readable'] = 'Ed448';
                break;
            default:
                $return['public_key_algoritm_readable'] = 'UNKNOWN';
                break;
        }
    } else {
        $return = false;
    }

    return $return;
}

function parseSrv($srv)
{
    if ($srv) {
        $pieces = explode(" ", $srv);

        if (is_array($pieces) && count($pieces) == 4) {
            return [
            'priority' => $pieces[0],
            'weight' => $pieces[1],
            'port' => $pieces[2],
            'target' => $pieces[3],
            ];
        }
    }

    return false;
}

function parseMx($mx)
{
    if ($mx) {
        $pieces = explode(" ", $mx);
        return [
            'priority' => $pieces[0],
            'target' => $pieces[1],
        ];
    } else {
        return false;
    }
}

function parseCaa($caa)
{
    if ($caa) {
        $pieces = explode(" ", $caa);


        $return = [
        'flags' => $pieces[0],
        'tag' => $pieces[1],
        'value' => $pieces[2],
        ];

        for ($i = 3; $i < count($pieces); $i++) {
            $return['value'] .= ' '. $pieces[$i];
        }

        # Strip quotes from the value
        $return['value'] = str_replace('"', '', $return['value']);

        # Normalize semi-colons
        $return['value'] = str_replace('\;', ';', $return['value']);

        if ($return['tag'] == 'issue' || $return['tag'] == 'issuewild') {
            # The value portion can contain multiple parts; https://tools.ietf.org/html/rfc6844#section-5.2
            # If it only contains one part, fake it to make 2 pieces
            if ($return['value'] == ';') {
                // Special cases: this means no one is allowed to issue certificates
                $return['value_'. $return['tag']]['domain'] = ';';
            } else {
                if (stristr($return['value'], ';') === false) {
                    # Value does not contain semicolon, only the domain value will be present
                    $return['value_'. $return['tag']]['domain'] = $return['value'];
                    $return['value_'. $return['tag']]['parameter'] = '';
                } else {
                    // First semi-colon splits domain vs. parameters
                    // The parameters can contain more semicolons on their own
                    $value_pieces = explode(";", $return['value']);
                    $value_domain = array_shift($value_pieces);
                    $value_parameter = trim(implode(';', $value_pieces));

                    $return['value_'. $return['tag']]['domain'] = $value_domain;
                    $return['value_'. $return['tag']]['parameter'] = $value_parameter;
                }
            }
        }

        return $return;
    } else {
        return false;
    }
}

function isValidCaaDomain($domain)
{
    if (strlen($domain) > 5) {
        $fullUrl = 'http://'. $domain;
        if (false === filter_var($fullUrl, FILTER_VALIDATE_URL)) {
            // failed test
            return false;
        }

        return true;
    }

    return false;
}

function isValidCaaIodef($target)
{
    if (strlen($target) > 5) {
        if (false === filter_var($target, FILTER_VALIDATE_URL)) {
            // failed test
            return false;
        }

        return true;
    }

    return false;
}

function prepareRecordInMail($record)
{
    # If it's a multi-line record, start it on a new line
    if (strstr($record, "\n")) {
        $record = "\n". $record;
    }

    return $record;
}

function temporaryFile($name, $content)
{
    $random_element = md5(time() ."salt_5410135999");

    $file = DIRECTORY_SEPARATOR .
            trim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) .
            DIRECTORY_SEPARATOR .
            ltrim($random_element . $name, DIRECTORY_SEPARATOR);

    file_put_contents($file, $content);

    return $file;
}

function parseZonefileCheck($content, $zone)
{
    $arrWarnings = [];

    if (strlen($content) > 10) {
        $lines = explode("\n", $content);
        foreach ($lines as $line) {
            if (!stristr($line, 'loaded serial') &&
            !stristr($line, 'not loaded due to errors') &&
            !stristr($line, 'loading from master')
            ) {
                # Detect zone errors
                $regex = '#^zone '. $zone .'/IN: (.*)$#';
                $matches = [];
                preg_match_all($regex, $line, $matches, PREG_SET_ORDER);

                if (is_array($matches) && count($matches) > 0) {
                    # This output needs some love, it's like this:
                    # Input: exlibris.domain.tld/MX 'exlibris.domain.tld' has no address records (A or AAAA)
                    # transform to:
                    # Output: exlibris.domain.tld MX record: 'exlibris.domain.tld' has no address records (A or AAAA)
                    $match = $matches[0][1];
                    $match = str_replace('/MX ', ' MX record: value ', $match);
                    $match = str_replace('/TXT ', ' TXT record: value ', $match);
                    $match = str_replace('/SRV ', ' SRV record: value ', $match);

                    $arrWarnings[] = $match;
                }
            }
        }

        return $arrWarnings;
    } else {
        return false;
    }
}

function domainTopLevels($domain)
{
    $pieces = explode(".", $domain);
    $levels = [];

    if (count($pieces) > 0) {
        for ($i = 1; $i < count($pieces); $i++) {
            $domain_tmp = "";
            for ($x = $i; $x < count($pieces); $x++) {
                if ($domain_tmp != "") {
                    $domain_tmp = $domain_tmp .'.';
                }

                $domain_tmp .= $pieces[$x];
            }

            $levels[] = $domain_tmp;
        }

        return $levels;
    } else {
        return false;
    }
}

function getWhoisFromIP($ip)
{
    if (stristr($ip, ":")) {
        # This is an IPv6 address
        $full_ipv6   = expand_ipv6($ip);
        $reversed_ip = reverse_ipv6($full_ipv6);

        $cmd = "dig +nocookie +short +tries=2 +time=3 ". $reversed_ip .".origin6.asn.cymru.com TXT | head -n 1";
    } else {
        # IPv4
        $reversed_ip = reverse_ip($ip);
        $cmd = "dig +nocookie +short +tries=2 +time=3 ". $reversed_ip .".origin.asn.cymru.com TXT | head -n 1";
    }

    #dump($cmd);
    $output = trim(`$cmd`);

    # Parse output
    if (strlen($output) > 0) {
        # $  dig +short 36.211.239.193.origin.asn.cymru.com TXT
        # "39318 | 193.239.210.0/23 | BE | ripencc | 2005-06-30"
        $pieces = explode("|", $output);

        if (is_array($pieces) && count($pieces) == 5) {
            $as_number = trim($pieces[0]);
            $as_number = str_replace('"', '', $as_number);

            return [
            'PROVIDER' => 'AS'. $as_number .' - '. resolve_asnumber($as_number),
            'LOCATION' => trim($pieces[2]),
            ];
        }
    }

    return false;
}

function expand_ipv6($ip)
{
    $hex = unpack("H*hex", inet_pton($ip));
    $ip  = substr(preg_replace("/([A-f0-9]{4})/", "$1:", $hex['hex']), 0, -1);

    # Turn this: fe80:0001:0000:0000:0000:0000:0000:0af0
    # Into this: fe80.0001.0.0.0.0.0.0af0
    # Credits: http://stackoverflow.com/questions/12095835/quick-way-of-expanding-ipv6-addresses-with-php
    # Also converts ":" to "." for DNS queries
    $ip = str_replace('0000', '0', $ip);
    $ip = str_replace(':', '', $ip);

    return $ip;
}

function reverse_ip($ip)
{
    $ip_parts   = explode(".", $ip);
    $reverse_ip = [];

    # Loop the array, reverse each part
    # Turns this: 193.239.211.36
    # Into this: 36.211.239.193
    for ($i = count($ip_parts); $i > 0; $i--) {
        $reverse_ip[] = $ip_parts[$i-1];
    }

    return implode(".", $reverse_ip);
}

function reverse_ipv6($ip)
{
    $reverse_ip = [];

    # Loop the array, reverse each part
    # Turns this: 193.239.211.36
    # Into this: 36.211.239.193
    for ($i = strlen($ip); $i > 0; $i--) {
        $reverse_ip[] = $ip[$i-1];
    }

    return implode(".", $reverse_ip);
}

function resolve_asnumber($as)
{
    $cmd = "dig +tries=2 +time=3 +nocookie +short AS". $as .".asn.cymru.com TXT | head -n 1";

    #dump($cmd);

    $output = trim(`$cmd`);

    # Parse output
    if (strlen($output) > 0) {
        # $  dig +short 36.211.239.193.origin.asn.cymru.com TXT
        # "39318 | 193.239.210.0/23 | BE | ripencc | 2005-06-30"
        $pieces = explode("|", $output);

        if (is_array($pieces) && count($pieces) == 5) {
            # Remove the trailing quote from the output
            # $pieces[4]: CLOUDFLARENET - CloudFlare, Inc., US"
            $as_name = $pieces[4];
            $as_name = substr($as_name, 0, strlen($as_name) - 1);

            return trim($as_name);
        }
    }
}

function grab_first_ip($ip)
{
    # If there are multiple IP values in $ip, pick the first one
    if (stristr($ip, "\n")) {
        # Multiline value found, this is round robin DNS, pick the first IP
        # TODO: properly handle round robin, see Cloudflare as an example!
        $ip_pieces = explode("\n", $ip);
        $ip = $ip_pieces[0];
    }

    return $ip;
}

function dnsspy_idn_to_ascii($value)
{
    return idn_to_ascii($value, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
}
