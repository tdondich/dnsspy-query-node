<?php

namespace App\Http\Controllers;

use App\Http\Requests\QueryRequest;
use ReflectionProperty;

class QueryController extends Controller
{
    public function query(QueryRequest $request)
    {
        // First, we have to fetch the IP address of the requested nameserver.  It may already be 
        // an IP address, or a potential hostname.  If it's an IP address, go ahead and use it.  If it's 
        // a hostname, then we need to try and fetch it's ip address using the resolver.

        $nameserver = $request->nameserver;
        if(filter_var($nameserver, FILTER_VALIDATE_IP)) {
            $nameserver = [$nameserver];
        } else {
            $result = $this->resolveNameserver($nameserver);
            if(!$result) {
                return response()->json([
                    'code' => 404,
                    'error' => 'Could not resolve nameserver',
                    'message' => 'Could not resolve nameserver'
                ], 400);
            }
        }

        $resolver = new \NetDNS2\Resolver();
        $resolver->nameservers = $nameserver;
        try {
            $result =  $resolver->query($request->name, $request->type);

            $header = $this->parseHeader($result->header);

            $answers = collect($result->answer)->map(function ($answer) {
                return $this->parseAnswer($answer);
            });

            $additional = collect($result->additional)->map(function ($additional) {
                return $this->parseAnswer($additional);
            });

            $response = [
                'header' => $header,
                'answers' => $answers,
                'additional' => $additional,
                'response_time' => $result->response_time
            ];

            return response()->json($response);
        } catch (\NetDNS2\Exception $e) {
            // Check to see if code was a socket error
            if ($e->getCode() == \NetDNS2\ENUM\Error::INT_FAILED_SOCKET->value) {
                return response()->json([
                    'code' => $e->getCode(),
                    'error' => \NetDNS2\ENUM\Error::INT_FAILED_SOCKET->label(),
                    'message' => 'Could not connect to nameserver'
                ], 522); // Timeout potentially reaching the origin nameserver
            }
            return response()->json([
                'code' => $e->getCode(),
                'error' => \NetDNS2\ENUM\Error::from($e->getCode())->name,
                'message' => $e->getMessage()
            ], 400);
        }
    }

    private function parseHeader(\NetDNS2\Header $header)
    {
        return [
            'id' => $header->id,
            'qr' => $header->qr,
            'opcode' => $header->opcode->value,
            'aa' => $header->aa,
            'tc' => $header->tc,
            'rd' => $header->rd,
            'ra' => $header->ra,
            'z' => $header->z,
            'ad' => $header->ad,
            'cd' => $header->cd,
            'rcode' => $header->rcode->value,
            'qdcount' => $header->qdcount,
            'ancount' => $header->ancount,
            'nscount' => $header->nscount,
            'arcount' => $header->arcount,
        ];
    }

    private function parseAnswer(\NetDNS2\RR $answer)
    {
        // Get all the properties and dump to array
        $reflector = new \ReflectionClass($answer);
        $properties = collect($reflector->getProperties(ReflectionProperty::IS_PUBLIC | ReflectionProperty::IS_PROTECTED));
        $results = [];
        foreach($properties as $property) {
            $propName = $property->getName();
            if(in_array($propName, [
                'udp_length', 
                'rdata',
                'rdlength'
                ])) {
                continue;
            }
            // if the property is an Enum, get the label
            if($answer->$propName instanceof \BackedEnum) {
                $results[$propName] = $answer->$propName->label();
            } else if(is_array($answer->$propName)) {
                // If the property is an array, iterate through the array (for txt?)
                $tmp = [];
                foreach($answer->$propName as $item) {
                    $tmp[] = $item->__toString();
                }
                $results[$propName] = $tmp;
            } else {
                $results[$propName] = $answer->$propName instanceof \Stringable ? $answer->$propName->__toString() : $answer->$propName;
            }
        }
        $results['__string'] = $answer->__toString();
        return $results;
    }

    private function resolveNameserver($nameserver)
    {
        $resolver = new \NetDNS2\Resolver();
        $resolver->nameservers = ['127.0.0.1'];

        try {
            $result = $resolver->query($nameserver, 'A');
            if(count($result->answer) > 0) {
                return $result->answer[0]->address;
            } else {
                return null;
            }
        } catch (\NetDNS2\Exception $e) {
            return null;
        }
    }
}
