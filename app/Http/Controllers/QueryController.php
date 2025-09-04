<?php

namespace App\Http\Controllers;

use App\Http\Requests\QueryRequest;
use ReflectionProperty;

class QueryController extends Controller
{
    public function query(QueryRequest $request)
    {
        $resolver = new \NetDNS2\Resolver();
        $resolver->nameservers = [$request->nameserver ?? '127.0.0.1'];
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
                    'error' => 'Socket error',
                    'message' => 'Could not connect to nameserver'
                ], 500);
            }
            return response()->json([
                'code' => $e->getCode(),
                'error' => 'Unknown error',
                'message' => $e->getMessage()
            ], 500);
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
            } else {
                $results[$propName] = $answer->$propName instanceof \Stringable ? $answer->$propName->__toString() : $answer->$propName;
            }
        }
        return $results;
    }
}
