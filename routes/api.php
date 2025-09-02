<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Middleware\ValidateApiKey;
use App\Http\Requests\QueryRequest;
use App\Exceptions\TimeoutException;

Route::get('/query', function (QueryRequest $request) {
    try{
        $exclude = $request->exclude === null ? false : $request->exclude;
        $nameserver = $request->nameserver === null ? false : $request->nameserver;
        $resolve_cname = $request->resolve_cname === null ? false : $request->resolve_cname;
        $trace = $request->trace === null ? false : $request->trace;
        $authority = $request->authority === null ? false : $request->authority;
        $response =  resolveDnsRecord($request->record, $request->type, $exclude, $nameserver, $resolve_cname, $trace, $authority);
        if($response) {
            return response()->json($response);
        } else {
            return response()->json(['error' => 'No response'], 204);
        }
    } catch (TimeoutException $e) {
        return response()->json(['error' => 'Timeout'], 408);
    }
})->middleware(ValidateApiKey::class);

Route::get('/test', function () {
    return 'ok';
});