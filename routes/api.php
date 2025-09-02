<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Middleware\ValidateApiKey;
use App\Http\Requests\QueryRequest;
use App\Exceptions\TimeoutException;

Route::get('/query', function (QueryRequest $request) {
    try{
        dd(resolveDnsRecord($request->record, $request->type, $request->exclude, $request->nameserver, $request->resolve_cname, $request->trace, $request->authority));
    } catch (TimeoutException $e) {
        return response()->json(['error' => 'Timeout'], 500);
    }
})->middleware(ValidateApiKey::class);

Route::get('/test', function () {
    return 'ok';
});