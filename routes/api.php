<?php

use Illuminate\Support\Facades\Route;
use App\Http\Middleware\ValidateApiKey;
use App\Http\Controllers\QueryController;

Route::get('/query', [QueryController::class, 'query'])->middleware(ValidateApiKey::class)->middleware(ValidateApiKey::class);