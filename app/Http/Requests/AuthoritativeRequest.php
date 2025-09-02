<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class AuthoritativeRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'domain' => 'required|string',
        ];
    }
}
