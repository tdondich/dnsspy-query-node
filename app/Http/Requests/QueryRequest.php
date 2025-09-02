<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class QueryRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'record' => 'required|string',
            'type' => 'required|string',
            'exclude' => 'nullable|string',
            'nameserver' => 'nullable|string',
            'resolve_cname' => 'nullable|boolean',
            'trace' => 'nullable|boolean',
            'authority' => 'nullable|boolean',
        ];
    }
}
