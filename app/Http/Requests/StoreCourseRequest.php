<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreCourseRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'name' => "required|min:2",
            'created_at' => "required",
            'image' => 'required|image|mimes:png,jpg',
            'price' => "required",
            'start_date' => "required",
            'end_date' => "required",
        ];
    }
}
