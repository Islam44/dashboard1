<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('login', 'Student\StudentAuthController@login');
Route::post('register', 'Student\StudentAuthController@register');
Route::get('verifyemail/{token}', 'Student\StudentAuthController@verify')->name('verify');

Route::group(['middleware' => 'auth.jwt'], function () {
    Route::get('logout', 'Student\StudentAuthController@logout');
    Route::get('me', 'Student\StudentAuthController@me');
    Route::post('me/update/{user}', 'Student\StudentAuthController@update');
    Route::get('course/{course}', 'Student\StudentAuthController@enroll');
    Route::get('mycourses', 'Student\StudentAuthController@courses');
    Route::post('course/comment/{course}', 'Student\StudentAuthController@comment');
});


