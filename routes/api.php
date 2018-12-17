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


Route::group(['middleware' => 'auth:api','prefix' => '/mobile'], function () {
	Route::get('/get-users', 'Api\LoginController@getUsers');
});

Route::post('/mobile/login', 'Api\LoginController@login');
Route::post('/mobile/refresh-token', 'Api\LoginController@refreshToken');