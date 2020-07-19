<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

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

Route::group(['middleware' => 'api', 'prefix' => 'v1', 'namespace' => 'API\V1'], function() {
    Route::post('auth/register', 'AuthController@register');
    Route::post('auth/login', 'AuthController@login');
    
});

Route::group(['middleware' => 'jwt.verify', 'prefix' => 'v1', 'namespace' => 'API\V1'], function($router) {
    Route::post('auth/logout', 'AuthController@logout');
    Route::post('/user', 'UserController@list');
});
