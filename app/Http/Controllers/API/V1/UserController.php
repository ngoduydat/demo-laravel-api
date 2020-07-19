<?php

namespace App\Http\Controllers\API\V1;

use App\User;
use App\Payment;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use App\Helpers\VibaseHelper;
use App\Http\Controllers\API\V1\BaseController;
use Validator;
use JWTAuth;

class UserController
{

    public function list() {

        try {
            return response()->json([
                'status' => false,
                'msg' => 'Success',
                'data' => 'hello',
                'code' => 200
            ]);
            
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'msg' => $e->getMessage(),
                'data' => null,
                'code' => 200
            ]);
        }
    }
}