<?php
namespace App\Http\Controllers\API\V1;

use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Http\Request;
use JWTAuth;
use JWTAuthException;
use Hash;
use Validator;
use App\Helpers\VibaseHelper;
use Illuminate\Support\Facades\Auth;
use Session;
use App\CartModel;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;


class BaseController extends Controller
{
    protected $auth = null;

    public function __construct(Request $request)
    {
        
        try {
            $token = $request->header('Authorization');
            if (!$token) {
                $token = $request->get('token');
            }
            $user = JWTAuth::toUser($token);
            $credentials = [
                'email' 
            ];
            
            session(['token' => $token]);
            $this->auth = $user;
            Auth::login($user);
        } catch (JWTException $e) {
            if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException) {
                return response()->json([
                    'status' => false,
                    'msg' => 'Token is expired',
                    'data' => null,
                    'code' => 422
                ], 422);

            } elseif ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException) {
                return response()->json([
                    'status' => false,
                    'msg' => 'Token is Invalid',
                    'data' => null,
                    'code' => 422
                ], 422);

                return response()->json(['token_invalid'], $e->getStatusCode());
            } else {
                return response()->json([
                    'status' => false,
                    'msg' => 'Token is required',
                    'data' => null,
                    'code' => 422
                ], 422);
            }
        }
    }
}