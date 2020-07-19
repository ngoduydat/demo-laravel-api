<?php

namespace App\Http\Controllers\API\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use App\User;
use Hash;
use JWTAuth;


class AuthController extends Controller
{

    public function __constructor() {
       
    }

    public function profile(Request $request) {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            if( !$user ) throw new Exception('User Not Found');
        } catch (Exception $e) {
            if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException){
                return response()->json([
                    'data' => null,
                    'status' => false,
                    'err_' => [
                    'message' => 'Token Invalid',
                    'code' => 1
                    ]
                ]
            );
        } else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException){
            return response()->json([
                    'data' => null,
                    'status' => false,
                    'err_' => [
                    'message' => 'Token Expired',
                    'code' =>1
                    ]
                ]
            );
        }
        else {
            if( $e->getMessage() === 'User Not Found') {
                return response()->json([
                    "data" => null,
                    "status" => false,
                    "err_" => [
                    "message" => "User Not Found",
                    "code" => 1
                    ]
                ]
            ); 
        }
            return response()->json([
                        'data' => null,
                        'status' => false,
                        'err_' => [
                        'message' => 'Authorization Token not found',
                        'code' =>1
                        ]
                    ]
                );
            }
        }
    }

    public function register(Request $request) {

        try {
            $rules  = [
                'name' => 'required|max:255',
                'email' => 'required|max:255|email|unique:users',
                'password' => 'required|min:6',
            ];

            $messages =[
                'required' => ':attribute là bắt buộc.',
                'email.email' => 'Email không đúng định dạng',
                'email.max' => 'Email không quá 255 kí tự',
                'email.unique' => 'Email đã tồn tại',
                'password.min' => 'Mật khẩu ít nhất 6 kí tự',
            ];

            $fieldNames = [
                'name' => 'Họ tên',
                'email' => 'Email',
                'password' => 'Mật khẩu',
            ];

            $validator = Validator::make($request->all(), $rules, $messages);

            if ($validator->fails()) {

                
                $validator->setAttributeNames($fieldNames);

                $msg = [];
                foreach ($validator->errors()->toArray() as $error) {
                    $msg[] = $error[0];
                }
                $msg = implode(',', $msg);

                return response()->json([
                    'status' => false,
                    'msg' => $msg,
                    'data' => null,
                    'code' => 200
                ]);
            } else {

                $user = new User();
                $user->name = $request->get('name');
                $user->email = $request->get('email');
                $user->password = bcrypt($request->get('password'));
             
                $user->save();

                $token = null;
                if ($user) {
                    Auth::login($user);
                    $token = JWTAuth::attempt(['email' => $user->email, 'password' => $request->get('password')]);
                    if (!$token) {
                        return response()->json(['invalid_email_or_password'], 422);
                    }
                }

                return response()->json([
                    'status' => true,
                    'msg' => 'Đăng kí tài khoản thành công',
                    'data' => $user,
                    'token' => $token,
                    'code' => 200
                ]);
            }
           
        } catch (Exception $e) {
            return response()->json([
                'status' => false,
                'msg' => 'Đăng nhập thất bại!',
                'data' => null,
                'code' => 200
            ]);
        }
    }

   

    /**
     * Get a JWT token via given credentials.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        $token = null;

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(
                [
                    'status' => false,
                    'msg' => 'Đăng nhập thất bại!',
                    'data' => null,
                    'code' => 401
                ]);
        }

        return response()->json([
            'status' => true,
            'msg' => 'Đăng nhập thành công!',
            'token' => $token,
            'code' => 200
        ]);
    }

    /**
     * Get the authenticated User
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json($this->guard()->user());
    }

    /**
     * Log the user out (Invalidate the token)
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        $this->guard()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    public function refresh()
    {
        return $this->respondWithToken($this->guard()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $this->guard()->factory()->getTTL() * 60
        ]);
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\Guard
     */
    public function guard()
    {
        return Auth::guard();
    }
}
