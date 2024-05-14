<?php

namespace App\Http\Controllers\api;

use App\Enums\TokenAbility;
use App\Http\Controllers\Controller;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;

class AuthApiController extends Controller
{
    //
    /**
     * @OA\Post(
     *     path="/api/register",
     *     summary="Register a new user",
     *     @OA\Parameter(
     *         name="name",
     *         in="query",
     *         description="User's name",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="email",
     *         in="query",
     *         description="User's email",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="password",
     *         in="query",
     *         description="User's password",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *          name="password_confirmation",
     *          in="query",
     *          description="User's password confirmation",
     *          required=true,
     *          @OA\Schema(type="string")
     *      ),
     *     @OA\Response(response="201", description="User registered successfully"),
     *     @OA\Response(response="422", description="Validation errors")
     * )
     */
    public function register(Request $request)
    {
        $validateUser = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'name' => 'required|string|min:1',
            'password' => 'required|string|min:6|regex:/^(?=.*[A-Z])(?=.*\d).+$/|confirmed'
        ]);

        if ($validateUser->fails()) {
            return $this->handleResponse(false,'The fields with format is invalid.',422);
        }

        try {
            $user = User::firstOrCreate(
                ['email' => $request->email],
                [
                    'name' => $request->name,
                    'password' => Hash::make($request->password)
                ]
            );

            $isCreated = $user->wasRecentlyCreated;
            $message = $isCreated ? 'User created successfully' : 'User already exists';
            if($isCreated) {event(new Registered($user));}
            return $this->handleResponse($isCreated,$message,$isCreated ? 201 : 422);

        } catch (\Exception $e) {
            return $this->handleResponse(false,$e->getMessage(),500);
        }
    }

    /**
     * @OA\Post(
     *     path="/api/login",
     *     summary="Authenticate user and generate JWT token",
     *     @OA\Parameter(
     *         name="email",
     *         in="query",
     *         description="User's email",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="password",
     *         in="query",
     *         description="User's password",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Login successful"),
     *     @OA\Response(response="401", description="Invalid credentials")
     * )
     */
    public function login(Request $request)
    {
        $validateUser = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string|min:6|regex:/^(?=.*[A-Z])(?=.*\d).+$/'
        ]);

        if ($validateUser->fails()) {
            return $this->handleResponse(false, 'The fields with format is invalid.', 422);
        }

        try {
            $user = User::where('email', $request->email)->first();

            if (!$user) {
                return $this->handleResponse(false, 'User not found.', 404);
            }

            if (!Auth::attempt($request->only(['email', 'password']))) {
                return $this->handleResponse(false, 'Email & Password does not match with our record.', 401);
            }

            if (!$user->hasVerifiedEmail()) {
                $user->sendEmailVerificationNotification();
                return $this->handleResponse(false, 'User has not verified email.', 400);
            }

            return $this->handleResponseLogin($user);

        } catch (\Exception $e) {
            return $this->handleResponse(false, $e->getMessage(), 500);
        }
    }

    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();
        return $this->handleResponse(true,'User logged out',200);
    }

    public function forgotPassword(Request $request)
    {
        $validateEmail = Validator::make($request->all(), [
            'email' => 'required|string|email'
        ]);

        if ($validateEmail->fails()) {
            return $this->handleResponse(false,'The email field is invalid.',422);
        }

        try {
            $status = Password::sendResetLink(
                $request->only('email')
            );

            $isSuccess = $status === Password::RESET_LINK_SENT;
            $message = $isSuccess ? 'Password reset link sent to your email address.' : 'Unable to send password reset link.';
            return $this->handleResponse($isSuccess,$message,$isSuccess ? 200 : 500);
        }catch(\Exception $e) {
            return $this->handleResponse(false, $e->getMessage(), 500);
        }
    }

    public function resetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'token' => 'required|string',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if ($validator->fails()) {
            return $this->handleResponse(false,'The fields is invalid.',422);
        }
        try {
            $status = Password::reset(
                $request->only('email', 'password', 'password_confirmation', 'token'),
                function ($user, $password) {
                    $user->forceFill([
                        'password' => Hash::make($password)
                    ])->save();
                }
            );
            $isSuccess = $status === Password::PASSWORD_RESET;
            $message = $isSuccess ? 'Password reset successfully.' : 'Unable to reset password.';
            return $this->handleResponse($isSuccess,$message,$isSuccess ? 200 : 400);
        }
        catch (\Exception $e) {
            return $this->handleResponse(false, $e->getMessage(), 500);
        }
    }

    public function verifyEmail(Request $request, $id)
    {
        try {
            $user = User::find($id);
            if (!$user) {
                return $this->handleResponse(false, 'User not found.', 404);
            }

            $expires = $request->expires;
            $hash = $request->hash;

            if (now()->getTimestamp() > $expires || ! hash_equals($hash, sha1($user->getEmailForVerification()))) {
                return $this->handleResponse(false, 'Invalid verification token.', 400);
            }

            $user->markEmailAsVerified();
            return $this->handleResponse(true, 'Email verified successfully', 200);
        }
        catch (\Exception $e) {
            return $this->handleResponse(false, $e->getMessage(), 500);
        }
    }


    public function refreshToken(Request $request)
    {
        try {
            $request->validate([
                'refresh_token' => 'required',
            ]);

            $user = Auth::user();
            $newAccessToken = $user->createToken(
                'access_token',
                [TokenAbility::ACCESS_API->value],
                Carbon::now()->addMinutes(config('sanctum.expiration'))
            );

            return response()->json([
                'status' => true,
                'message' => 'Refresh token successfully!',
                'access_token' => $newAccessToken,
            ]);
        }
        catch (\Exception $e){
            return $this->handleResponse(false, $e->getMessage(), 500);
        }
    }

    private function handleResponse($status, $message, $statusCode)
    {
        return response()->json([
            'status' => $status,
            'message' => $message,
        ], $statusCode);
    }

    private function handleResponseLogin($user)
    {
        $accessToken = $user->createToken('access_token', [TokenAbility::ACCESS_API->value], Carbon::now()->addMinutes(config('sanctum.expiration')));
        $refreshToken = $user->createToken('refresh_token', [TokenAbility::ISSUE_ACCESS_TOKEN->value], Carbon::now()->addMinutes(config('sanctum.rt_expiration')));
        return response()->json([
            'status' => true,
            'message' => 'User login successfully',
            'data' => [
                'user' => $user->only(['id', 'name', 'email']),
                'token' => $accessToken->plainTextToken,
                'refresh_token' => $refreshToken->plainTextToken,
            ]
        ], 200);
    }


//    protected function sendEmailVerificationNotification($user)
//    {
//        $verificationUrl = URL::temporarySignedRoute(
//            'verification.verify',
//            now()->addMinutes(60),
//            ['id' => $user->id]
//        );
//
//        Mail::to($user->email)->send(new VerifyEmailMail($user, $verificationUrl));
//    }

}
