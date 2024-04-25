<?php

use App\Http\Controllers\api\AuthApiController;
use App\Http\Controllers\api\ProfileApiController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

// Authentication
Route::post('/login', [AuthApiController::class, 'login']);
Route::post('/register', [AuthApiController::class, 'register']);
Route::post('/logout', [AuthApiController::class, 'logout']);
Route::post('/forgot-password', [AuthApiController::class, 'forgotPassword']);
Route::post('/reset-password', [AuthApiController::class, 'resetPassword']);
Route::post('/verify-email/{id}', [AuthApiController::class, 'verifyEmail']);

// User Profile
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/profile/{id}', [ProfileApiController::class, 'getProfile']);
    Route::put('/profile/{id}', [ProfileApiController::class, 'updateProfile']);
    Route::delete('/profile/{id}', [ProfileApiController::class, 'deleteProfile']);
});
