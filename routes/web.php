<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});


Route::get('password/reset/{token}', [AuthController::class,'showResetForm'])->name('password.reset');
Route::get('verification/verify/{id}', [AuthController::class,'verifyEmail'])->name('verification.verify');
