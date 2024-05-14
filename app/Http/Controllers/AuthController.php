<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AuthController extends Controller
{
    //
    public function showResetForm()
    {
        return view('auth.reset_password');
    }
    public function verifyEmail(){
        return view('auth.view_verify');
    }

}
