<?php

namespace App\Http\Controllers\api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;

class ProfileApiController extends Controller
{
    public function getProfile($id)
    {
        $profile = User::find($id);

        if (!$profile) {
            return response()->json(
                [
                    'status' => false,
                    'message' => 'Profile not found'
                ], 404);
        }

        return response()->json(
            [
                'status' => true,
                'message' => 'Profile selected successfully',
                'data' => $profile
            ], 200);
    }

    public function updateProfile(Request $request, $id)
    {
        $profile = User::find($id);

        if (!$profile) {
            return response()->json(
                [
                    'status' => false,
                    'message' => 'Profile not found'
                ], 404);
        }
        try {
            $profile->update($request->only('name'));

            return response()->json(
                [
                    'status' => true,
                    'message' => 'Profile updated successfully',
                    'data' => $profile
                ], 200);
        }
        catch (\Exception $e) {
            return response()->json(
                [
                    'status' => false,
                    'message' => $e->getMessage()
                ], 500);
        }
    }

    public function deleteProfile($id)
    {
        $profile = User::find($id);

        if (!$profile) {
            return response()->json(
                [
                    'status' => false,
                    'message' => 'Profile not found'
                ], 404);
        }

        try{
            $profile->delete();

            return response()->json(
                [
                    'status' => true,
                    'message' => 'Profile deleted successfully'
                ], 200);
        }
        catch (\Exception $e) {
            return response()->json(
                [
                   'status' => false,
                   'message' => $e->getMessage()
                ], 500);
        }
    }
}
