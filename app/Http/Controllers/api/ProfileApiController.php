<?php

namespace App\Http\Controllers\api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;

class ProfileApiController extends Controller
{
    /**
     * @OA\Get(
     *     path="/api/profile/{id}",
     *     summary="Get user profile by ID",
     *     description="Retrieve user profile details by ID",
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="User ID",
     *         @OA\Schema(
     *             type="integer"
     *         )
     *     ),
     *     @OA\Response(
     *         response="200",
     *         description="Successful operation"
     *     ),
     *     @OA\Response(
     *         response="404",
     *         description="User not found"
     *     ),
     *     security={{"bearerAuth":{}}}
     * )
     */

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
            $profile->update([
                'name' => $request->name,
                'date_of_birth' => $request->date_of_birth
            ]);

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
