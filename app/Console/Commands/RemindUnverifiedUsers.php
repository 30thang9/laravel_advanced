<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\User;

class RemindUnverifiedUsers extends Command
{
    protected $signature = 'users:remind-unverified';
    protected $description = 'Send reminders to unverified users';

    public function handle()
    {
        $unverifiedUsers = User::where('email_verified_at', null)->get();

        foreach ($unverifiedUsers as $user) {
            $user->sendEmailVerificationNotification();
        }

        $this->info('Reminder emails sent to unverified users.');
    }
}
