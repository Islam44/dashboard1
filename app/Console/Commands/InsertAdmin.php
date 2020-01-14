<?php

namespace App\Console\Commands;

use App\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;
use Spatie\Permission\Models\Role;

class InsertAdmin extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'create:admin {--email=} {--password=}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command description';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $email = $this->option('email');
        $password = $this->option('password');
        $user= User::create([
            'name' => 'admin',
            'email' => $email,
            'password' => Hash::make($password),
             'image'=>'images/images.jpeg',
            'national_id'=>'no national id',
        ]);
        ($user->assignRole([(Role::where('name','=','Admin')->first())->id]));
    }
}
