<?php

use Illuminate\Database\Seeder;


class CreateAdminUserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $user = User::create([
            'name' => 'Islam emam',
            'email' => 'admin@admin.com',
            'password' => bcrypt('123456')
        ]);
        $role1 = Role::create(['name' => 'Admin']);
        $role2 = Role::create(['name' => 'Teacher']);
        $role3 = Role::create(['name' => 'Supporter']);
        $permissions = Permission::pluck('id', 'id')->all();
        $role1->syncPermissions($permissions);
        $user->assignRole([$role1->id]);


//        $user = \App\Student::create([
//            'name' => 'islam',
//            'email' => 'islamemam@yahoo.com',
//            'password' => bcrypt('123456'),
//            'gender' => 'male',
//            'dob' => '1995-07-12',
//            'image' => 'islam.jpg'
//
//        ]);
    }

}
