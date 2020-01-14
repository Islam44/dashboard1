<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class AddAvailableToUsersTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->unsignedBigInteger('teacher_id')->nullable()
                ->on('users')->onUpdate('cascade')->onDelete('set null');;
            $table->foreign('teacher_id')->references('id')->on('users');
            $table->unsignedBigInteger('course_id')->nullable()
                ->on('courses')->onUpdate('cascade')->onDelete('set null');;
            $table->foreign('course_id')->references('id')->on('courses');
            $table->boolean('available')->default(false);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            //
        });
    }
}
