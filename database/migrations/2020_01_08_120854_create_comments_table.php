<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateCommentsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('comments', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('course_id')->nullable()
                ->on('courses')->onUpdate('cascade')->onDelete('set null');
            $table->foreign('course_id')->references('id')->on('courses');
            $table->unsignedBigInteger('student_id')->nullable()
                ->on('students')->onUpdate('cascade')->onDelete('set null');
            $table->foreign('student_id')->references('id')->on('students');

            $table->unsignedBigInteger('supporter_id')->nullable()
                ->on('users')->onUpdate('cascade')->onDelete('set null');
            $table->foreign('supporter_id')->references('id')->on('users');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('comments');
    }
}
