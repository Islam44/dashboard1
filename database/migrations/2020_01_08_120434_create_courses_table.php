<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateCoursesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('courses', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->string('name');
            $table->date('created_when');
            $table->string('image')->nullable();
            $table->string('price');
            $table->date('start_date');
            $table->date('end_date');
            $table->unsignedBigInteger('teacher_id')->nullable()
                ->on('users')->onUpdate('cascade')->onDelete('set null');;
            $table->foreign('teacher_id')->references('id')->on('users');
            //$table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('courses');
    }
}
