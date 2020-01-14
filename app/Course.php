<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Course extends Model
{
    protected $fillable = ['name', 'image', 'price', 'start_date', 'end_date', 'teacher_id'];

    public function teacher()
    {
        return $this->belongsTo(Teacher::class);
    }

//student enroll in many courses
    public function students()
    {
        return $this->belongsToMany(Student::class, 'student_course', 'course_id', 'student_id');
    }

    public function comments()
    {
        return $this->hasMany(Comment::class);
    }

    public function supporters()
    {
        return $this->hasMany(Supporter::class);
    }
}
