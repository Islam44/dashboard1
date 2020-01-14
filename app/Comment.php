<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Comment extends Model
{
    protected $fillable = ['body', 'course_id', 'student_id', 'supporter_id', 'status'];

    public function course()
    {
        return $this->belongsTo(Course::class);

    }
}
