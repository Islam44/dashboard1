<?php

namespace App;

use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;


class Student extends User implements JWTSubject
{
    use Notifiable;
    protected $fillable = ['name', 'email', 'password', 'gender', 'dob', 'image','email_token', 'last_login_at',
        'last_login_ip',];

    public function courses()
    {
        return $this->belongsToMany(Course::class, 'student_course')->withTimestamps();
    }

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }

    public function tasks()
    {
        return $this->hasMany(Task::class);
    }
}
