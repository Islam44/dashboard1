<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Task extends Model
{
    protected $table = 'tasks';

    /**
     * @var array
     */
    protected $guarded = [];

    public function student()
    {
        return $this->belongsTo(Task::class);
    }
}
