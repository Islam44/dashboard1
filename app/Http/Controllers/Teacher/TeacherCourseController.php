<?php

namespace App\Http\Controllers\Teacher;

use App\Course;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreCourseRequest;
use App\Teacher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class TeacherCourseController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $currentuser=auth()->user();
        if($currentuser->hasAnyRole(['Admin', 'Teacher'])){
            $currentuser= Teacher::find(auth()->user()->getAuthIdentifier());
            $courses = $currentuser->courses;
            return response()->json($courses);

        }
        else{
            return response("you cant do this operation");
        }
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */

    public function store(StoreCourseRequest $request)
    {
        $currentuser=auth()->user();
        if($currentuser->hasAnyRole(['Admin', 'Teacher'])) {
            $course = Course::create([
                'name' => $request->name,
                'created_at' => $request->created_at,
                'image' => $request->image->store('images'),
                'price' => $request->price * 100,
                'start_date' => $request->start_date,
                'end_date' => $request->end_date,
                'user_id' => auth()->user()->id
            ]);
            return response()->json($course);
        }
        else{
            return  response()->json('you cant do this operation');
        }
    }


    /**
     * Display the specified resource.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function show(Course $course)
    {
        $currentuser=auth()->user();
        if($currentuser->hasAnyRole(['Admin', 'Teacher'])&& $currentuser->id==$course->teacher_id) {
            return  response()->json($course);
        }
        else{
            return  response()->json('you cant do this operation');
        }
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param \Illuminate\Http\Request $request
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, Course $course)
    {
        $currentuser=auth()->user();
        if($currentuser->hasAnyRole(['Admin', 'Teacher'])&& $currentuser->id==$course->teacher_id) {
            $course->update(array(
                'name' => request()->name,
                'created_at' => request()->created_at,
                'price' => request()->price * 100,
                'start_date' => request()->start_date,
                'end_date' => request()->end_date,
            ));
            if (request()->hasFile('image')) {
                Storage::delete(request()->course_image);
                $course->image = request()->image->store('image');
            }
            return response()->json($course);
        }
        else{
            return response()->json('unauzorized');
        }
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function destroy(Course $course)
    {
        $currentuser=auth()->user();
        if($currentuser->hasAnyRole(['Admin', 'Teacher'])&& $currentuser->id==$course->teacher_id) {
            if (count($course->students()->get()) > 0) {
                return response()->json('you cant delelte this course');
            } else {
                $course->delete();
            }
        }
        else{
            return response()->json('unauzorized');
        }

    }
    //
}
