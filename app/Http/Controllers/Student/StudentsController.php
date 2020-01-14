<?php

namespace App\Http\Controllers\Student;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreStudentRequest;
use app\http\Requests\StudentRequest;
use App\Student;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class StudentsController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $students = Student::paginate(5);
       // return response()->json($students);
        return view('admin.students.index',[
            'students'=> $students
        ]);
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
    public function store(StoreStudentRequest $request)
    {
        $student = Student::create([
            'name' => $request->name,
            'gender' => $request->gender,
            'email' => $request->email,
            'password' => $request->password,
            'dob' => $request->dob,
            'image' => $request->image->store('images')
        ]);
        return response()->json($student);

    }

    /**
     * Display the specified resource.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function show(Student $student)
    {
        //return response()->json($student);
        return view('admin.students.show',[
            'student'=> $student
        ]);
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function edit(Student $student)
    {
        return view('admin.students.edit',[
            'student'=> $student
        ]);
    }

    /**
     * Update the specified resource in storage.
     *
     * @param \Illuminate\Http\Request $request
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, Student $studentobj)
    {
        $studentobj->name = $request->name;
        $studentobj->gender = $request->gender;
        $studentobj->email = $request->email;
        $studentobj->dob = $request->dob;
        if ($request->hasFile('image')) {
            Storage::delete($studentobj->image);
            $studentobj->image = $request->image->store('images');
        }
//        if ($studentobj->isClean()) {
//            return response()->json('You need to specify a different value to update', 422);
//        }
        $studentobj->save();
       // return response()->json($studentobj);
        return view('admin.students.edit',[
            'student'=> $studentobj
        ]);
    }

    public function destroy(Student $student)
    {
        $student->delete();
        //return response()->json($student);
      return redirect('/admin/students');
    }
}
