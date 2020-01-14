<?php

namespace App\Http\Controllers\Supporter;

use App\Course;
use App\Http\Controllers\Controller;
use App\Supporter;
use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Spatie\Permission\Models\Role;

class SupportersController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        return view('admin/supporter/index', [
            'supporters' => Supporter::paginate(10)
        ]);
        //return response()->json(Supporter::withoutBanned()->paginate(10));
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $user = new User;
        $user->name = $request->name;
        $user->password = $request->password;
        $user->national_id = $request->national_id;
        $user->image = $request->image->store('images');
        $user->assignRole((Role::where('name', '=', 'Supporter')->first())->id);
        $user->save();
        return response()->json($user);
        // return redirect(route('users.index'));
    }

    /**
     * Display the specified resource.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function show(Supporter $supporter)
    {
        $courses = Course::all();

//        foreach (request()->courses as $id) {
//                $supporter = Course::find($id)->first();
//                $supporter->course_id = $course->id;
//            }
        return view('admin.supporter.show', [
            'supporter' => $supporter,
            'courses' => $courses,
        ]);
    }
    public function assignCoursersToSupporter(Supporter $supporter)
    {
        if (!$supporter->available) {
            $course = json_decode(request()->courses);
            $supporter->course_id = $course->id;
            $supporter->save();
            return response()->json('suucess');
        } else {
            return response()->json('this supporter have course');
        }

    }


    /**
     * Show the form for editing the specified resource.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function edit(Supporter $supporter)
    {
        return view('admin.supporter.edit', [
            'supporter' => $supporter,
        ]);
    }

    /**
     * Update the specified resource in storage.
     *
     * @param \Illuminate\Http\Request $request
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, Supporter $supporter)
    {
        $supporter->name = $request->name;
        $supporter->email = $request->email;
        $supporter->available = $request->available;
        $supporter->national_id = $request->national_id;
        if ($request->hasFile('image')) {
            Storage::delete($supporter->image);
            $supporter->image = $request->image->store('images');
        }
        $supporter->save();

        return view('admin/supporter/index', [
            'supporters' => Supporter::withoutBanned()->paginate(10)
        ]);
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
    public function destroy(Supporter $supporter)
    {
        $supporter->delete();
        return view('admin/supporter/index', [
            'supporters' => Supporter::withoutBanned()->paginate(10)
        ]);
    }
}
