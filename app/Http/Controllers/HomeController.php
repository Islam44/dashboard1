<?php

namespace App\Http\Controllers;

use App\Student;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class HomeController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    protected $user;

    public function __construct()
    {
        $this->middleware('auth');
        $this->middleware(function ($request, $next) {
            $this->user = Auth::user();
            return $next($request);
        });
    }

    /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable
     */
    public function index()
    {
        return view('home');
    }



//    public function pie2()
//    {
//        $data2 = Student::withCount('courses')
//            ->orderBy('courses_count', 'desc')
//            ->groupBy('id')
//            ->take(10)
//            ->get()->toArray();
//        $array2 [] = ['name', 'courses_count'];
//        foreach ($data2 as $key => $value) {
//            $array2[++$key] = [$value['name'], $value['courses_count']];
//        }
//        return view('chart/index1')->with('courses_count', json_encode(
//            $array2));
//    }


    public function line()
    {
        $data = DB::table('courses')->
        join('student_course', 'student_course.course_id', '=', 'courses.id')
            ->whereBetween('created_at', [now(), now()->addMonths(12 - ((int)(Carbon::now())->month))])
            ->orderBy('created_at')
            ->get()
            ->groupBy(function ($val) {
                return Carbon::parse($val->created_at)->format('m');
            })->map(function ($row) {
                return $row->sum('price');
            }
            );

        return view('chart/index3')->with('money', json_encode(
            $data));

    }
}
