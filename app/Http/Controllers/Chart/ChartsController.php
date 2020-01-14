<?php

namespace App\Http\Controllers\Chart;

//use App\Http\Controllers\Controller;
//use App\Student;
//use App\User;
////use Charts;
//use ConsoleTVs\Charts\Facades\Charts;
//use Illuminate\Support\Carbon;
use App\Charts\MoneyChart;
use App\Http\Controllers\Controller;
use App\Student;
use Illuminate\Support\Facades\DB;

class ChartsController extends Controller
{
    public function index()
    {
        $data = DB::table('students')
            ->select(
                DB::raw('gender as gender'),
                DB::raw('count(*) as number'))
            ->groupBy('gender')
            ->get();
        $array [] = ['Gender', 'Number'];
        foreach ($data as $key => $value) {
            $array[++$key] = [$value->gender, $value->number];
        }
        return view('chart/index')->with('gender', json_encode(
            $array));
    }

    public function index1()
    {
        $data = Student::withCount('courses')
            ->orderBy('courses_count', 'desc')
            ->groupBy('id')
            ->take(10)
            ->get()->toArray();
        $array [] = ['name', 'courses_count'];
        foreach ($data as $key => $value) {
            $array[++$key] = [$value['name'], $value['courses_count']];
        }
        return view('chart/index1')->with('courses_count', json_encode(
            $array));
    }


    public function index3()
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
