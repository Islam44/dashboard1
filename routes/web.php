<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});
Route::get('/home', function () {
    return view('home');
})->name('home');

Auth::routes();

Route::get('/chart/index', 'Chart\ChartsController@index');
Route::get('/chart/index1', 'Chart\ChartsController@index1');
Route::get('/chart/index3', 'Chart\ChartsController@index3');

Route::get('/admin/courses', 'Course\CourseController@index');
Route::get('/admin/courses/{course}', 'Course\CourseController@show')->name('admin.course.show');
Route::get('/admin/courses/edit/{course}', 'Course\CourseController@edit');
Route::put('/admin/courses/update/{course}', 'Course\CourseController@update');
Route::delete('/admin/courses/delete/{course}', 'Course\CourseController@destroy');


Route::put('course/support/{course}', 'Course\CourseSupporterController@update');

Route::get('/admin/students', 'Student\StudentsController@index');
Route::get('/admin/students/create', 'Student\StudentsController@create');
Route::get('/admin/students/edit/{student}', 'Student\StudentsController@edit');
Route::post('/admin/students', 'Student\StudentsController@store');
Route::get('/admin/students/{student}', 'Student\StudentsController@show')->name('admin.students.show');
Route::put('/admin/student/update/{studentobj}', 'Student\StudentsController@update');
Route::delete('/admin/student/delete/{student}', 'Student\StudentsController@destroy');

Route::get('/admin/supporters/index', 'Supporter\SupportersController@index');
Route::get('/admin/supporters/create', 'Supporter\SupportersController@create');
Route::get('/admin/supporters/edit/{supporter}', 'Supporter\SupportersController@edit');
Route::post('supporters', 'Supporter\SupportersController@store');
Route::get('/admin/supporters/{supporter}', 'Supporter\SupportersController@show');
Route::put('supporter/update/{supporter}', 'Supporter\SupportersController@update');
Route::delete('supporter/delete/{supporter}', 'Supporter\SupportersController@destroy');
Route::get('supporter/addtosupporter/{supporter}', 'Supporter\SupportersController@assignCoursersToSupporter');

Route::get('teacher/mycourses', 'Teacher\TeacherCourseController@index');
Route::get('teacher/mycourses/{course}', 'Teacher\TeacherCourseController@show');
Route::post('teacher/addcourse', 'Teacher\TeacherCourseController@store');
Route::delete('teacher/deletecourse/{course}', 'Teacher\TeacherCourseController@destroy');
Route::put('teacher/updatecourse/{course}', 'Teacher\TeacherCourseController@update');

Route::get('teacher/mysupporter', 'Teacher\TeacherSupporterController@index');
Route::post('teacher/addsupporter', 'Teacher\TeacherSupporterController@store');
Route::delete('teacher/deletesupporter/{supporter}', 'Teacher\TeacherSupporterController@destroy');
Route::get('teacher/bansupporter/{supporter}', 'Teacher\TeacherSupporterController@ban');
Route::get('teacher/unbansupporter/{supporter}', 'Teacher\TeacherSupporterController@unban');


Route::get('/admin/teachers', 'Teacher\TeachersController@index');
Route::get('/admin/teachers/create', 'Teacher\TeachersController@create');
Route::get('teachers/edit/{teacher}', 'Teacher\TeachersController@edit');
Route::post('/admin/teachers', 'Teacher\TeachersController@store');
Route::get('teachers/show/{teacher}', 'Teacher\TeachersController@show');
Route::put('/admin/teacher/update/{teacherobj}', 'Teacher\TeachersController@update');
Route::delete('teacher/delete/{teacher}', 'Teacher\TeachersController@destroy');

Route::get('admin/comment/index', 'Comment\CommentsController@index');
Route::get('approve/{comment}', 'Comment\CommentSupporterController@approveComment');
Route::get('disapprove/{comment}', 'Comment\CommentSupporterController@disapproveComment');
