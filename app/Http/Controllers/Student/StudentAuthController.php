<?php

namespace App\Http\Controllers\Student;

use App\Comment;
use App\Course;
use App\Http\Controllers\Controller;
use App\Http\Requests\RegistrationFormRequest;
use App\Jobs\SendEmailVerify;
use App\Jobs\SendEmailVerifyChange;
use App\Jobs\SendVerificationEmail;
use App\Mail\UserCreated;
use App\Notifications\enroll;
use App\Student;
use Carbon\Carbon;
use http\QueryString;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class StudentAuthController extends Controller
{

    public function __construct()
    {
       // Config::set('auth.providers.users.model', Student::class);
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     * @throws \Illuminate\Validation\ValidationException
     */
    public function logout(Request $request)
    {
            $this->lastLogin();
            $this->guard()->logout();
            return response()->json(['message' => 'Successfully logged out']);
    }

    public function register(Request $request)
    {
        $user = new Student();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->gender = 'male';
        $user->dob = '2020-07-12';
        $user->image = 'islam.jpg';
        $user->verification_token = base64_encode($request->email);
        $user->save();
        dispatch(new SendEmailVerify($user));
        return response()->json('success');
    }

    public function update(Request $request, Student $user)
    {
        if ($this->guard()->user()->id != $user->id) {
            return response()->json('not same user');
        }
        else {

//        $rules = [
//            'email' => 'email|unique:users,email,' . $user->id,
//            'password' => 'min:6|confirmed',
//        ];
            if ($request->has('name')) {
                $user->name = $request->name;
            }
            if ($request->has('gender')) {
                $user->gender = $request->gender;
            }
            if ($request->has('dob')) {
                $user->dob = $request->dob;
            }
            if ($request->has('password')) {
                $user->password = bcrypt($request->password);
            }
            if ($request->has('image')) {
                $user->image = $request->image;
            }
            if ($request->has('email') && $user->email != $request->email) {

                $user->verified = false;
                $user->verification_token = base64_encode($request->email);
                $user->email = $request->email;
                $user->save();
                dispatch(new SendEmailVerify($user));
            }
            $user->save();
            return response()->json('data changes success');
        }


    }

    public function verify($token)
    {
        $user = Student::where('verification_token', $token)->firstOrFail();
        $user->verified = true;
        $user->verification_token = null;
        $user->save();
        //redirect('/home');
        return response()->json('The account has been verified succesfully');

    }

    public function login(Request $request)
    {
        $input = $request->only('email', 'password');
        if ($token = $this->guard()->attempt($input)) {
            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => $this->guard()->factory()->getTTL() * 60
            ]);
        }
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    public function me()
    {
        $user = $this->guard()->user();
        return response()->json(['status' => 'success', 'user' => $user]);
    }

    public function enroll(Course $course)
    {
        $student = $this->guard()->user();
        $student->courses()->attach([$course->id]);
        $student->notify(new enroll($student, $course));
    }

    public function comment(Request $request, Course $course)
    {
        $rules =
            [
                'body' => 'required|min:1|max:50'
            ];
        $validator = Validator::make($request->all(), $rules);
        if ($validator->fails()) {
            return response()->json(["error" => $validator->messages()]);
        }
        $data = $request->all();
        $data['body'] = $request->body;
        $data['student_id'] = $this->guard()->user()->id;
        $data['course_id'] = $course->id;
        $comment = Comment::create($data);
        return response()->json([
            "comment" => $comment,
            "code" => 200
        ], 200);
    }

    public function courses()
    {
        return response()->json(['data' =>
            $this->guard()->user()->courses()->with('teacher')
                ->with(['comments' => function ($query) {
                        $query->where('status', '=', 1);
                    }]
                )->get()
        ]);
    }
    function lastLogin()
    {
        $this->guard()->user()->update([
            'last_login_at' => Carbon::now()->toDateTimeString(),
            'last_login_ip' =>\Request::ip()
        ]);
    }
    public function guard()
    {
        return  Auth::guard('api');
    }
}
