@extends('admin.students.base')

@section('action-content')
<div class="container">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default">
                <div class="panel-heading">Student Details</div>
                <div class="panel-body">
                    <form class="form-horizontal" role="form" enctype="multipart/form-data">
                        <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
                            <label for="name" class="col-md-4 control-label">Name</label>
                            <div class="col-md-6">
                                <h4 id="name" type="text" class="form-control" name="name" value="{{ $student->name }}" required autofocus>{{ $student->name }}</h4>
                            </div>
                        </div>
                        <div class="form-group{{ $errors->has('email') ? ' has-error' : '' }}">
                            <label for="email" class="col-md-4 control-label">Email</label>

                            <div class="col-md-6">
                                <h4 id="email" type="text" class="form-control" name="email" value="{{ $student->email }}" required>
                                    {{ $student->email }}
                                </h4>
                            </div>
                        </div>
                        <div class="form-group{{ $errors->has('gender') ? ' has-error' : '' }}">
                            <label for="gender" class="col-md-4 control-label">gender</label>

                            <div class="col-md-6">
                                <h4 id="gender" type="text" class="form-control" name="gender" value="{{ $student->gender }}" required>
                                    {{ $student->gender }}
                                </h4>
                            </div>
                        </div>
                        <div class="form-group{{ $errors->has('dob') ? ' has-error' : '' }}">
                            <label for="dob" class="col-md-4 control-label">dob</label>

                            <div class="col-md-6">
                                <h4 id="dob" type="text" class="form-control" name="dob" value="{{ $student->dob }}" required>
                                    {{ $student->dob }}
                                </h4>

                            </div>
                        </div>
                        <div class="form-group">
                            <label for="avatar" class="col-md-4 control-label">Image</label>
                            <div class="col-md-6">
                            <td><img src="{{env('APP_URL').'/'.$student->image}}" width="150px" height="150px" /></td>
                            </div>
                        </div>


                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection