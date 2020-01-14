@extends('admin.courses.base')
@section('action-content')
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <div class="panel panel-default">
                    <div class="panel-heading">Update course</div>
                    <div class="panel-body">
                        <form class="form-horizontal" role="form" method="POST" action="/courses/update/{{$course->id}}" enctype="multipart/form-data">
                            <input type="hidden" name="_method" value="PUT">
                            <input type="hidden" name="_token" value="{{ csrf_token() }}">
                            <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
                                <label for="name" class="col-md-4 control-label">Name</label>

                                <div class="col-md-6">
                                    <input id="name" type="text" class="form-control" name="name" value="{{ $course->name }}" required autofocus>

                                    @if ($errors->has('name'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('name') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('price') ? ' has-error' : '' }}">
                                <label for="price" class="col-md-4 control-label">Price</label>

                                <div class="col-md-6">
                                    <input id="price" type="price" class="form-control" name="price" value="{{ $course->price }}" required>

                                    @if ($errors->has('price'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('price') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div>
{{--                            <div class="form-group{{ $errors->has('teacher_id') ? ' has-error' : '' }}">--}}
{{--                                <label for="teacher_id" class="col-md-4 control-label">Teacher</label>--}}

{{--                                <div class="col-md-6">--}}
{{--                                    <input id="teacher_id" type="text" class="form-control" name="teacher_id" value="{{ $course->teacher_id }}" required>--}}

{{--                                    @if ($errors->has('teacher_id'))--}}
{{--                                        <span class="help-block">--}}
{{--                                        <strong>{{ $errors->first('teacher_id') }}</strong>--}}
{{--                                    </span>--}}
{{--                                    @endif--}}
{{--                                </div>--}}
                            </div>


                            <div class="form-group">
                                <label for="avatar" class="col-md-4 control-label" >Image</label>
                                <div class="col-md-6">
                                    <td><img id="image" src="{{env('APP_URL').'/'.$course->image}}" width="150px" height="150px"/></td>
                                    <input type="file" id="image" name="image"  />
                                </div>
                            </div>


                            <div class="form-group">
                                <div class="col-md-6 col-md-offset-4">
                                    <button type="submit" class="btn btn-primary">
                                        Update
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection
