@extends('admin.supporter.base')

@section('action-content')
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <div class="panel panel-default">
                    <div class="panel-heading">Product Details</div>
                    <div class="panel-body">
                            <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
                                <label for="name" class="col-md-4 control-label">Name</label>
                                <div class="col-md-6">
                                    <h4  id="name" type="text" class="form-control" name="name" value="{{ $supporter->name }}" >{{ $supporter->name }}</h4>
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('email') ? ' has-error' : '' }}">
                                <label for="details" class="col-md-4 control-label">Description</label>

                                <div class="col-md-6">
                                    <h4 id="details" type="text" class="form-control" name="details" value="{{ $supporter->email }}">
                                        {{ $supporter->email }}
                                    </h4>
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('national_id') ? ' has-error' : '' }}">
                                <label for="description" class="col-md-4 control-label">national_id</label>

                                <div class="col-md-6">
                                    <h4  rows="4" cols="50" id="description" type="text" class="form-control" name="national_id" value="{{ $supporter->national_id }}">
                                        {{ $supporter->national_id }}
                                    </h4>
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('available') ? ' has-error' : '' }}">
                                <label for="available" class="col-md-4 control-label">available</label>

                                <div class="col-md-6">
                                    <h4 id="quantity" type="text" class="form-control" name="quantity" value="{{ $supporter->available }}">
                                        {{ $supporter->available }}
                                    </h4>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="avatar" class="col-md-4 control-label" >Image</label>
                                <div class="col-md-6">
                                        <td><img src="{{env('APP_URL').'/'.$supporter->image}}" width="150px" height="150px"/></td>
                                </div>
                            </div>
                            <form method="get" action="/supporter/addtosupporter/{{$supporter->id}}">
                                @csrf
                                <div class="form-group">
                                    <label for="avatar" class="col-md-4 control-label" >Courses</label>
                                    <div class="col-md-6">
                                        @foreach ($courses as $course)
                                            <input type="radio" name="courses" value="{{$course}}">{{$course->name}}<br>
                                        @endforeach
                                            <input type="submit" class="btn btn-primary" name="submit"/><br>
                                    </div>
                                </div>
                            </form>

                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection
