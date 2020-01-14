@extends('admin.supporter.base')

@section('action-content')
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <div class="panel panel-default">
                    <div class="panel-heading">Update student</div>
                    <div class="panel-body">
                        <form class="form-horizontal" role="form" method="POST"
                              action="/supporter/update/{{$supporter->id}}" enctype="multipart/form-data">
                            <input type="hidden" name="_method" value="PUT">
                            <input type="hidden" name="_token" value="{{ csrf_token() }}">
                            <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
                                <label for="name" class="col-md-4 control-label">Name</label>

                                <div class="col-md-6">
                                    <input id="name" type="text" class="form-control" name="name"
                                           value="{{ $supporter->name }}" required autofocus>

                                    @if ($errors->has('name'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('name') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('email') ? ' has-error' : '' }}">
                                <label for="email" class="col-md-4 control-label">Email</label>

                                <div class="col-md-6">
                                    <input id="email" type="email" class="form-control" name="email"
                                           value="{{ $supporter->email }}" required>

                                    @if ($errors->has('email'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('email') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('national_id') ? ' has-error' : '' }}">
                                <label for="national_id" class="col-md-4 control-label">national_id</label>

                                <div class="col-md-6">
                                    <input id="national_id" type="text" class="form-control" name="national_id"
                                           value="{{ $supporter->national_id }}" required>

                                    @if ($errors->has('national_id'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('national_id') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('available') ? ' has-error' : '' }}">
                                <label for="available" class="col-md-4 control-label">available</label>

                                <div class="col-md-6">
                                    <input id="available" type="text" class="form-control" name="available"
                                           value="{{ $supporter->available }}" required>

                                    @if ($errors->has('available'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('available') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div>

                            <div class="form-group">
                                <label for="avatar" class="col-md-4 control-label">Image</label>
                                <div class="col-md-6">
                                    <td><img id="image" src="{{env('APP_URL').'/'.$supporter->image}}" width="150px"
                                             height="150px"/></td>
                                    <input type="file" id="image" name="image"/>
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
