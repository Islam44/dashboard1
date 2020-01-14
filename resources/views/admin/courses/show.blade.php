@extends('admin.courses.base')

@section('action-content')
<div class="container">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default">
                <div class="panel-heading">course Details</div>
                <div class="panel-body">
                    <form class="form-horizontal" role="form" enctype="multipart/form-data">
                        <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
                            <label for="name" class="col-md-4 control-label">Name</label>
                            <div class="col-md-6">
                                <h4 id="name" type="text" class="form-control" name="name" value="{{ $course->name }}" required autofocus>{{ $course->name }}</h4>
                            </div>
                        </div>
                        <div class="form-group{{ $errors->has('created_when') ? ' has-error' : '' }}">
                            <label for="created_when" class="col-md-4 control-label">created_when</label>

                            <div class="col-md-6">
                                <h4 id="created_when" type="text" class="form-control" name="created_when" value="{{ $course->created_when }}" required>
                                    {{ $course->created_when }}
                                </h4>
                            </div>
                        </div>
                        <div class="form-group{{ $errors->has('price') ? ' has-error' : '' }}">
                            <label for="price" class="col-md-4 control-label">price</label>

                            <div class="col-md-6">
                                <h4 id="price" type="text" class="form-control" name="price" value="{{ $course->price }}" required>
                                    {{ $course->price }}
                                </h4>
                            </div>
                        </div>
                        <div class="form-group{{ $errors->has('start_date') ? ' has-error' : '' }}">
                            <label for="start_date" class="col-md-4 control-label">start_date</label>

                            <div class="col-md-6">
                                <h4 id="start_date" type="text" class="form-control" name="start_date" value="{{ $course->start_date }}" required>
                                    {{ $course->start_date }}
                                </h4>

                            </div>
                        </div>
                        <div class="form-group{{ $errors->has('end_date') ? ' has-error' : '' }}">
                            <label for="end_date" class="col-md-4 control-label">end_date</label>

                            <div class="col-md-6">
                                <h4 id="end_date" type="text" class="form-control" name="end_date" value="{{ $course->end_date }}" required>
                                    {{ $course->end_date }}
                                </h4>

                            </div>
                        </div>
                        <div class="form-group{{ $errors->has('teacher_id') ? ' has-error' : '' }}">
                            <label for="teacher_id" class="col-md-4 control-label">teacher_id</label>

                            <div class="col-md-6">
                                <h4 id="teacher_id" type="text" class="form-control" name="teacher_id" value="{{ $course->teacher_id }}" required>
                                    {{ $course->teacher_id }}
                                </h4>

                            </div>
                        </div>
                        <div class="form-group{{ $errors->has('buyers_count') ? ' has-error' : '' }}">
                            <label for="buyers_count" class="col-md-4 control-label">buyers_count</label>

                            <div class="col-md-6">
                                <h4 id="buyers_count" type="text" class="form-control" name="buyers_count" value="{{ $course->buyers_count }}" required>
                                    {{ $course->buyers_count }}
                                </h4>

                            </div>
                        </div>



                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection