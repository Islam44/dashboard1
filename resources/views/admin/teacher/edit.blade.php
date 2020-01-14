@extends('admin.teacher.base')

@section('action-content')
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <div class="panel panel-default">
                    <div class="panel-heading">Update Teacher</div>
                    <div class="panel-body">
                    <form class="form-horizontal" role="form" method="POST" action="/teachers/update/{{$teacher->id}}" enctype="multipart/form-data">

                            <input type="hidden" name="_method" value="PUT">
                            <input type="hidden" name="_token" value="{{ csrf_token() }}">
                            <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
                                <label for="name" class="col-md-4 control-label">Name</label>

                                <div class="col-md-6">
                                    <input id="name" type="text" class="form-control" name="name" value="{{ $teacher->name }}" required >

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
                                    <input id="email" type="text" class="form-control" name="email" value="{{ $teacher->email }}" required>

                                    @if ($errors->has('email'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('email') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('national_id') ? ' has-error' : '' }}">
                                <label for="national_id" class="col-md-4 control-label">National_id</label>

                                <div class="col-md-6">
                                    <input id="national_id" type="text" class="form-control" name="national_id" value="{{ $teacher->national_id }}" required>

                                    @if ($errors->has('national_id'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('national_id') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('image') ? ' has-error' : '' }}">
                                <label for="image" class="col-md-4 control-label">Image</label>

                                <div class="col-md-6">
                                    <img id="image" src="{{env('APP_URL').'/'.$teacher->image}}" width="150px" height="150px"/>
                                    <input type="file" id="image" name="image"  />

                                    @if ($errors->has('image'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('image') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div>
                            {{-- <div class="form-group{{ $errors->has('price') ? ' has-error' : '' }}">
                                <label for="quantity" class="col-md-4 control-label">price</label>

                                <div class="col-md-6">
                                    <input id="price" type="text" class="form-control" name="price" value="{{ $teacher->price }}" required>

                                    @if ($errors->has('price'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('price') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div> --}}
                            {{-- <div class="form-group">
                                <label for="avatar" class="col-md-4 control-label" >Picture</label>
                                <div class="col-md-6">
                                    <td><img id="ip" src="{{env('APP_URL').'/'.$teacher->main_image}}" width="50px" height="50px"/></td>
                                    <input type="file" id="main_image" name="main_image" onchange="readURL(this)" />
                                </div>
                            </div> --}}

                            {{-- <div class="form-group{{ $errors->has('categories') ? ' has-error' : '' }}">
                                <label for="categories" class="col-md-4 control-label">
                                    Categories
                                </label>

                                <div class="col-md-6">
                                    <ul style="list-style-type: none; padding-left: 0">
                                        @foreach ($allCategories as $category)
                                            <li><label><input value="{{ $category->id}}" type="checkbox" name="category[]" style="margin-right: 5px;" {{ $categoriesForteacher->contains($category) ? 'checked' : '' }}>{{ $category->name }}</label></li>
                                        @endforeach
                                    </ul>
                                    @if ($errors->has('categories'))
                                        <span class="help-block">
                                        <strong>{{ $errors->first('categories') }}</strong>
                                    </span>
                                    @endif
                                </div>
                            </div> --}}

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
    {{-- <script type="text/javascript">
        function readURL(input) {
            if (input.files && input.files[0]) {
                var reader = new FileReader();
                reader.onload = function (e) {
                    $('#ip')
                        .attr('src', e.target.result);
                };
                reader.readAsDataURL(input.files[0]);
            }
        }
    </script> --}}
@endsection
