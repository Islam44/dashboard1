@extends('admin.teacher.base')

@section('action-content')
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <div class="panel panel-default">
                    <div class="panel-heading">Teacher Details</div>
                    <div class="panel-body">
                        <form class="form-horizontal" role="form" enctype="multipart/form-data">
                            <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
                                <label for="name" class="col-md-4 control-label">Name</label>
                                <div class="col-md-6">
                                    <h4  id="name" type="text" class="form-control" name="name" value="{{ $teacher->name }}" required autofocus>{{ $teacher->name }}</h4>
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('details') ? ' has-error' : '' }}">
                                <label for="details" class="col-md-4 control-label">email</label>

                                <div class="col-md-6">
                                    <h4 id="details" type="text" class="form-control" name="email" value="{{ $teacher->email }}" required>
                                        {{ $teacher->email }}
                                    </h4>
                                </div>
                            </div>
                           
                            <div class="form-group{{ $errors->has('national_id') ? ' has-error' : '' }}">
                                <label for="quantity" class="col-md-4 control-label">National_Id</label>

                                <div class="col-md-6">
                                    <h4 id="national_id" type="text" class="form-control" name="national_id" value="{{ $teacher->national_id }}" required>
                                        {{ $teacher->national_id }}
                                    </h4>
                                </div>
                            </div>
                            <div class="form-group{{ $errors->has('image') ? ' has-error' : '' }}">
                                <label for="image" class="col-md-4 control-label">Image</label>
                            <img src="{{env('APP_URL').'/'.$teacher->image}}" width="150px" height="150px"/>
                            </div>
                            {{-- <div class="form-group">
                                <label for="avatar" class="col-md-4 control-label" >Pictures</label>
                                <div class="col-md-6">
                                    @if(count($teacher->images()->pluck('image')->toArray())==0)
                                        <td><img src="{{env('APP_URL').'/'.$teacher->main_image}}" width="150px" height="150px"/></td>
                                        @endif
                                    @foreach($teacher->images()->pluck('image')->toArray() as $image)
                                    <td><img src="{{env('APP_URL').'/'.$image}}" width="150px" height="150px"/></td>
                                        @endforeach

                                </div>
                            </div> --}}
                            {{-- <div class="form-group">
                                <label for="avatar" class="col-md-4 control-label" >Rates</label>
                                <div class="col-md-6">
                                    <table>
                                        <thead>
                                        <tr>
                                            <th>Email</th>
                                            <th>Stars</th>
                                            <th>Positives </th>
                                            <th>Negatives </th>
                                        </tr>
                                        </thead>
                                        <tbody>
                                        @foreach($rates as $rate)
                                        <tr>
                                            <td>{{\App\User::all()->where('id','=',$rate->buyer_id)->first()->value('email')}}</td>
                                            @if($rate->stars==1)
                                            <td><span class="rating-static rating-10"></span></td>
                                            @elseif($rate->stars==2)
                                                <td><span class="rating-static rating-20"></span></td>
                                            @elseif($rate->stars==3)
                                                <td><span class="rating-static rating-30"></span></td>
                                            @elseif($rate->stars==4)
                                                <td><span class="rating-static rating-40"></span></td>
                                            @elseif($rate->stars==5)
                                                <td><span class="rating-static rating-50"></span></td>
                                            @endif
                                            <td>{{$rate->positives}}</td>
                                            <td>{{$rate->negatives}}</td>

                                        </tr>
                                            @endforeach
                                        </tbody>
                                        <tfoot>
                                        </tfoot>
                                    </table>
                                </div>
                            </div> --}}

                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection