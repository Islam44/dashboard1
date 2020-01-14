@extends('admin.supporter.base')
@section('action-content')
    <!-- Main content -->
    <section class="content">
      <div class="box">
  <div class="box-header">
    <div class="row">
        <div class="col-sm-8">
          <h3 class="box-title">List of products</h3>
        </div>
    </div>
  </div>
  <!-- /.box-header -->
{{--  <div class="box-body">--}}
{{--      <div class="row">--}}
{{--        <div class="col-sm-6"></div>--}}
{{--        <div class="col-sm-6"></div>--}}
{{--      </div>--}}
{{--      <form method="POST" action="{{ route('admin.products.search') }}">--}}
{{--         {{ csrf_field() }}--}}
{{--         @component('layouts.search', ['title' => 'Search'])--}}
{{--          @component('layouts.two-cols-search-row', ['items' => ['Name','Accept'],--}}
{{--          'oldVals' => [isset($searchingValues) ? $searchingValues['name'] : '', isset($searchingValues) ? $searchingValues['accept'] : '']])--}}
{{--          @endcomponent--}}
{{--        @endcomponent--}}
{{--      </form>--}}
    <div id="example2_wrapper" class="dataTables_wrapper form-inline dt-bootstrap">
      <div class="row">
        <div class="col-sm-12">
          <table id="example2" class="table table-bordered table-hover dataTable" role="grid" aria-describedby="example2_info">
            <thead>
              <tr role="row">
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">name</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">email</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">image</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">national_id</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">available
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Action</th>
              </tr>
            </thead>
            <tbody>
            @foreach ($supporters as $supporter)
                <tr role="row" class="odd">
                    <td class="sorting_1">{{ $supporter->name }}</td>
                    <td class="sorting_1">{{ $supporter->email}}</td>
                    <td><img src="{{env('APP_URL').'/'.$supporter->image}}" width="50px" height="50px"/></td>
                    <td>{{ $supporter->national_id }}</td>
                    <td>{{ $supporter->available}}</td>
                  <td>
                      <a href="/admin/supporters/{{$supporter->id}}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin">
                          Show
                      </a>
                      <a href="/admin/supporters/edit/{{$supporter->id}}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin">
                          Edit
                      </a>
                      <a id="bu" href="/teacher/bansupporter/{{$supporter->id}}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin" onclick="toggle()">
                          BAN
                      </a>
                      <a id="bu1" href="/teacher/unbansupporter/{{$supporter->id}}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin" onclick="toggle1()">
                          UNBAN
                      </a>
                      <form action="/supporter/delete/{{$supporter->id}}" method="post">
                         @csrf
                          @method('DELETE')
                          <button class=" deleteRecord btn btn-danger" type="submit" id="{{$supporter->id}}">Delete</button>
                      </form>
{{--                        <a href="{{ route('admin.products.edit', ['id' => $supporters->id]) }}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin">--}}
{{--                         Update--}}
{{--                        </a>--}}
{{--                        <a  href="{{ route('products.switchF', ['id' => $supporters->id]) }}" class="btn btn-warning col-sm-11 col-xs-6 btn-margin">--}}
{{--                            @csrf--}}
{{--                            @if($supporters->featured==1) Remove From Featured @endif--}}
{{--                            @if($supporters->featured==0) Make As Featured @endif--}}
{{--                        </a>--}}
{{--                      <a  href="{{ route('products.switchA', ['id' => $supporters->id]) }}" class="btn btn-warning col-sm-11 col-xs-6 btn-margin">--}}
{{--                          @csrf--}}
{{--                          @if($supporters->accept==1) Remove From Accept @endif--}}
{{--                          @if($supporters->accept==0) Make As Accept @endif--}}
{{--                      </a>--}}
{{--                      <a>--}}
{{--                          <form method="POST" action="/admin/products/{{$supporters->id}}" >--}}
{{--                              {{ csrf_field() }}--}}
{{--                              {{ method_field('DELETE') }}--}}
{{--                              <div class="form-group">--}}
{{--                                  <input type="submit" class="btn btn-danger col-sm-10 col-xs-10 btn-margin" value="Delete" onclick = "return confirm('Are you sure to delete this user')">--}}
{{--                              </div>--}}
{{--                          </form>--}}
{{--                      </a>--}}
                    </td>

              </tr>
            @endforeach
            </tbody>
          </table>
        </div>
      </div>
      <div class="row">
        <div class="col-sm-5">
          <div class="dataTables_info" id="example2_info" role="status" aria-live="polite">Showing 1 to {{count($supporters)}} of {{count($supporters)}} entries</div>
        </div>
        <div class="col-sm-7">
          <div class="dataTables_paginate paging_simple_numbers" id="example2_paginate">
            {{ $supporters->links() }}
          </div>
        </div>
      </div>
    </div>
  </div>
  <!-- /.box-body -->
    </section>
    <!-- /.content -->
    <script>
        $(".deleteRecord").click(function(event){
            var id = $(this).data("id");
            $.ajax(
                {
                    url:"/supporter/delete/"+id,
                    type: 'DELETE',
                    success: function (){
                        console.log("it Works");
                    }
                });
        });
        // function toggle() {
        //     document.getElementById('bu').style.display='none';
        //     document.getElementById('bu1').style.display='block';
        //
        // }
        // function toggle1() {
        //     document.getElementById('bu1').style.display='none';
        //     document.getElementById('bu').style.display='block';
        //
        // }
    </script>
@endsection
