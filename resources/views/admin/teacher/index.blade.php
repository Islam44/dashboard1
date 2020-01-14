@extends('admin.teacher.base')
@section('action-content')
    <!-- Main content -->
    <section class="content">
      <div class="box">
  <div class="box-header">
    <div class="row">
        <div class="col-sm-8">
          <h3 class="box-title">List of teachers</h3>
        </div>
    </div>
  </div>
  <!-- /.box-header -->
  <div class="box-body">
      <div class="row">
        <div class="col-sm-6"></div>
        <div class="col-sm-6"></div>
      </div>
      {{-- <form method="POST" action="{{ route('admin.teachers.search') }}">
         {{ csrf_field() }}
         @component('layouts.search', ['title' => 'Search'])
          @component('layouts.two-cols-search-row', ['items' => ['Name','Accept'],
          'oldVals' => [isset($searchingValues) ? $searchingValues['name'] : '', isset($searchingValues) ? $searchingValues['accept'] : '']])
          @endcomponent
        @endcomponent
      </form> --}}
    <div id="example2_wrapper" class="dataTables_wrapper form-inline dt-bootstrap">
      <div class="row">
        <div class="col-sm-12">
          <table id="example2" class="table table-bordered table-hover dataTable" role="grid" aria-describedby="example2_info">
            <thead>
              <tr role="row">
                <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Name</th>
                <th width="20%" class="sorting" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Email: activate to sort column ascending">email</th>
                  <th width="20%" class="sorting" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Email: activate to sort column ascending">image</th>
                  <th width="20%" class="hidden-xs" width="10%" rowspan="1" colspan="1">national_id</th>
                  <th width="20%">action</th>
                  </tr>
            </thead>


            <tbody>
            @foreach ($teachers as $teacher)
                <tr role="row" class="odd">
                  <td class="sorting_1">{{ $teacher->name }}</td>
                    <td>{{ $teacher->email }}</td>
                    <td><img src="{{env('APP_URL').'/'.$teacher->main_image}}" width="50px" height="50px"/></td>
                    <td>{{$teacher->national_id}}</td>
                <td><a class="btn btn-primary" href="/teachers/show/{{$teacher->id}}">show</a>
                <a class="btn btn-success" href="/teachers/edit/{{$teacher->id}}">edit</a>
                {{-- <a class="btn btn-danger" href="/teacher/delete/{{$teacher->id}}">delete</a> --}}

                <form action="/teacher/delete/{{$teacher->id}}" method="POST">
                  @csrf
                  @method('DELETE')
                    <input type="submit" class="btn btn-danger col-sm-10 col-xs-10 btn-margin" value="Delete" onclick = "return confirm('Are you sure to delete this user')">
              </form>
                    </td>


              </tr>
            @endforeach
            </tbody>


            {{-- <tfoot>
              <tr>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Seller</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Name</th>
                  <th width="20%" class="sorting" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Email: activate to sort column ascending">Description</th>
                  <th width="20%" class="sorting" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Email: activate to sort column ascending">Details</th>
                  <th class="hidden-xs" width="10%" rowspan="1" colspan="1">Price</th>
                  <th class="hidden-xs" width="10%" rowspan="1" colspan="1">Featured</th>
                  <th class="hidden-xs" width="10%" rowspan="1" colspan="1">Quantity</th>
                  <th class="hidden-xs" width="10%" rowspan="1" colspan="1">Image</th>
              </tr>
            </tfoot> --}}
          </table>
        </div>
      </div>
      <div class="row">
        <div class="col-sm-5">
          <div class="dataTables_info" id="example2_info" role="status" aria-live="polite">
          Showing 1 to {{count($teachers)}} of {{count($teachers)}} entries
            </div>

        </div>
        <div class="col-sm-7">
          <div class="dataTables_paginate paging_simple_numbers" id="example2_paginate">

          </div>
        </div>
      </div>
    </div>
  </div>
  <!-- /.box-body -->
</div>
    </section>
    <!-- /.content -->
  </div>
    <script>
    </script>
@endsection
