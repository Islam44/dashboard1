@extends('admin.students.base')
@section('action-content')
    <!-- Main content -->
    <section class="content">
      <div class="box">
  <div class="box-header">
    <div class="row">
        <div class="col-sm-8">
          <h3 class="box-title">List of Students</h3>
        </div>
    </div>
  </div>
  <!-- /.box-header -->
  <div class="box-body">
      <div class="row">
        <div class="col-sm-6"></div>
        <div class="col-sm-6"></div>
      </div>
      <form method="POST" action="#">
         {{ csrf_field() }}
         @component('layouts.search', ['title' => 'Search'])
          @component('layouts.two-cols-search-row', ['items' => ['Name','Accept'],
          'oldVals' => [isset($searchingValues) ? $searchingValues['name'] : '', isset($searchingValues) ? $searchingValues['accept'] : '']])
          @endcomponent
        @endcomponent
      </form>
    <div id="example2_wrapper" class="dataTables_wrapper form-inline dt-bootstrap">
      <div class="row">
        <div class="col-sm-12">
          <table id="example2" class="table table-bordered table-hover dataTable" role="grid" aria-describedby="example2_info">
            <thead>
              <tr role="row">
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Id</th>
                <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Name</th>
                <th width="20%" class="sorting" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Email: activate to sort column ascending">Email</th>
                  <th width="20%" class="sorting" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Email: activate to sort column ascending">Gender</th>
                  <th class="hidden-xs" width="10%" rowspan="1" colspan="1">Dob</th>
                  <th class="hidden-xs" width="10%" rowspan="1" colspan="1">created_at</th>
                  <th width="8%" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Picture: activate to sort column descending" aria-sort="ascending">Image</th>
                <th width="15%" tabindex="0" aria-controls="example2" rowspan="3" colspan="1" aria-label="Action: activate to sort column ascending">Action</th>
              </tr>
            </thead>
            <tbody>
            @foreach ($students as $student)
                <tr role="row" class="odd">
                    <td class="sorting_1">{{ $student->id}}</td>
                  <td class="sorting_1">{{ $student->name }}</td>
                    <td>{{ $student->email }}</td>
                    <td>{{ $student->gender}}</td>
                    <td>{{$student->dob}}</td>
                    <td>{{$student->created_at}}</td>
                    <td><img src="{{env('APP_URL').'/'.$student->main_image}}" width="50px" height="50px"/></td>
                  <td>
                      <a href="{{ route('admin.students.show', ['student' => $student->id]) }}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin">
                          Show
                      </a>
                        <a href="/admin/students/edit/{{$student->id}}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin">
                         Update
                        </a>
                          <form method="POST" action="/admin/student/delete/{{$student->id}}" >
                              {{ csrf_field() }}
                              {{ method_field('DELETE') }}
                                  <input type="submit" class="btn btn-danger col-sm-10 col-xs-10 btn-margin" value="Delete" onclick = "return confirm('Are you sure to delete this user')">
                          </form>
                    </td>

              </tr>
            @endforeach
            </tbody>
          </table>
        </div>
      </div>
      <div class="row">
        <div class="col-sm-5">
          <div class="dataTables_info" id="example2_info" role="status" aria-live="polite">Showing 1 to {{count($students)}} of {{count($students)}} entries</div>
        </div>
        <div class="col-sm-7">
          <div class="dataTables_paginate paging_simple_numbers" id="example2_paginate">
            {{ $students->links() }}
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

