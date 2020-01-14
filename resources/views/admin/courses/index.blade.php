@extends('admin.courses.base')
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
  <div class="box-body">
      <div class="row">
        <div class="col-sm-6"></div>
        <div class="col-sm-6"></div>
      </div>
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
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">created_when</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">price</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">start_date</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">end_date</th>
                  @role('admin')
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">teacher_id</th>
                  @else
                      @endrole
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">action</th>


            </thead>
            <tbody>


            @foreach ($courses as $course)
            <tr>
            <td>{{$course->name}}</td>
            <td>{{$course->created_when}}</td>
            <td>{{$course->price}}</td>
            <td>{{$course->start_date}}</td>
            <td>{{$course->end_date}}</td>
                @role('Admin')
            <td>{{$course->teacher_id}}</td>
                @else
                    @endrole
            <td>
              <a href="{{ route('admin.course.show', ['course' => $course->id]) }}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin">
                Show
            </a>
          <a href="/admin/courses/edit/{{$course->id}}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin">
                  Update
                 </a>
                 <form method="POST" action="/admin/courses/delete/{{$course->id}}" >
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
          <div class="dataTables_info" id="example2_info" role="status" aria-live="polite">Showing 1 to {{count($courses)}} of {{count($courses)}} entries</div>
        </div>
        <div class="col-sm-7">
          <div class="dataTables_paginate paging_simple_numbers" id="example2_paginate">
            {{ $courses->links() }}
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
