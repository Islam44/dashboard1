@extends('admin.comment.base')
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
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Body</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Course</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Student</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Support</th>
                  <th width="10%" class="sorting_asc" tabindex="0" aria-controls="example2" rowspan="1" colspan="1" aria-label="Name: activate to sort column descending" aria-sort="ascending">Action</th>
            </thead>
            <tbody>
            @foreach ($comments as $comment)
                <tr role="row" class="odd">
                  <td class="sorting_1">{{ $comment->body}}</td>
                    <td>{{ $comment->course->name }}</td>
                    <td>{{ (\App\Student::find($comment->student_id))['name']}}</td>
                    <td>{{ (\App\Supporter::find($comment->supporter_id))['name']}}</td>
                  <td>
                      <a href="/approve/{{$comment->id}}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin">
                          Approve
                      </a>
                      <a href="/disapprove/{{$comment->id}}" class="btn btn-warning col-sm-8 col-xs-5 btn-margin">
                          DisApprove
                      </a>
                    </td>
              </tr>
            @endforeach
            </tbody>
            <tfoot>
              <tr>
              </tr>
            </tfoot>
          </table>
        </div>
      </div>
      <div class="row">
        <div class="col-sm-5">
          <div class="dataTables_info" id="example2_info" role="status" aria-live="polite">Showing 1 to {{count($comments)}} of {{count($comments)}} entries</div>
        </div>
        <div class="col-sm-7">
          <div class="dataTables_paginate paging_simple_numbers" id="example2_paginate">
            {{ $comments->links() }}
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
