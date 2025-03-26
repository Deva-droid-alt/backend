from django.urls import path

from . import views

urlpatterns = [
    path('admincreate', views.admin_creation,name='admincreate'),
    path('login/', views.login),
    # path('employee/get-manager/', views.get),
    path('admin/manageemployee/list', views.list_employee),
    path('employee/manager/', views.get_manager_for_employee, name='employee-manager'),
    # path('adminlist', views.list_req_for_admin),
    path('manager-view/requests/', views.manager_view_requests),
    path('employee/request/<int:request_id>', views.employee_view_req),
    path('view-requests', views.get_travel_requests,name='view-requests'),
    path('employee/request/<int:request_id>/updatenote', views.requestupdate_from_employees),
    path('employee/request/<int:request_id>/delete', views.delete_requests_by_employees), 
    path('edit-travel-request/<int:request_id>/', views.edit_rq_by_employee, name='edit_rq_by_employee'),  
    path('manager/request/<int:request_id>', views.manager_update_reqs),
    path('manager/request/<int:request_id>/addnote', views.addnote_mngr),
    # path('admin/request/<int:request_id>', views.view_requests_by_admin),
    path('admin/request/<int:request_id>/addnote', views.addnote_admin),
    path('employee_management', views.employee_management),
    path('manager_management', views.manager_management),  
    path('employee/travel_requests_new', views.travel_requests_new),
    path('filter-requests/',views.filter_travel_requestsby_employee, name='filter_travel_requests'),
    path('travel-requests-manager/',views.filter_travel_requests_by_manager, name='filter_travel_requests'),
    path('filter-travel-requests-admin/',views.filter_travel_requests_admin, name='filter-travel-requests-admin'),
    # path('view-requests/manager', views.mgr_viewTravelRequests, name='manager-travel-requests'),
    path('get-employee-name', views.get_employee_name_id, name='employee-name-id'),
    # path('filter-rq/', views.flter_get_requests, name='filter-rq'),
    path('update-status/<int:request_id>',views.update_rq_status, name='update-status'),
    path('flterview-req/',views.filter_req, name='flterview-req'),
    path('travel-requests/<int:request_id>/resubmit', views.resubmit_request, name='resubmit-travel-request'),
    path('requests/<int:request_id>/close', views.close_request, name='resubmit-travel-request'),
    path('update-request/<int:request_id>/', views.update_rq_resubmission, name='update_request'),
    path('full-reqs',views.travel_Req_admin, name='full-reqs')


]