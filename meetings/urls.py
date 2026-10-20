from django.urls import path
from . import views

urlpatterns = [
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/', views.student_dashboard, name='student_dashboard'),
    path('<int:meeting_id>/lock/', views.lock_meeting, name='lock_meeting'),
    path('<int:meeting_id>/qr/', views.projector_qr_view, name='projector_qr_view'),
    path('<int:meeting_id>/sign/', views.sign_meeting, name='sign_meeting'),
]