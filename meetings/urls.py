from django.urls import path
from . import views

urlpatterns = [
    path('create/', views.create_meeting, name='create_meeting'),
    path('department/<int:dept_id>/create/', views.create_meeting, name='create_meeting_dept'),
    path('<int:meeting_id>/assign/', views.assign_participants, name='assign_participants'),
    path('<int:meeting_id>/edit/', views.edit_meeting, name='edit_meeting'),
    path('<int:meeting_id>/review/', views.review_meeting, name='review_meeting'),
    path('<int:meeting_id>/finalize/', views.finalize_meeting, name='finalize_meeting'),
    path('authorized-personnel-dashboard/', views.authorized_personnel_dashboard, name='authorized_personnel_dashboard'),
    path('dashboard/', views.officer_dashboard, name='student_dashboard'),  # compatibility alias
    path('officer-dashboard/', views.officer_dashboard, name='officer_dashboard'),
    path('<int:meeting_id>/lock/', views.lock_meeting, name='lock_meeting'),
    path('<int:meeting_id>/qr/', views.projector_qr_view, name='projector_qr_view'),
    path('<int:meeting_id>/sign/', views.sign_meeting, name='sign_meeting'),
]
