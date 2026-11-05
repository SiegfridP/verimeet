from django.urls import path
from . import views

urlpatterns = [
    path('<int:meeting_id>/export/pdf/', views.export_meeting_pdf, name='export_meeting_pdf'),
    path('<int:meeting_id>/history/', views.document_history, name='document_history'),
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
    path('<int:meeting_id>/qr/attendance/', views.generate_attendance_qr, name='generate_attendance_qr'),
    path('<int:meeting_id>/qr/signing/', views.generate_signing_qr, name='generate_signing_qr'),
    path('<int:meeting_id>/qr/sessions/<int:session_id>/', views.view_qr_session, name='view_qr_session'),
    path('<int:meeting_id>/qr/sessions/<int:session_id>/revoke/', views.revoke_qr_session, name='revoke_qr_session'),
    path('<int:meeting_id>/qr/attendance/scan/', views.scan_attendance_qr, name='scan_attendance_qr'),
    path('<int:meeting_id>/sign/', views.sign_meeting, name='sign_meeting'),
    path('<int:meeting_id>/attendance/', views.meeting_attendance, name='meeting_attendance'),
    path('<int:meeting_id>/attendance/<int:attendance_id>/update/', views.update_attendance_status, name='update_attendance_status'),
    path('<int:meeting_id>/attendance/<int:attendance_id>/verify/', views.verify_signature, name='verify_signature'),
    path('<int:meeting_id>/my-attendance/', views.my_attendance, name='my_attendance'),
    # Batch 08 — Individual Signature Verification QR
    path('<int:meeting_id>/qr/my-signature/', views.my_signature_verification_qr, name='my_signature_verification_qr'),
    path('<int:meeting_id>/qr/my-signature/revoke/', views.revoke_my_signature_verification_qr, name='revoke_my_signature_verification_qr'),
    path('verify/', views.verify_individual_signature, name='verify_individual_signature'),
]
