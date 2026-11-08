from django.urls import path
from django.views.generic import RedirectView
from . import views

urlpatterns = [
    path('settings/', views.account_settings, name='account_settings'),
    path('onboarding/', views.onboarding, name='onboarding'),
    path('signature/preview/', views.signature_preview, name='signature_preview'),
    path('department/create/', views.create_department, name='create_department'),
    path('department/<int:dept_id>/delete/', views.delete_department, name='delete_department'),
    path('route/', views.routing_view, name='routing_view'),
    path('dashboard/', views.central_dashboard, name='central_dashboard'),
    path('waiting-room/', views.waiting_room, name='waiting_room'),
    path('login/', RedirectView.as_view(pattern_name='account_login', permanent=False), name='login'),
    # RBAC dashboards
    path('admin/', views.admin_dashboard, name='admin_dashboard'),
    path('department/<int:dept_id>/', views.department_dashboard, name='department_dashboard'),
    path('invitation/<int:invitation_id>/retry/', views.retry_invitation_delivery, name='retry_invitation_delivery'),
    # Invitations
    path('department/<int:dept_id>/invite/', views.invite_member, name='invite_member'),
    path('invitation/accept/<str:token>/', views.accept_invitation, name='accept_invitation'),
    # Role elevation requests
    path('department/<int:dept_id>/request-elevation/', views.request_authorized_personnel, name='request_authorized_personnel'),
    path('elevation-requests/', views.review_elevation_requests, name='review_elevation_requests'),
]
