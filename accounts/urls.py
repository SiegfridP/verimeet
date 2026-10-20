from django.urls import path
from django.views.generic import RedirectView
from . import views

urlpatterns = [
    path('route/', views.routing_view, name='routing_view'),
    path('waiting-room/', views.waiting_room, name='waiting_room'),
    path('login/', RedirectView.as_view(pattern_name='account_login', permanent=False), name='login'),
]