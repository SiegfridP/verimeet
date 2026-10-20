from django.urls import path
from . import views

urlpatterns = [
    path('route/', views.routing_view, name='routing_view'),
    path('waiting-room/', views.waiting_room, name='waiting_room'),
]