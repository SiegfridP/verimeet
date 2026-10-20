from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

@login_required
def routing_view(request):
    """Routes users based on their Department assignment after logging in."""
    if not request.user.department:
        return redirect('waiting_room')
    
    if request.user.is_admin:
        return redirect('admin_dashboard') # URL defined in meetings app
    return redirect('student_dashboard')   # URL defined in meetings app

@login_required
def waiting_room(request):
    """The default page for users without an assigned department."""
    if request.user.department:
        return redirect('routing_view')
    return render(request, 'accounts/waiting_room.html')