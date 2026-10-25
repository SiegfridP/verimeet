from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponseForbidden, HttpResponseBadRequest
from .models import Department, Membership, Invitation, RoleElevationRequest, User
from django import forms
from django.utils import timezone

# Helper decorators

def is_global_admin(user):
    return user.is_authenticated and (getattr(user, 'is_admin', False) or user.is_superuser)

def has_membership(user, department, role=None):
    try:
        membership = Membership.objects.get(user=user, department=department)
        if role:
            return membership.role == role
        return True
    except Membership.DoesNotExist:
        return False

# ---------- Dashboard Views ----------
@login_required
@user_passes_test(is_global_admin)
def admin_dashboard(request):
    departments = Department.objects.filter(is_active=True)
    pending_requests = RoleElevationRequest.objects.filter(status='P')
    return render(request, 'accounts/admin_dashboard.html', {
        'departments': departments,
        'pending_requests': pending_requests,
    })

@login_required
def department_dashboard(request, dept_id=None):
    # Determine department context
    if dept_id:
        department = get_object_or_404(Department, pk=dept_id, is_active=True)
    else:
        # pick first membership if only one, otherwise require explicit dept_id
        memberships = Membership.objects.filter(user=request.user)
        if memberships.count() == 1:
            department = memberships.first().department
        else:
            return HttpResponseBadRequest('Department ID required')

    # Resolve membership and role
    try:
        membership = Membership.objects.get(user=request.user, department=department)
    except Membership.DoesNotExist:
        return HttpResponseForbidden('No membership in this department')

    if membership.role == 'AP':
        template = 'accounts/authorized_dashboard.html'
    else:
        template = 'accounts/member_dashboard.html'

    return render(request, template, {'department': department, 'membership': membership})

# ---------- Invitation Views ----------
class InvitationForm(forms.Form):
    email = forms.EmailField(label='Invitee Email')

@login_required
def invite_member(request, dept_id):
    department = get_object_or_404(Department, pk=dept_id, is_active=True)
    # Only Authorized Personnel can invite
    if not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden('Only Authorized Personnel may invite')
    if request.method == 'POST':
        form = InvitationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            # Avoid duplicate pending invitations
            Invitation.objects.filter(email=email, department=department, accepted=False).delete()
            Invitation.objects.create(email=email, department=department, inviter=request.user)
            return redirect('department_dashboard', dept_id=department.id)
    else:
        form = InvitationForm()
    return render(request, 'accounts/invite.html', {'form': form, 'department': department})

def accept_invitation(request, token):
    invitation = get_object_or_404(Invitation, token=token)
    if not invitation.is_valid():
        return HttpResponseBadRequest('Invalid or expired invitation')
    if not request.user.is_authenticated:
        # Store token in session and redirect to login
        request.session['pending_invite_token'] = token
        return redirect('account_login')
    # Create membership with regular role (Student)
    Membership.objects.get_or_create(user=request.user, department=invitation.department, defaults={'role': invitation.role})
    invitation.accepted = True
    invitation.accepted_at = timezone.now()
    invitation.save()
    request.session.pop('pending_invite_token', None)
    return redirect('department_dashboard', dept_id=invitation.department.id)

# ---------- Role Elevation Request Views ----------
class ElevationRequestForm(forms.Form):
    target_email = forms.EmailField(label='User Email')
    note = forms.CharField(widget=forms.Textarea, required=False)

@login_required
def request_authorized_personnel(request, dept_id):
    department = get_object_or_404(Department, pk=dept_id, is_active=True)
    # Only current Authorized Personnel can request new one
    if not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden('Only Authorized Personnel may request')
    if request.method == 'POST':
        form = ElevationRequestForm(request.POST)
        if form.is_valid():
            target_email = form.cleaned_data['target_email']
            note = form.cleaned_data['note']
            target_user = User.objects.filter(email=target_email).first()
            if not target_user:
                return HttpResponseBadRequest('Target user does not exist')
            RoleElevationRequest.objects.get_or_create(
                department=department,
                target_user=target_user,
                defaults={'requester': request.user, 'note': note}
            )
            return redirect('department_dashboard', dept_id=department.id)
    else:
        form = ElevationRequestForm()
    return render(request, 'accounts/elevation_request.html', {'form': form, 'department': department})

@login_required
@user_passes_test(is_global_admin)
def review_elevation_requests(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        req_id = request.POST.get('request_id')
        req = get_object_or_404(RoleElevationRequest, pk=req_id, status='P')
        if action == 'approve':
            # Grant Authorized Personnel role in the department
            Membership.objects.update_or_create(
                user=req.target_user,
                department=req.department,
                defaults={'role': 'AP'}
            )
            req.status = 'A'
        elif action == 'reject':
            req.status = 'R'
        else:
            return HttpResponseBadRequest('Invalid action')
        req.reviewed_at = timezone.now()
        req.reviewer = request.user
        req.save()
        return redirect('review_elevation_requests')
    pending = RoleElevationRequest.objects.filter(status='P')
    return render(request, 'accounts/review_elevation_requests.html', {'pending_requests': pending})

# ---------- Routing Adjustments ----------
@login_required
def routing_view(request):
    """Routes users based on their Department assignment after logging in."""
    # Admins (including superusers) get admin dashboard
    if is_global_admin(request.user):
        return redirect('admin_dashboard')
    # Users with a department go to their department dashboard
    if request.user.department:
        return redirect('department_dashboard', dept_id=request.user.department.id)
    # No department assigned – show waiting room
    return redirect('waiting_room')

@login_required
def waiting_room(request):
    """The default page for users without an assigned department."""
    if request.user.department:
        return redirect('routing_view')
    return render(request, 'accounts/waiting_room.html')