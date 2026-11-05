from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponseForbidden, HttpResponseBadRequest
from .models import Department, Membership, Invitation, RoleElevationRequest, User
from django import forms
from django.utils import timezone
from django.db import transaction
from .audit import record, grant_ap

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

@login_required
@transaction.atomic
def admin_dashboard(request):
    if not is_global_admin(request.user):
        return HttpResponseForbidden('Global Admin access required')

    if request.method == 'POST':
        action = request.POST.get('action') or request.GET.get('action')
        req_id = request.POST.get('request_id') or request.GET.get('request_id')
        if not action or not req_id:
            return HttpResponseBadRequest('Missing request_id or action')
        req = get_object_or_404(RoleElevationRequest.objects.select_for_update(), pk=req_id, status='P')
        if action == 'approve':
            grant_ap(request.user, req.target_user, req.department)
            req.status = 'A'
        elif action == 'reject':
            req.status = 'R'
        else:
            return HttpResponseBadRequest('Invalid action')
        req.reviewed_at = timezone.now()
        req.reviewer = request.user
        req.save()
        return redirect('admin_dashboard')

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

    # Resolve membership and role (or Global Admin bypass)
    try:
        membership = Membership.objects.get(user=request.user, department=department)
        role = membership.role
    except Membership.DoesNotExist:
        if is_global_admin(request.user):
            membership = None
            role = 'AP'
        elif request.user.department_id == department.id:
            role = 'O'
            membership, _ = Membership.objects.get_or_create(
                user=request.user, department=department, defaults={'role': role}
            )
        else:
            return HttpResponseForbidden('No membership in this department')

    if hasattr(department, 'meeting_set'):
        meetings = list(department.meeting_set.all().order_by('-created_at'))
        from meetings.models import Attendance
        user_attendances = {
            att.meeting_id: att for att in Attendance.objects.filter(
                meeting__in=meetings, user=request.user
            )
        }
        for m in meetings:
            m.user_attendance = user_attendances.get(m.id)
    else:
        meetings = []
    user_memberships = Membership.objects.filter(user=request.user).select_related('department')

    if role == 'AP':
        template = 'accounts/authorized_dashboard.html'
    else:
        template = 'accounts/member_dashboard.html'

    return render(request, template, {
        'department': department,
        'membership': membership,
        'meetings': meetings,
        'user_memberships': user_memberships,
    })

# ---------- Invitation Views ----------
class InvitationForm(forms.Form):
    email = forms.EmailField(label='Invitee Email')
    role = forms.ChoiceField(
        choices=[('O', 'Officer')],
        initial='O',
        label='Department Role',
        help_text='Invitations grant Officer membership in the department.'
    )

@login_required
@transaction.atomic
def invite_member(request, dept_id):
    department = get_object_or_404(Department, pk=dept_id, is_active=True)
    # Only Authorized Personnel (or Global Admin) can invite
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden('Only Authorized Personnel may invite')
    if request.method == 'POST':
        form = InvitationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            # Invitations strictly grant canonical Officer role
            role = 'O'
            # Avoid duplicate pending invitations
            pending = Invitation.objects.select_for_update().filter(email=email, department=department, accepted=False)
            for old_invitation in pending:
                record(request.user, 'invitation.revoked', old_invitation, department)
            pending.delete()
            invitation = Invitation.objects.create(email=email, department=department, inviter=request.user, role=role)
            record(request.user, 'invitation.created', invitation, department)
            return redirect('department_dashboard', dept_id=department.id)
    else:
        form = InvitationForm()
    return render(request, 'accounts/invite.html', {'form': form, 'department': department})

@transaction.atomic
def accept_invitation(request, token):
    invitation = get_object_or_404(Invitation, token=token)
    if not invitation.is_valid():
        return HttpResponseBadRequest('Invalid or expired invitation')
    if not request.user.is_authenticated:
        # Store token in session and redirect to login
        request.session['pending_invite_token'] = token
        return redirect('account_login')
    # Grant canonical Officer role (mapping legacy 'S' or 'O' to 'O')
    role_to_grant = 'O'
    membership, created = Membership.objects.get_or_create(
        user=request.user,
        department=invitation.department,
        defaults={'role': role_to_grant}
    )
    if created:
        record(request.user, 'membership.added', membership, invitation.department,
               {'user_id': request.user.pk, 'new_role': role_to_grant})
    # Ensure accepting an invitation does not downgrade an existing Authorized Personnel
    if not created and membership.role not in ('AP',):
        previous_role = membership.role
        membership.role = role_to_grant
        membership.save(update_fields=['role'])
        if previous_role != role_to_grant:
            record(request.user, 'user.role_changed', membership, invitation.department,
                   {'user_id': request.user.pk, 'previous_role': previous_role, 'new_role': role_to_grant})

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
    # Only current Authorized Personnel (or Global Admin) can request new one
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
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
@transaction.atomic
def review_elevation_requests(request):
    if not is_global_admin(request.user):
        return HttpResponseForbidden('Global Admin access required')

    if request.method == 'POST':
        action = request.POST.get('action') or request.GET.get('action')
        req_id = request.POST.get('request_id') or request.GET.get('request_id')
        if not action or not req_id:
            return HttpResponseBadRequest('Missing request_id or action')
        req = get_object_or_404(RoleElevationRequest.objects.select_for_update(), pk=req_id, status='P')
        if action == 'approve':
            # Grant Authorized Personnel role in the department
            grant_ap(request.user, req.target_user, req.department)
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

    # Resolve active department via Membership or legacy department
    membership = Membership.objects.filter(user=request.user).select_related('department').first()
    if membership:
        return redirect('department_dashboard', dept_id=membership.department_id)
    if request.user.department:
        return redirect('department_dashboard', dept_id=request.user.department.id)

    # No department assigned – show waiting room
    return redirect('waiting_room')

@login_required
def waiting_room(request):
    """The default page for users without an assigned department."""
    has_membership_record = Membership.objects.filter(user=request.user).exists()
    if has_membership_record or request.user.department:
        return redirect('routing_view')
    return render(request, 'accounts/waiting_room.html')