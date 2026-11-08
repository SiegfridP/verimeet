from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponseForbidden, HttpResponseBadRequest
from .models import Department, Membership, Invitation, RoleElevationRequest, User
from django import forms
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError, PermissionDenied
from django.views.decorators.http import require_http_methods
from .audit import record, grant_ap
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Exists, OuterRef, Prefetch
from .dashboard_context import FILTER_CHOICES, department_allowed, workflow_redirect, overview_department


@login_required
@require_http_methods(['GET', 'POST'])
def account_settings(request):
    from .forms import UsernameSettingsForm
    from .signatures import signature_valid
    from allauth.account.models import EmailAddress
    from django.db import IntegrityError, OperationalError, connection
    form = UsernameSettingsForm(request.POST if request.method == 'POST' else None, user=request.user)
    if request.method == 'POST':
        saved = False
        try:
            with transaction.atomic():
                user = User.objects.select_for_update().get(pk=request.user.pk)
                form = UsernameSettingsForm(request.POST, user=user)
                if form.is_valid():
                    username = form.cleaned_data['username']
                    if username != user.username:
                        user.username = username
                        user.save(update_fields=['username'])
                        record(user, 'user.username_changed', user)
                    saved = True
        except IntegrityError:
            form.add_error('username', 'This username is no longer available. Please choose another.')
        except OperationalError as error:
            from sqlite3 import SQLITE_BUSY, SQLITE_LOCKED
            code = getattr(error.__cause__, 'sqlite_errorcode', None)
            locked = ((code & 255) in (SQLITE_BUSY, SQLITE_LOCKED) if code is not None else
                      str(error).lower().partition(':')[0] in {
                          'database is locked', 'database is busy',
                          'database table is locked', 'database schema is locked',
                      })
            if connection.vendor != 'sqlite' or not locked:
                raise
            form.add_error(None, 'The account could not be saved right now. Please retry.')
        else:
            if saved:
                messages.success(request, 'Username saved.')
                return redirect('account_settings')
    from .forms import SignatureReplacementForm
    from .signature_replacement import version
    ready = signature_valid(request.user)
    return render(request, 'accounts/account_settings.html', {
        'replacement_form': SignatureReplacementForm(initial={'version': version(request.user)})
            if ready and not is_global_admin(request.user) else None,
        'form': form,
        'email_addresses': EmailAddress.objects.filter(user=request.user).order_by('-primary', 'email'),
        'memberships': Membership.objects.filter(user=request.user, department__is_active=True)
            .select_related('department').order_by('department__name', 'department_id'),
        'signature_ready': ready,
        'has_password': request.user.has_usable_password(),
        'global_admin': is_global_admin(request.user),
    })


@login_required
@require_http_methods(['POST'])
def replace_account_signature(request):
    from .forms import SignatureReplacementForm
    from .signature_replacement import replace_signature
    from django.db import OperationalError, connection
    if is_global_admin(request.user):
        raise PermissionDenied('Signature management is unavailable.')
    form = SignatureReplacementForm(request.POST, request.FILES)
    if form.is_valid():
        try:
            replace_signature(request.user, form.cleaned_data['signature'], form.cleaned_data['version'])
        except ValidationError as error:
            form.add_error(None, error)
        except OperationalError as error:
            from sqlite3 import SQLITE_BUSY, SQLITE_LOCKED
            code = getattr(error.__cause__, 'sqlite_errorcode', None)
            locked = ((code & 255) in (SQLITE_BUSY, SQLITE_LOCKED) if code is not None else
                      str(error).lower().partition(':')[0] in {
                          'database is locked', 'database is busy',
                          'database table is locked', 'database schema is locked',
                      })
            if connection.vendor != 'sqlite' or not locked:
                raise
            form.add_error(None, 'Replacement could not be saved. Refresh Settings and retry.')
        except OSError:
            form.add_error(None, 'Replacement could not be saved. Refresh Settings and retry.')
        else:
            messages.success(request, 'Signature replaced. Previous versions remain privately retained.')
            return redirect('account_settings')
    return render(request, 'accounts/signature_replacement_error.html', {'form': form}, status=400)


def onboarding_destination(request):
    from .invitations import pending_invitation
    from allauth.account.utils import has_verified_email
    from django.urls import reverse
    invitation = pending_invitation(request)
    saved = request.session.pop('onboarding_invitation', None)
    if (isinstance(saved, list) and len(saved) == 2 and saved[1] == request.user.pk
            and isinstance(saved[0], str) and 0 < len(saved[0]) <= 64):
        candidate = Invitation.objects.filter(token=saved[0], accepted=False, department__is_active=True).first()
        if candidate and candidate.is_valid() and has_verified_email(request.user, candidate.email):
            return reverse('accept_invitation', args=[candidate.token])
    if (invitation and request.session.get('invite_verification_intent') == [invitation.token, request.user.pk]
            and has_verified_email(request.user, invitation.email)):
        return reverse('accept_invitation', args=[invitation.token])
    return reverse('central_dashboard')


@login_required
@require_http_methods(['GET', 'POST'])
def onboarding(request):
    from .forms import OnboardingForm
    from .signatures import signature_valid
    if is_global_admin(request.user):
        return redirect('admin_dashboard')
    valid = signature_valid(request.user)
    form = OnboardingForm(request.POST if request.method == 'POST' else None, request.FILES or None,
                          user=request.user, needs_signature=not valid)
    if request.method == 'POST':
        stored = None
        storage = request.user.signature_image.storage
        saved = False
        try:
            with transaction.atomic():
                user = User.objects.select_for_update().get(pk=request.user.pk)
                valid = signature_valid(user)
                # Requirements may have changed since the initial form was built.
                # Validate only this fresh form, before consuming the upload.
                form = OnboardingForm(request.POST, request.FILES or None,
                                      user=user, needs_signature=not valid)
                if form.is_valid():
                    # Recovery already persists signature state atomically. This
                    # later save is only for non-signature onboarding changes.
                    onboarding_fields = ['username', 'username_confirmation_required']
                    if user.username_confirmation_required or not user.username:
                        user.username = form.cleaned_data['username']
                        user.username_confirmation_required = False
                    if not valid:
                        upload = form.cleaned_data['signature']
                        if user.signature_image:
                            from .signature_replacement import _recover_onboarding_signature
                            stored = _recover_onboarding_signature(user, upload)
                            user.refresh_from_db(fields=['signature_image', 'signature_validation_hash', 'signature_validated'])
                        else:
                            stored = storage.save(upload.name, upload)
                            user.signature_image = stored
                            user.signature_validation_hash = ''
                            user.signature_validated = False
                            # Initial storage writes have not persisted a User reference yet.
                            onboarding_fields.extend(['signature_image', 'signature_validation_hash', 'signature_validated'])
                    user.save(update_fields=onboarding_fields)
                    if not user.username or user.username_confirmation_required or not signature_valid(user):
                        raise ValueError('Incomplete saved onboarding')
                    saved = True
        except Exception:
            # Failed new uploads remain private orphans; physical deletion is disabled.
            request.user.refresh_from_db(fields=['username', 'username_confirmation_required',
                'signature_image', 'signature_validation_hash', 'signature_validated'])
            valid = signature_valid(request.user)
            # Rollback or external file changes may have changed the requirements.
            # Start a fresh form rather than reusing consumed upload streams.
            form = OnboardingForm({}, user=request.user, needs_signature=not valid)
            form.add_error(None, 'Could not save onboarding. Please review the current requirements and retry.')
        else:
            if saved:
                messages.success(request, 'Account onboarding complete. Your signature preview is available on My Dashboard.')
                return redirect(onboarding_destination(request))
    return render(request, 'accounts/onboarding.html', {'form': form, 'signature_ready': valid})


@login_required
@require_http_methods(['GET', 'HEAD'])
def signature_preview(request):
    from .signatures import validated_signature_data
    from django.http import HttpResponse, Http404
    data = validated_signature_data(request.user)
    if data is None:
        raise Http404
    response = HttpResponse(data, content_type='image/png')
    response['Cache-Control'] = 'private, no-store'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


def meeting_list_context(request, queryset, officer=False):
    """Filter an already authorized meeting scope; personal data is always user-bound."""
    from meetings.models import Attendance
    filters = {'q': request.GET.get('q', '').strip()[:200]}
    choices = {'status': FILTER_CHOICES['status']}
    if officer:
        choices.update({key: value for key, value in FILTER_CHOICES.items() if key != 'status'})
    for key, allowed in choices.items():
        value = request.GET.get(key, '')
        filters[key] = value if value in allowed else ''
    has_meetings = queryset.exists()
    if filters['q']:
        queryset = queryset.filter(title__icontains=filters['q'])
    if filters['status']:
        queryset = queryset.filter(status=filters['status'])
    if officer:
        own = Attendance.objects.filter(meeting_id=OuterRef('pk'), user=request.user)
        queryset = queryset.annotate(assigned=Exists(own), signed=Exists(own.filter(has_signed=True)),
                                    eligible_attendance=Exists(own.filter(status__in=('Attended', 'Late'))))
        if filters['assignment']:
            queryset = queryset.filter(assigned=filters['assignment'] == 'assigned')
        if filters['attendance']:
            queryset = queryset.filter(Exists(own.filter(status=filters['attendance'])))
        signing = filters['signing']
        if signing == 'signed':
            queryset = queryset.filter(signed=True)
        elif signing == 'eligible':
            queryset = queryset.filter(assigned=True, signed=False, eligible_attendance=True, status='Finished')
        elif signing == 'awaiting':
            queryset = queryset.filter(assigned=True, signed=False, eligible_attendance=False, status='Finished')
        elif signing == 'unavailable':
            queryset = queryset.filter(assigned=True, signed=False).exclude(status='Finished')
        queryset = queryset.prefetch_related(Prefetch('attendees',
            queryset=Attendance.objects.filter(user=request.user), to_attr='own_attendances'))
    else:
        queryset = queryset.annotate(assigned_count=Count('attendees'))
    page = Paginator(queryset.select_related('department').order_by('-created_at', '-pk'), 20).get_page(request.GET.get('page'))
    for meeting in page:
        if officer:
            meeting.user_attendance = next(iter(meeting.own_attendances), None)
            att = meeting.user_attendance
            meeting.signing_label = ('Not Assigned' if att is None else 'Signed' if att.has_signed
                else 'Signing unavailable' if meeting.status != 'Finished' else 'Eligible to sign'
                if att.status in ('Attended', 'Late') else 'Awaiting attendance')
    from django.http import QueryDict
    params = QueryDict(mutable=True)
    params.update({key: value for key, value in filters.items() if value})
    department_value = request.GET.get('department', '')
    if department_value.isascii() and department_value.isdecimal() and len(department_value) < 10:
        params['department'] = department_value
    return {'meetings': page, 'page_obj': page, 'filters': filters,
            'filter_query': params.urlencode(), 'has_meetings': has_meetings,
            'officer_list': officer, 'lifecycle_choices': ('Draft', 'Finished', 'Archived'),
            'attendance_choices': ('Attended', 'Late', 'Absent')}


def department_scope(user, role=None):
    scope = Department.objects.filter(is_active=True)
    if is_global_admin(user):
        return scope
    memberships = Membership.objects.filter(user=user)
    if role:
        memberships = memberships.filter(role=role)
    if not role and user.department_id and not Membership.objects.filter(user=user).exists():
        return scope.filter(pk=user.department_id)
    return scope.filter(pk__in=memberships.values('department_id'))

class DepartmentForm(forms.ModelForm):
    class Meta:
        model = Department
        fields = ('name', 'contact_email')
        error_messages = {'name': {'unique': 'This name is unavailable. Choose another name.'}}

@login_required
@require_http_methods(['GET', 'POST'])
def create_department(request):
    form = DepartmentForm(request.POST if request.method == 'POST' else None)
    if request.method == 'POST' and form.is_valid():
        try:
            with transaction.atomic():
                department = form.save(commit=False)
                department.is_active = True
                department.save()
                record(request.user, 'department.created', department, department)
                membership = Membership.objects.create(user=request.user, department=department, role='AP')
                record(request.user, 'membership.added', membership, department,
                       {'user_id': request.user.pk, 'new_role': 'AP'})
        except Exception:
            form.add_error(None, 'Department could not be created. Please retry with another name.')
        else:
            return redirect('department_dashboard', dept_id=department.pk)
    return render(request, 'accounts/create_department.html', {'form': form})

@login_required
@require_http_methods(['GET', 'POST'])
def delete_department(request, dept_id):
    if not is_global_admin(request.user):
        return HttpResponseForbidden('Global Admin access required')
    department = get_object_or_404(Department, pk=dept_id)
    error = None
    if request.method == 'POST':
        try:
            from .department_deletion import delete_with_audit
            delete_with_audit(request.user, department)
        except PermissionDenied as exc:
            error = str(exc)
        else:
            return redirect('admin_dashboard')
    return render(request, 'accounts/delete_department.html', {'department': department, 'error': error},
                  status=400 if error else 200)

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


def active_department_for_user(user):
    membership = (Membership.objects.filter(user=user, department__is_active=True)
                  .order_by('department_id', 'pk').first())
    if membership:
        return membership.department
    # Membership records are authoritative, including inactive-only memberships.
    if user.department_id and not Membership.objects.filter(user=user).exists():
        return Department.objects.filter(pk=user.department_id, is_active=True).first()
    return None

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
            try:
                grant_ap(request.user, req.target_user, req.department)
            except ValidationError:
                return HttpResponseBadRequest('Active department membership required.')
            req.status = 'A'
        elif action == 'reject':
            req.status = 'R'
        else:
            return HttpResponseBadRequest('Invalid action')
        req.reviewed_at = timezone.now()
        req.reviewer = request.user
        req.save()
        messages.success(request, 'Role-elevation request processed.')
        return workflow_redirect(request, 'admin_dashboard')

    departments = Department.objects.filter(is_active=True).order_by('name', 'pk')
    pending_requests = RoleElevationRequest.objects.filter(status='P').select_related('target_user', 'department')
    from meetings.models import Meeting
    queryset = Meeting.objects.all()
    department_filter = overview_department(request.GET.get('department', ''))
    if department_filter:
        queryset = queryset.filter(department_id=int(department_filter))
    return render(request, 'accounts/admin_dashboard.html', {
        **meeting_list_context(request, queryset),
        'global_admin': True, 'global_overview': True, 'can_manage': True, 'department_filter': department_filter,
        'departments': departments,
        'pending_requests': pending_requests,
    })

@login_required
def department_dashboard(request, dept_id=None):
    # Determine department context
    if dept_id:
        department = get_object_or_404(department_scope(request.user), pk=dept_id)
    else:
        # pick first membership if only one, otherwise require explicit dept_id
        memberships = Membership.objects.filter(user=request.user, department__is_active=True)
        if memberships.count() == 1:
            department = memberships.first().department
        else:
            return HttpResponseBadRequest('Department ID required')

    # Global authority takes precedence over department membership.
    membership = Membership.objects.filter(user=request.user, department=department).first()
    global_admin = is_global_admin(request.user)
    if not global_admin and not membership:
        if not department_allowed(request.user, department):
            return HttpResponseForbidden('No membership in this department')
    can_manage = global_admin or (membership and membership.role == 'AP')
    departments = Department.objects.filter(is_active=True).order_by('name', 'pk')
    if not global_admin:
        departments = departments.filter(memberships__user=request.user)
    return render(request, 'accounts/authorized_dashboard.html' if can_manage else 'accounts/member_dashboard.html', {
        **meeting_list_context(request, department.meeting_set.all(), officer=not can_manage),
        'department': department, 'membership': membership, 'global_admin': global_admin,
        'can_manage': can_manage, 'switch_departments': departments,
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
    department = get_object_or_404(department_scope(request.user, 'AP'), pk=dept_id)
    # Only Authorized Personnel (or Global Admin) can invite
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden('Only Authorized Personnel may invite')
    if request.method == 'POST':
        form = InvitationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            # Invitations strictly grant canonical Officer role
            role = 'O'
            try:
                with transaction.atomic():
                    # Serialize replacements per department, including on SQLite.
                    from django.db.models import F
                    if not Department.objects.filter(pk=department.pk, is_active=True).update(name=F('name')):
                        return HttpResponseForbidden('Department is inactive.')
                    pending = list(Invitation.objects.filter(email=email, department=department, accepted=False))
                    invitation = Invitation.objects.create(email=email, department=department, inviter=request.user, role=role)
                    from .models import InvitationDelivery
                    InvitationDelivery.objects.create(invitation=invitation)
                    record(request.user, 'invitation.created', invitation, department)
                    for old in pending:
                        record(request.user, 'invitation.revoked', old, department)
                        old.delete()
            except Exception:
                form.add_error(None, 'Invitation could not be queued. Please retry. Any previous invitation remains valid.')
            else:
                messages.success(request, 'Invitation queued for email processing. Backend submission does not confirm inbox delivery.')
                return workflow_redirect(request, 'department_dashboard', dept_id=department.id)
    else:
        form = InvitationForm()
    return render(request, 'accounts/invite.html', {'form': form, 'department': department,
        'pending_invitations': department.invitations.filter(accepted=False, expires_at__gt=timezone.now()).select_related('delivery').order_by('-pk')[:20]})

def accept_invitation(request, token):
    from .invitations import pending_invitation_url, clear_pending_invitation
    from allauth.account.utils import has_verified_email
    from django.http import HttpResponseNotAllowed
    from django.urls import reverse
    if request.method not in ('GET', 'POST'):
        return HttpResponseNotAllowed(['GET', 'POST'])
    pending_invitation_url(request)  # Remove unusable older context even on invalid links.
    invitation = get_object_or_404(Invitation.objects.select_related('department'), token=token)
    if not invitation.is_valid() or not invitation.department.is_active:
        if request.session.get('pending_invite_token') == token:
            clear_pending_invitation(request)
        return HttpResponseBadRequest('Invitation is unavailable or expired.')
    # Viewing a page is not verification intent; retain only this flow's marker.
    if (request.session.get('pending_invite_token') != token
            or not request.user.is_authenticated
            or request.session.get('invite_verification_intent') != [token, request.user.pk]):
        request.session.pop('invite_verification_intent', None)
    request.session['pending_invite_token'] = token
    eligible = request.user.is_authenticated and has_verified_email(request.user, invitation.email)
    if request.method == 'POST':
        if not eligible:
            return HttpResponseForbidden('Log in with a verified matching email before accepting.')
        with transaction.atomic():
            from django.db.models import F
            # Shared lock order with replacement; no timestamp or lifecycle mutation.
            if not Department.objects.filter(pk=invitation.department_id, is_active=True).update(name=F('name')):
                return HttpResponseBadRequest('Invitation is unavailable.')
            invitation = get_object_or_404(Invitation.objects.select_for_update(), token=token)
            if not has_verified_email(request.user, invitation.email):
                return HttpResponseForbidden('Verified matching email required.')
            consumed = Invitation.objects.filter(pk=invitation.pk, accepted=False,
                expires_at__gt=timezone.now(), department__is_active=True).update(accepted=True, accepted_at=timezone.now())
            if consumed != 1:
                return HttpResponseBadRequest('Invitation is unavailable or expired.')
            membership, created = Membership.objects.get_or_create(user=request.user,
                department_id=invitation.department_id, defaults={'role': 'O'})
            if created:
                record(request.user, 'membership.added', membership, invitation.department,
                       {'user_id': request.user.pk, 'new_role': 'O'})
            record(request.user, 'invitation.accepted', invitation, invitation.department)
        clear_pending_invitation(request)
        messages.success(request, 'Invitation accepted. Your department membership is available.')
        return redirect('department_dashboard', dept_id=invitation.department_id)
    return render(request, 'accounts/accept_invitation.html', {'invitation': invitation,
        'eligible': eligible, 'invitation_path': reverse('accept_invitation', args=[token])})
# ---------- Role Elevation Request Views ----------
class ElevationRequestForm(forms.Form):
    target_email = forms.EmailField(label='User Email')
    note = forms.CharField(widget=forms.Textarea, required=False)

@login_required
def request_authorized_personnel(request, dept_id):
    department = get_object_or_404(department_scope(request.user, 'AP'), pk=dept_id)
    # Only current Authorized Personnel (or Global Admin) can request new one
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden('Only Authorized Personnel may request')
    if request.method == 'POST':
        form = ElevationRequestForm(request.POST)
        if form.is_valid():
            target_email = form.cleaned_data['target_email']
            note = form.cleaned_data['note']
            target_user = User.objects.filter(email=target_email).first()
            if not target_user or not Membership.objects.filter(user=target_user, department=department).exists():
                return HttpResponseBadRequest('Target user does not exist')
            elevation, created = RoleElevationRequest.objects.get_or_create(
                department=department,
                target_user=target_user,
                defaults={'requester': request.user, 'note': note}
            )
            if created:
                messages.success(request, 'Role-elevation request submitted.')
            else:
                messages.info(request, 'A role-elevation request already exists for this user and department.')
            return workflow_redirect(request, 'department_dashboard', dept_id=department.id)
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
            try:
                grant_ap(request.user, req.target_user, req.department)
            except ValidationError:
                return HttpResponseBadRequest('Active department membership required.')
            req.status = 'A'
        elif action == 'reject':
            req.status = 'R'
        else:
            return HttpResponseBadRequest('Invalid action')
        req.reviewed_at = timezone.now()
        req.reviewer = request.user
        req.save()
        messages.success(request, 'Role-elevation request processed.')
        return workflow_redirect(request, 'review_elevation_requests')
    pending = RoleElevationRequest.objects.filter(status='P')
    return render(request, 'accounts/review_elevation_requests.html', {'pending_requests': pending})

# ---------- Default and central dashboard routing ----------
@login_required
def routing_view(request):
    """Default landing only; explicit authentication continuations take precedence."""
    return redirect('admin_dashboard' if is_global_admin(request.user) else 'central_dashboard')


@login_required
def central_dashboard(request):
    if is_global_admin(request.user):
        return redirect('admin_dashboard')
    memberships = Membership.objects.filter(user=request.user)
    entries = [
        {'department': membership.department, 'role': membership.get_role_display()}
        for membership in memberships.filter(department__is_active=True)
        .select_related('department').order_by('department__name', 'department_id')
    ]
    # Real memberships are authoritative, including inactive-only memberships.
    if not entries and not memberships.exists():
        department = active_department_for_user(request.user)
        if department:
            entries.append({'department': department, 'role': 'Officer'})
    from .invitations import dashboard_invitations
    return render(request, 'accounts/central_dashboard.html', {
        'department_entries': entries,
        'pending_invitations': dashboard_invitations(request),
    })


@login_required
def waiting_room(request):
    """Compatibility destination for bookmarks and authentication continuations."""
    return redirect('admin_dashboard' if is_global_admin(request.user) else 'central_dashboard')


@login_required
@transaction.atomic
def retry_invitation_delivery(request, invitation_id):
    from django.http import HttpResponseNotAllowed
    from django.db.models import F
    from .models import InvitationDelivery
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    invitations = Invitation.objects.all()
    if not is_global_admin(request.user):
        invitations = invitations.filter(department__memberships__user=request.user,
                                         department__memberships__role='AP')
    invitation = get_object_or_404(invitations, pk=invitation_id)
    if not is_global_admin(request.user) and not has_membership(request.user, invitation.department, role='AP'):
        return HttpResponseForbidden('Authorized Personnel access required.')
    if not Department.objects.filter(pk=invitation.department_id, is_active=True).update(name=F('name')):
        return HttpResponseBadRequest('Invitation is unavailable.')
    invitation = get_object_or_404(Invitation.objects.select_for_update(), pk=invitation_id)
    if not invitation.is_valid():
        return HttpResponseBadRequest('Invitation is unavailable.')
    delivery, created = InvitationDelivery.objects.get_or_create(invitation=invitation)
    if not created:
        changed = InvitationDelivery.objects.filter(pk=delivery.pk, status='failed').update(
            status='pending', attempts=0, next_attempt_at=timezone.now(), last_error='')
        if not changed:
            return HttpResponseBadRequest('Delivery is not eligible for manual retry.')
    messages.success(request, 'Invitation email queued using the existing invitation and expiry.')
    return workflow_redirect(request, 'invite_member', dept_id=invitation.department_id)
