import hmac
import time
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, HttpResponse, HttpResponseBadRequest, HttpResponseNotAllowed
from django.utils import timezone
from django.contrib import messages
from django.db import transaction
from .models import Meeting, Attendance, AuditLog
from .crypto import generate_hmac_qr_token, sign_document_data, verify_document_signature
from .forms import MeetingForm, AssignParticipantsForm, MeetingEditForm
from accounts.models import Membership, Department, User
from accounts.views import is_global_admin, has_membership

def user_in_department(user, meeting):
    if not user.is_authenticated:
        return False
    if is_global_admin(user):
        return True
    return has_membership(user, meeting.department)

@login_required
def authorized_personnel_dashboard(request):
    """Legacy compatibility route: redirects Authorized Personnel to canonical department dashboard."""
    dept_id = request.GET.get('dept_id')
    if dept_id:
        try:
            department = Department.objects.get(pk=dept_id, is_active=True)
        except (Department.DoesNotExist, ValueError):
            return HttpResponseForbidden('Department not found')
    elif request.user.department:
        department = request.user.department
    else:
        # Look for first AP membership
        ap_mem = Membership.objects.filter(user=request.user, role='AP').first()
        if ap_mem:
            department = ap_mem.department
        else:
            return HttpResponseForbidden('Authorized Personnel access required')

    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden('Authorized Personnel access required')

    return redirect('department_dashboard', dept_id=department.id)

@login_required
def officer_dashboard(request):
    """Officer dashboard compatibility route: redirects Officers to canonical department dashboard."""
    dept_id = request.GET.get('dept_id')
    if dept_id:
        try:
            department = Department.objects.get(pk=dept_id, is_active=True)
            if not is_global_admin(request.user) and not has_membership(request.user, department):
                return HttpResponseForbidden('No membership in this department')
            return redirect('department_dashboard', dept_id=department.id)
        except (Department.DoesNotExist, ValueError):
            return HttpResponseForbidden('Department not found')

    # Resolve department context via active Membership or legacy user.department
    membership = Membership.objects.filter(user=request.user).select_related('department').first()
    if membership:
        return redirect('department_dashboard', dept_id=membership.department_id)
    if request.user.department_id:
        return redirect('department_dashboard', dept_id=request.user.department_id)

    return redirect('waiting_room')

# Compatibility alias
student_dashboard = officer_dashboard

def _finalize_meeting_internal(request, meeting_id):
    """
    Shared implementation for finalizing/locking a Draft meeting to 'Finished'.
    Enforces server-side authorization (Global Admin or AP of meeting's department),
    POST method requirement (rejects GET), Draft status integrity, atomic transition
    with row-level locking against concurrent requests, and audit logging.
    """
    # Method check first: Finalization MUST be submitted via POST.
    # GET requests must never finalize or lock a meeting.
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'], "Finalization requires a POST request.")

    with transaction.atomic():
        # Lock the row to prevent concurrent finalization of the same meeting.
        meeting = get_object_or_404(Meeting.objects.select_for_update(), id=meeting_id)
        department = meeting.department

        # Server-side authorization check: Global Admin or AP of the department.
        if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
            return HttpResponseForbidden("You are not authorized to finalize meetings for this department.")

        # Integrity check: Meeting must be currently in Draft status.
        # Finished or Archived cannot be finalized again.
        if meeting.status != 'Draft':
            return HttpResponseForbidden("Only Draft meetings can be finalized.")

        meeting.status = 'Finished'
        meeting.save(update_fields=['status', 'updated_at'])

        AuditLog.objects.create(
            department=department,
            meeting=meeting,
            user=request.user,
            action="Finalized document for signing"
        )

    messages.success(request, f"Meeting '{meeting.title}' has been finalized and locked for signing.")
    return redirect('department_dashboard', dept_id=department.id)


@login_required
def lock_meeting(request, meeting_id):
    """
    Compatibility endpoint for locking/finalizing a meeting.
    Delegates to the shared finalization implementation to enforce identical authorization,
    method restrictions (POST only), Draft-status check, and audit logging.
    """
    return _finalize_meeting_internal(request, meeting_id)

@login_required
def projector_qr_view(request, meeting_id):
    """Displays the QR code for the projector."""
    meeting = get_object_or_404(Meeting, id=meeting_id)
    can_access = is_global_admin(request.user) or has_membership(request.user, meeting.department, role='AP')
    if not can_access or meeting.status != 'Finished':
        return HttpResponseForbidden()

    timestamp = str(int(time.time()))
    sig = generate_hmac_qr_token(meeting_id, timestamp)

    # The URL the QR code will point to
    signing_url = f"{request.scheme}://{request.get_host()}/meetings/{meeting_id}/sign/?t={timestamp}&sig={sig}"

    return render(request, 'meetings/qr_projector.html', {'signing_url': signing_url})

@login_required
def sign_meeting(request, meeting_id):
    """Officer view to annotate and sign."""
    meeting = get_object_or_404(Meeting, id=meeting_id)
    if not user_in_department(request.user, meeting) or meeting.status != 'Finished':
        return HttpResponseForbidden()

    # 1. Verify the HMAC token from the URL to ensure they scanned the QR
    timestamp = request.GET.get('t')
    received_sig = request.GET.get('sig')
    if not timestamp or not received_sig:
        return HttpResponseForbidden("Missing security token.")

    try:
        ts = int(timestamp)
        now = int(time.time())
        token_age = now - ts
        if token_age < 0 or token_age > 3600:
            return HttpResponseForbidden("Invalid or expired QR code.")

        expected_sig = generate_hmac_qr_token(meeting_id, timestamp)
        if not hmac.compare_digest(expected_sig, received_sig):
            return HttpResponseForbidden("Invalid or expired QR code.")
    except (ValueError, TypeError):
        return HttpResponseForbidden("Invalid or expired QR code.")

    # 2. Verify Officer is an assigned eligible signer for this meeting
    try:
        attendance = Attendance.objects.get(meeting=meeting, user=request.user)
    except Attendance.DoesNotExist:
        return HttpResponseForbidden("You are not an assigned eligible signer for this meeting.")

    if attendance.has_signed:
        return HttpResponseForbidden("You have already signed this document.")

    if request.method == 'POST':
        annotation = request.POST.get('annotation', '')

        if not request.user.private_key:
            return HttpResponseBadRequest("Digital signature key is unavailable. Please contact your administrator.")

        # Build canonical payload using the single source of truth function
        payload_to_sign = _build_signing_payload(meeting, annotation)

        # Sign with the user's encrypted private key.
        # Any cryptographic failure must NOT leave a false has_signed=True record.
        try:
            digital_sig = sign_document_data(request.user.private_key, payload_to_sign)
        except Exception:
            return HttpResponseBadRequest("Cryptographic signing could not be completed. Please contact your administrator.")

        # Atomically persist the signature and audit record only if still unsigned.
        # This conditional update guarantees that concurrent requests cannot both succeed.
        with transaction.atomic():
            updated = Attendance.objects.filter(
                pk=attendance.pk,
                has_signed=False
            ).update(
                annotation=annotation,
                has_signed=True,
                cryptographic_signature=digital_sig,
                signed_at=timezone.now()
            )

            if updated == 0:
                return HttpResponseForbidden("You have already signed this document.")

            AuditLog.objects.create(
                department=meeting.department,
                meeting=meeting,
                user=request.user,
                action="Signed document with annotation"
            )
        return redirect('department_dashboard', dept_id=meeting.department_id)

    return render(request, 'meetings/sign_document.html', {'meeting': meeting})


def _build_signing_payload(meeting, annotation: str = '') -> str:
    """Return the canonical meeting-bound signing payload.

    Binds the meeting ID, department ID, meeting title, finalized minutes content,
    and signer annotation into a deterministic byte sequence for signing and verification.
    """
    minutes = meeting.minutes_content or ''
    ann = annotation or ''
    return (
        f"meeting_id:{meeting.id}\n"
        f"department_id:{meeting.department_id}\n"
        f"title:{meeting.title}\n"
        f"{minutes}\n"
        f"---ANNOTATION---\n"
        f"{ann}"
    )


def _build_legacy_signing_payload(meeting, annotation: str = '') -> str:
    """Return the original legacy signing payload format.

    Preserves backward compatibility for signatures generated before
    meeting-bound canonical payloads were introduced.
    """
    minutes = meeting.minutes_content or ''
    ann = annotation or ''
    return f"{minutes}\n---ANNOTATION---\n{ann}"


@login_required
def create_meeting(request, dept_id=None):
    """
    Authorized Personnel creates a new meeting within their authorized department
    and assigns eligible department members as participants and intended signers.
    """
    target_dept_id = dept_id or request.GET.get('dept_id') or request.POST.get('department_id')
    department = None

    if target_dept_id:
        try:
            department = Department.objects.get(pk=target_dept_id, is_active=True)
        except (Department.DoesNotExist, ValueError):
            return HttpResponseForbidden("Invalid or inactive department.")
    elif request.user.department and (is_global_admin(request.user) or has_membership(request.user, request.user.department, role='AP')):
        department = request.user.department
    else:
        ap_memberships = Membership.objects.filter(user=request.user, role='AP').select_related('department')
        if ap_memberships.count() == 1:
            department = ap_memberships.first().department
        elif ap_memberships.count() > 1:
            return render(request, 'meetings/select_department.html', {
                'departments': [m.department for m in ap_memberships]
            })
        elif is_global_admin(request.user):
            active_depts = Department.objects.filter(is_active=True)
            if active_depts.count() == 1:
                department = active_depts.first()
            elif active_depts.exists():
                return render(request, 'meetings/select_department.html', {
                    'departments': active_depts
                })
            else:
                return HttpResponseForbidden("No active departments available.")
        else:
            return HttpResponseForbidden("Authorized Personnel access required.")

    # Strict server-side authorization check
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden("You are not authorized to create meetings for this department.")

    if request.method == 'POST':
        form = MeetingForm(request.POST, department=department)
        if form.is_valid():
            with transaction.atomic():
                meeting = form.save(commit=False)
                meeting.department = department
                meeting.status = 'Draft'
                meeting.save()

                participants = form.cleaned_data.get('participants') or []
                for user in participants:
                    Attendance.objects.create(meeting=meeting, user=user)

                AuditLog.objects.create(
                    department=department,
                    meeting=meeting,
                    user=request.user,
                    action=f"Created meeting '{meeting.title[:50]}' with {len(participants)} assigned participant(s)"
                )

            messages.success(request, f"Meeting '{meeting.title}' created successfully.")
            return redirect('department_dashboard', dept_id=department.id)
    else:
        form = MeetingForm(department=department)

    return render(request, 'meetings/create_meeting.html', {
        'form': form,
        'department': department,
    })


@login_required
def assign_participants(request, meeting_id):
    """
    Authorized Personnel manages participant/intended-signer assignments
    for an existing Draft meeting within their department.
    """
    meeting = get_object_or_404(Meeting, id=meeting_id)
    department = meeting.department

    # Server-side authorization check
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden("You are not authorized to manage participant assignments for this department.")

    # Integrity check: cannot alter assignments for finalized or locked documents
    if meeting.status != 'Draft':
        return HttpResponseForbidden("Cannot modify participant assignments for a locked or finalized meeting.")

    if request.method == 'POST':
        form = AssignParticipantsForm(request.POST, department=department, meeting=meeting)
        if form.is_valid():
            selected_users = form.cleaned_data.get('participants') or []
            selected_user_ids = {u.id for u in selected_users}

            with transaction.atomic():
                current_attendances = {att.user_id: att for att in Attendance.objects.filter(meeting=meeting)}
                current_user_ids = set(current_attendances.keys())

                # Add new participants
                to_add = selected_user_ids - current_user_ids
                for uid in to_add:
                    Attendance.objects.create(meeting=meeting, user_id=uid)

                # Remove unselected participants (only if they haven't already signed)
                to_remove = current_user_ids - selected_user_ids
                for uid in to_remove:
                    att = current_attendances[uid]
                    if not att.has_signed:
                        att.delete()

                AuditLog.objects.create(
                    department=department,
                    meeting=meeting,
                    user=request.user,
                    action=f"Updated participant assignments for meeting '{meeting.title[:50]}'"
                )

            messages.success(request, "Participant assignments updated successfully.")
            return redirect('department_dashboard', dept_id=department.id)
    else:
        assigned_user_ids = meeting.attendees.values_list('user_id', flat=True)
        initial_participants = User.objects.filter(id__in=assigned_user_ids)
        form = AssignParticipantsForm(
            department=department,
            meeting=meeting,
            initial={'participants': initial_participants}
        )

    return render(request, 'meetings/assign_participants.html', {
        'form': form,
        'meeting': meeting,
        'department': department,
    })


@login_required
def edit_meeting(request, meeting_id):
    """
    Authorized Personnel edits an existing Draft meeting within their authorized department.
    Enforces that finalized or locked meetings cannot be modified.
    """
    meeting = get_object_or_404(Meeting, id=meeting_id)
    department = meeting.department

    # Server-side authorization check: Global Admin or AP of the department
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden("You are not authorized to edit meetings for this department.")

    # Integrity check: cannot edit finalized or locked documents
    if meeting.status != 'Draft':
        return HttpResponseForbidden("Cannot edit a locked or finalized meeting.")

    if request.method == 'POST':
        form = MeetingEditForm(request.POST, instance=meeting)
        if form.is_valid():
            with transaction.atomic():
                updated_meeting = form.save(commit=False)
                # Guarantee that department association and Draft status are preserved
                updated_meeting.department = department
                updated_meeting.status = 'Draft'
                updated_meeting.save()

                AuditLog.objects.create(
                    department=department,
                    meeting=meeting,
                    user=request.user,
                    action=f"Edited draft meeting minutes for '{updated_meeting.title[:50]}'"
                )

            messages.success(request, f"Meeting '{updated_meeting.title}' updated successfully.")
            return redirect('department_dashboard', dept_id=department.id)
    else:
        form = MeetingEditForm(instance=meeting)

    return render(request, 'meetings/edit_meeting.html', {
        'form': form,
        'meeting': meeting,
        'department': department,
    })


@login_required
def review_meeting(request, meeting_id):
    """
    Read-only preview of meeting minutes before or after finalization.
    Does not modify meeting or document content.
    """
    meeting = get_object_or_404(Meeting, id=meeting_id)
    department = meeting.department

    # Server-side authorization check: Global Admin or AP of the department
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden("You are not authorized to review meetings for this department.")

    attendees = meeting.attendees.select_related('user').all()

    return render(request, 'meetings/review_meeting.html', {
        'meeting': meeting,
        'department': department,
        'attendees': attendees,
    })


@login_required
def finalize_meeting(request, meeting_id):
    """
    Authorized Personnel explicitly finalizes a Draft meeting, locking it to 'Finished'.
    Requires POST request. Rejects GET and prevents duplicate finalization.
    """
    return _finalize_meeting_internal(request, meeting_id)


@login_required
def verify_signature(request, meeting_id, attendance_id):
    """Internal signature verification endpoint (Batch 05).

    Access control:
    - Global Admin: may verify any meeting's signatures.
    - Authorized Personnel (AP): may verify signatures within their own department only.
    - Officers: not permitted.

    Supports:
    1. Canonical meeting-bound format (meeting_id, department_id, title, content, annotation).
    2. Legacy format (minutes_content + annotation) for backward compatibility.
    Distinguishes them explicitly in the response without falsely attributing meeting-bound
    integrity to legacy signatures.
    """
    import json

    meeting = get_object_or_404(Meeting, id=meeting_id)
    department = meeting.department

    # Authorization: Global Admin or AP of the meeting's department.
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden("You are not authorized to verify signatures for this department.")

    attendance = get_object_or_404(Attendance, id=attendance_id, meeting=meeting)

    signer = attendance.user
    stored_signature = attendance.cryptographic_signature
    public_key_pem = signer.public_key if signer else None

    if not attendance.has_signed or not stored_signature:
        result = {
            'valid': False,
            'reason': 'No signature on record for this attendance entry.',
            'format': None,
            'is_legacy': False,
            'meeting_bound': False,
            'meeting_id': meeting.id,
            'attendance_id': attendance.id,
            'signer': signer.username if signer else None,
        }
        return HttpResponse(json.dumps(result, indent=2), content_type='application/json')

    # 1. Attempt verification with the canonical meeting-bound payload.
    canonical_payload = _build_signing_payload(meeting, attendance.annotation or '')
    if verify_document_signature(public_key_pem, canonical_payload, stored_signature):
        result = {
            'valid': True,
            'format': 'canonical',
            'is_legacy': False,
            'meeting_bound': True,
            'meeting_id': meeting.id,
            'department_id': meeting.department_id,
            'attendance_id': attendance.id,
            'signer': signer.username if signer else None,
            'signed_at': attendance.signed_at.isoformat() if attendance.signed_at else None,
        }
        return HttpResponse(json.dumps(result, indent=2), content_type='application/json')

    # 2. Backward compatibility: Attempt verification with the legacy payload.
    legacy_payload = _build_legacy_signing_payload(meeting, attendance.annotation or '')
    if verify_document_signature(public_key_pem, legacy_payload, stored_signature):
        result = {
            'valid': True,
            'format': 'legacy',
            'is_legacy': True,
            'meeting_bound': False,
            'meeting_id': meeting.id,
            'department_id': meeting.department_id,
            'attendance_id': attendance.id,
            'signer': signer.username if signer else None,
            'signed_at': attendance.signed_at.isoformat() if attendance.signed_at else None,
            'note': 'Signature verified using legacy format without meeting ID, department, or title binding.',
        }
        return HttpResponse(json.dumps(result, indent=2), content_type='application/json')

    # 3. Neither payload format verified.
    result = {
        'valid': False,
        'format': None,
        'is_legacy': False,
        'meeting_bound': False,
        'meeting_id': meeting.id,
        'attendance_id': attendance.id,
        'signer': signer.username if signer else None,
        'signed_at': attendance.signed_at.isoformat() if attendance.signed_at else None,
        'reason': 'Signature verification failed for both canonical and legacy payload formats.',
    }
    return HttpResponse(json.dumps(result, indent=2), content_type='application/json')
