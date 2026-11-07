import base64
import datetime
import hmac
import io
import time
import segno
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, HttpResponse, HttpResponseBadRequest, HttpResponseNotAllowed
from django.utils import timezone
from django.contrib import messages
from django.db import transaction, IntegrityError
from django.core.paginator import Paginator
from .models import Meeting, Attendance, AuditLog, QRSession, QRUsage, VerificationQR
from .attendance_integrity import lock_mutable_meetings
from .crypto import (
    generate_hmac_qr_token,
    verify_hmac_qr_token,
    generate_qr_session_token,
    sign_document_data,
    verify_document_signature,
    generate_verification_token,
    hash_verification_token,
    encrypt_verification_token,
    decrypt_verification_token,
    verify_attendance_signature,
)
from .forms import (
    MeetingForm,
    AssignParticipantsForm,
    MeetingEditForm,
    AttendanceStatusUpdateForm,
    SignMeetingForm,
    MAX_ANNOTATION_LENGTH,
)
from accounts.models import Membership, Department, User
from accounts.dashboard_context import workflow_redirect
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
            event_type='meeting.finalized', target_type='meeting', target_id=str(meeting.pk), metadata={'previous_status': 'Draft', 'new_status': 'Finished'},
            action="Finalized document for signing"
        )

    messages.success(request, f"Meeting '{meeting.title}' has been finalized and locked for signing.")
    return workflow_redirect(request, 'department_dashboard', dept_id=department.id)


@login_required
def lock_meeting(request, meeting_id):
    """
    Compatibility endpoint for locking/finalizing a meeting.
    Delegates to the shared finalization implementation to enforce identical authorization,
    method restrictions (POST only), Draft-status check, and audit logging.
    """
    return _finalize_meeting_internal(request, meeting_id)

def _generate_qr_png_b64(url: str, scale: int = 6) -> str:
    """Return a base64-encoded PNG of a real, scannable QR code for the given URL.

    Uses the ``segno`` library which produces ISO/IEC 18004-compliant QR codes.
    The returned string is suitable for use as an ``<img src="data:image/png;base64,…">``
    attribute without any further encoding.

    ``scale`` controls module size in pixels (default 6 → each module is 6×6 px).
    """
    qr = segno.make(url, error='m')
    buf = io.BytesIO()
    qr.save(buf, kind='png', scale=scale)
    return base64.b64encode(buf.getvalue()).decode('ascii')


@login_required
@transaction.atomic
def projector_qr_view(request, meeting_id):
    """Displays the QR code for the projector."""
    if request.method not in ('GET', 'POST'):
        return HttpResponseNotAllowed(['GET', 'POST'])
    meeting = get_object_or_404(Meeting, id=meeting_id)
    can_access = is_global_admin(request.user) or has_membership(request.user, meeting.department, role='AP')
    if not can_access or meeting.status != 'Finished':
        return HttpResponseForbidden()

    if request.method == 'POST':
        lock_mutable_meetings([meeting.pk])
    meeting.refresh_from_db(fields=['status'])
    if meeting.status != 'Finished':
        return HttpResponseForbidden()

    # Reuse or create active signing QR session under the Meeting guard.
    qr_session = QRSession.objects.filter(
        meeting=meeting,
        purpose=QRSession.PURPOSE_SIGNING,
        is_revoked=False,
        expires_at__gt=timezone.now()
    ).first()

    if not qr_session and request.method == 'POST':
        token = generate_qr_session_token()
        expires_at = timezone.now() + datetime.timedelta(seconds=3600)
        qr_session = QRSession.objects.create(
            meeting=meeting,
            purpose=QRSession.PURPOSE_SIGNING,
            token=token,
            created_by=request.user,
            expires_at=expires_at,
        )
        AuditLog.objects.create(
            department=meeting.department,
            meeting=meeting,
            user=request.user,
            event_type='qr.generated', target_type='qr_session', target_id=str(qr_session.pk), metadata={'qr_session_id': qr_session.pk, 'purpose': qr_session.purpose, 'expires_at': qr_session.expires_at.isoformat()},
            action="Generated Signing QR code"
        )

    signing_url = (request.build_absolute_uri(reverse('sign_meeting', args=[meeting.id])) + f"?token={qr_session.token}"
                   if qr_session else None)
    qr_image_b64 = _generate_qr_png_b64(signing_url, scale=8) if signing_url else None

    return render(request, 'meetings/qr_projector.html', {
        'meeting': meeting,
        'qr_session': qr_session,
        'signing_url': signing_url,
        'qr_image_b64': qr_image_b64,
    })


@login_required
@transaction.atomic
def generate_attendance_qr(request, meeting_id):
    """
    Authorized Personnel generates an Attendance QR code for an eligible meeting.
    Draft and Finished meetings are eligible; Archived meetings are locked.
    """
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    meeting = get_object_or_404(Meeting, id=meeting_id)
    can_access = is_global_admin(request.user) or has_membership(request.user, meeting.department, role='AP')
    if not can_access:
        return HttpResponseForbidden("You are not authorized to generate QR codes for this department.")

    if meeting.status == 'Archived':
        return HttpResponseForbidden("Cannot generate attendance QR for an archived meeting.")

    lock_mutable_meetings([meeting.pk])
    meeting.refresh_from_db(fields=['status'])
    if meeting.status == 'Archived':
        return HttpResponseForbidden("Cannot generate attendance QR for an archived meeting.")

    token = generate_qr_session_token()
    expires_at = timezone.now() + datetime.timedelta(seconds=3600)
    qr_session = QRSession.objects.create(
        meeting=meeting,
        purpose=QRSession.PURPOSE_ATTENDANCE,
        token=token,
        created_by=request.user,
        expires_at=expires_at,
    )

    AuditLog.objects.create(
        department=meeting.department,
        meeting=meeting,
        user=request.user,
        event_type='qr.generated', target_type='qr_session', target_id=str(qr_session.pk), metadata={'qr_session_id': qr_session.pk, 'purpose': qr_session.purpose, 'expires_at': qr_session.expires_at.isoformat()},
        action="Generated Attendance QR code"
    )

    messages.success(request, "Attendance QR code generated successfully.")
    return workflow_redirect(request, 'view_qr_session', meeting_id=meeting.id, session_id=qr_session.id)


@login_required
@transaction.atomic
def generate_signing_qr(request, meeting_id):
    """
    Authorized Personnel generates a Signing QR code for an eligible Finished meeting.
    Draft and Archived meetings cannot have Signing QR codes.
    """
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    meeting = get_object_or_404(Meeting, id=meeting_id)
    can_access = is_global_admin(request.user) or has_membership(request.user, meeting.department, role='AP')
    if not can_access:
        return HttpResponseForbidden("You are not authorized to generate QR codes for this department.")

    if meeting.status != 'Finished':
        return HttpResponseForbidden("Signing QR codes can only be generated for Finished meetings.")

    lock_mutable_meetings([meeting.pk])
    meeting.refresh_from_db(fields=['status'])
    if meeting.status != 'Finished':
        return HttpResponseForbidden("Signing QR codes can only be generated for Finished meetings.")

    token = generate_qr_session_token()
    expires_at = timezone.now() + datetime.timedelta(seconds=3600)
    qr_session = QRSession.objects.create(
        meeting=meeting,
        purpose=QRSession.PURPOSE_SIGNING,
        token=token,
        created_by=request.user,
        expires_at=expires_at,
    )

    AuditLog.objects.create(
        department=meeting.department,
        meeting=meeting,
        user=request.user,
        event_type='qr.generated', target_type='qr_session', target_id=str(qr_session.pk), metadata={'qr_session_id': qr_session.pk, 'purpose': qr_session.purpose, 'expires_at': qr_session.expires_at.isoformat()},
        action="Generated Signing QR code"
    )

    messages.success(request, "Signing QR code generated successfully.")
    return workflow_redirect(request, 'view_qr_session', meeting_id=meeting.id, session_id=qr_session.id)


@login_required
def view_qr_session(request, meeting_id, session_id):
    """
    AP view to display the QR code, expiration time, purpose, and usage status.
    """
    meeting = get_object_or_404(Meeting, id=meeting_id)
    can_access = is_global_admin(request.user) or has_membership(request.user, meeting.department, role='AP')
    if not can_access:
        return HttpResponseForbidden("You are not authorized to view QR sessions for this department.")

    qr_session = get_object_or_404(QRSession, id=session_id, meeting=meeting)

    if qr_session.purpose == QRSession.PURPOSE_ATTENDANCE:
        scan_url = request.build_absolute_uri(reverse('scan_attendance_qr', args=[meeting.id])) + f"?token={qr_session.token}"
        purpose_display = "Attendance"
    else:
        scan_url = request.build_absolute_uri(reverse('sign_meeting', args=[meeting.id])) + f"?token={qr_session.token}"
        purpose_display = "Digital Signing"

    qr_image_b64 = _generate_qr_png_b64(scan_url, scale=6)

    return render(request, 'meetings/qr_display.html', {
        'meeting': meeting,
        'qr_session': qr_session,
        'scan_url': scan_url,
        'purpose_display': purpose_display,
        'qr_image_b64': qr_image_b64,
    })


@login_required
@transaction.atomic
def revoke_qr_session(request, meeting_id, session_id):
    """
    AP view to revoke an active QR session immediately.
    """
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'], "Revoking a QR session requires a POST request.")

    meeting = get_object_or_404(Meeting, id=meeting_id)
    can_access = is_global_admin(request.user) or has_membership(request.user, meeting.department, role='AP')
    if not can_access:
        return HttpResponseForbidden("You are not authorized to revoke QR sessions for this department.")

    qr_session = get_object_or_404(QRSession.objects.select_for_update(), id=session_id, meeting=meeting)

    if not qr_session.is_revoked:
        qr_session.is_revoked = True
        qr_session.revoked_at = timezone.now()
        qr_session.revoked_by = request.user
        qr_session.save(update_fields=['is_revoked', 'revoked_at', 'revoked_by'])

        AuditLog.objects.create(
            department=meeting.department,
            meeting=meeting,
            user=request.user,
            event_type='qr.revoked', target_type='qr_session', target_id=str(qr_session.pk), metadata={'qr_session_id': qr_session.pk, 'purpose': qr_session.purpose},
            action=f"Revoked {qr_session.get_purpose_display()} QR code"
        )
        messages.success(request, f"{qr_session.get_purpose_display()} QR code has been revoked.")

    return workflow_redirect(request, 'view_qr_session', meeting_id=meeting.id, session_id=qr_session.id)


@login_required
@transaction.atomic
def scan_attendance_qr(request, meeting_id):
    """
    Officer view to record attendance by scanning the Attendance QR code.
    Validates token, purpose, expiration, revocation, assignment, and existing state.
    """
    if request.method not in ('GET', 'POST'):
        return HttpResponseNotAllowed(['GET', 'POST'])
    meeting = get_object_or_404(Meeting, id=meeting_id)

    # 1. Department membership check
    if not user_in_department(request.user, meeting):
        return HttpResponseForbidden("You do not belong to this department.")

    # 2. Extract token or HMAC params
    qr_token = request.GET.get('token') or request.POST.get('token')
    timestamp = request.GET.get('t') or request.POST.get('t')
    received_sig = request.GET.get('sig') or request.POST.get('sig')

    qr_session = None

    if qr_token:
        qr_session = QRSession.objects.filter(token=qr_token, meeting=meeting).first()
        if not qr_session:
            return HttpResponseForbidden("Invalid QR code.")
        if qr_session.purpose != QRSession.PURPOSE_ATTENDANCE:
            return HttpResponseForbidden("Signing QR tokens cannot be used to record attendance.")
        if qr_session.is_revoked:
            return HttpResponseForbidden("This QR code has been revoked.")
        if qr_session.is_expired:
            return HttpResponseForbidden("This QR code has expired.")
    elif timestamp and received_sig:
        purpose_param = request.GET.get('purpose') or request.POST.get('purpose')
        if purpose_param == 'signing':
            return HttpResponseForbidden("Signing QR tokens cannot be used to record attendance.")

        if not verify_hmac_qr_token(meeting.id, timestamp, received_sig, purpose='attendance'):
            return HttpResponseForbidden("Invalid or expired QR code.")
    else:
        return HttpResponseForbidden("Missing security token.")

    if meeting.status == 'Archived':
        return HttpResponseForbidden('Archived meeting attendance is read-only.')
    if request.method == 'POST':
        lock_mutable_meetings([meeting.pk])

    if qr_session and request.method == 'POST':
        # Lock order: Meeting, QRSession, then Attendance. Do not reuse the
        # authorization snapshot taken before waiting for the Meeting guard.
        qr_session = QRSession.objects.select_for_update().filter(
            pk=qr_session.pk, token=qr_token, meeting=meeting
        ).first()
        if not qr_session:
            return HttpResponseForbidden("Invalid QR code.")
        if qr_session.purpose != QRSession.PURPOSE_ATTENDANCE:
            return HttpResponseForbidden("Signing QR tokens cannot be used to record attendance.")
        if qr_session.is_revoked:
            return HttpResponseForbidden("This QR code has been revoked.")
        if qr_session.is_expired:
            return HttpResponseForbidden("This QR code has expired.")

    # 3. Check Officer is an assigned participant for this meeting
    try:
        attendance = Attendance.objects.get(meeting=meeting, user=request.user)
    except Attendance.DoesNotExist:
        return HttpResponseForbidden("You are not an assigned participant for this meeting.")

    # 4. QR attendance must not overwrite an existing digital signature (pre-flight read; definitive
    #    check is re-confirmed inside the atomic block below).
    if attendance.has_signed:
        return HttpResponseForbidden("Attendance cannot be modified because you have already digitally signed this meeting document.")

    if request.method == 'GET':
        return render(request, 'meetings/qr_attendance_confirm.html', {
            'meeting': meeting, 'attendance': attendance, 'qr_token': qr_token,
            'timestamp': timestamp, 'sig': received_sig,
            'purpose': request.GET.get('purpose', ''),
        })

    # 5. Record attendance atomically.
    #
    #    The duplicate-use guard lives INSIDE the transaction so that two simultaneous requests by
    #    the same officer cannot both slip through a pre-flight check and both write attendance.
    #
    #    Strategy (SQLite-safe — no row-level SELECT FOR UPDATE):
    #      a. Attempt to INSERT a QRUsage row guarded by the unique_together constraint.
    #         Only one of two racing requests can win that INSERT; the other gets IntegrityError.
    #      b. Inside the same transaction, before writing attendance, re-read the Attendance row
    #         to confirm it is still unsigned and not yet recorded via QR.
    #      c. The winning INSERT request writes attendance + audit.
    #         The losing request rolls back cleanly and returns the "already recorded" response.
    #    For the HMAC path (no QRSession), use a conditional UPDATE that only writes when the
    #    status is still 'Absent' with a NULL status_updated_at, mirroring the sign_meeting
    #    conditional-update pattern used in Batch 05.
    already_recorded = False

    if qr_session:
        try:
            with transaction.atomic():
                # Serialize with manual updates where row locks are supported.
                # SQLite ignores this lock; the conditional update below also guards
                # the status snapshot, but SQLite can still report database contention.
                attendance_now = Attendance.objects.select_for_update().get(pk=attendance.pk)

                if attendance_now.has_signed:
                    return HttpResponseForbidden("Attendance cannot be modified because you have already digitally signed this meeting document.")

                # Expiration can pass while waiting for the Attendance lock.
                if qr_session.is_expired:
                    return HttpResponseForbidden("This QR code has expired.")

                # Try to create the QRUsage record first.  The unique_together constraint
                # (qr_session, user) means only one concurrent request can succeed.
                # get_or_create returns (obj, created); created=False means already recorded.
                _usage, created = QRUsage.objects.get_or_create(
                    qr_session=qr_session, user=request.user
                )

                if not created:
                    # Another request (or a previous scan) already recorded this usage.
                    already_recorded = True
                elif attendance_now.status in ('Attended', 'Late') and attendance_now.status_updated_at is not None:
                    # Attendance was already set by a prior QR scan or manual AP update.
                    already_recorded = True
                else:
                    # We hold the unique QRUsage slot.  Record attendance conditionally
                    # requiring has_signed=False so that a concurrent digital signature
                    # cannot be overwritten.
                    updated = Attendance.objects.filter(
                        pk=attendance.pk,
                        has_signed=False,
                        meeting__status__in=('Draft', 'Finished'),
                        status=attendance_now.status,
                        status_updated_at=attendance_now.status_updated_at,
                    ).update(
                        status='Attended',
                        status_updated_at=timezone.now(),
                    )
                    if updated == 0:
                        _usage.delete()
                        if Meeting.objects.filter(pk=meeting.pk, status='Archived').exists():
                            return HttpResponseForbidden('Archived meeting attendance is read-only.')
                        current = Attendance.objects.get(pk=attendance.pk)
                        if not current.has_signed:
                            return HttpResponseForbidden(
                                'Attendance changed during this request. Please retry.'
                            )
                        return HttpResponseForbidden(
                            "Attendance cannot be modified because you have already digitally signed this meeting document."
                        )

                    AuditLog.objects.create(
                        department=meeting.department,
                        meeting=meeting,
                        user=request.user,
                        event_type='attendance.changed', target_type='attendance', target_id=str(attendance.pk), metadata={'attendance_id': attendance.pk, 'officer_id': attendance.user_id, 'previous_status': attendance_now.status, 'new_status': 'Attended', 'method': 'qr'},
                        action="Recorded attendance via QR as Attended"
                    )
        except IntegrityError:
            # Race lost at the DB level (unique constraint on QRUsage).  Treat as already recorded.
            already_recorded = True
    else:
        # HMAC path: use conditional UPDATE to atomically record attendance only once.
        # The filter on status='Absent' + status_updated_at=None ensures idempotency.
        if not verify_hmac_qr_token(meeting.id, timestamp, received_sig, purpose='attendance'):
            return HttpResponseForbidden("Invalid or expired QR code.")
        updated = Attendance.objects.filter(
            pk=attendance.pk,
            has_signed=False,
            status='Absent',
            status_updated_at__isnull=True,
            meeting__status__in=('Draft', 'Finished'),
        ).update(
            status='Attended',
            status_updated_at=timezone.now(),
        )
        if updated == 0:
            if Meeting.objects.filter(pk=meeting.pk, status='Archived').exists():
                return HttpResponseForbidden('Archived meeting attendance is read-only.')
            current = Attendance.objects.filter(pk=attendance.pk).first()
            if current and current.has_signed:
                return HttpResponseForbidden(
                    "Attendance cannot be modified because you have already digitally signed this meeting document."
                )
            already_recorded = True
        else:
            AuditLog.objects.create(
                department=meeting.department,
                meeting=meeting,
                user=request.user,
                event_type='attendance.changed', target_type='attendance', target_id=str(attendance.pk), metadata={'attendance_id': attendance.pk, 'officer_id': attendance.user_id, 'previous_status': 'Absent', 'new_status': 'Attended', 'method': 'qr'},
                action="Recorded attendance via QR as Attended"
            )

    attendance.refresh_from_db()

    if already_recorded:
        return render(request, 'meetings/qr_attendance_result.html', {
            'meeting': meeting,
            'attendance': attendance,
            'already_recorded': True,
            'message': f"Your attendance is already recorded as {attendance.status}.",
        })

    return render(request, 'meetings/qr_attendance_result.html', {
        'meeting': meeting,
        'attendance': attendance,
        'already_recorded': False,
        'message': "Your attendance has been successfully recorded as Attended.",
    })


@login_required
def sign_meeting(request, meeting_id):
    """Officer view to annotate and sign."""
    meeting = get_object_or_404(Meeting, id=meeting_id)
    if not user_in_department(request.user, meeting) or meeting.status != 'Finished':
        return HttpResponseForbidden()

    # 1. Verify the QR session token or HMAC token from the URL to ensure they scanned the QR
    qr_token = request.GET.get('token') or request.POST.get('token')
    timestamp = request.GET.get('t') or request.POST.get('t')
    received_sig = request.GET.get('sig') or request.POST.get('sig')

    qr_session = None

    if qr_token:
        qr_session = QRSession.objects.filter(token=qr_token, meeting=meeting).first()
        if not qr_session:
            return HttpResponseForbidden("Invalid QR code.")
        if qr_session.purpose != QRSession.PURPOSE_SIGNING:
            return HttpResponseForbidden("Attendance QR tokens cannot be used for signing.")
        if qr_session.is_revoked:
            return HttpResponseForbidden("This QR code has been revoked.")
        if qr_session.is_expired:
            return HttpResponseForbidden("This QR code has expired.")
    elif timestamp and received_sig:
        purpose_param = request.GET.get('purpose') or request.POST.get('purpose')
        if purpose_param == 'attendance':
            return HttpResponseForbidden("Attendance QR tokens cannot be used for signing.")

        try:
            ts = int(timestamp)
            now = int(time.time())
            token_age = now - ts
            if token_age < 0 or token_age > 3600:
                return HttpResponseForbidden("Invalid or expired QR code.")

            expected_sig = generate_hmac_qr_token(meeting_id, timestamp)
            expected_sig_signing = generate_hmac_qr_token(meeting_id, timestamp, purpose='signing')
            if not (hmac.compare_digest(expected_sig, received_sig) or hmac.compare_digest(expected_sig_signing, received_sig)):
                return HttpResponseForbidden("Invalid or expired QR code.")
        except (ValueError, TypeError):
            return HttpResponseForbidden("Invalid or expired QR code.")
    else:
        return HttpResponseForbidden("Missing security token.")

    # 2. Verify Officer is an assigned eligible signer for this meeting
    try:
        attendance = Attendance.objects.get(meeting=meeting, user=request.user)
    except Attendance.DoesNotExist:
        return HttpResponseForbidden("You are not an assigned eligible signer for this meeting.")

    if attendance.has_signed:
        return HttpResponseForbidden("You have already signed this document.")

    # 3. Attendance status eligibility check: only 'Attended' or 'Late' can sign
    if attendance.status not in ('Attended', 'Late'):
        return HttpResponseForbidden("Your attendance must be recorded as Attended or Late before you can sign.")

    if request.method == 'POST':
        annotation = request.POST.get('annotation', '')
        if len(annotation) > MAX_ANNOTATION_LENGTH:
            return HttpResponseBadRequest(
                f"Annotation exceeds maximum allowed length of {MAX_ANNOTATION_LENGTH} characters."
            )

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

        # Atomically persist the signature and audit record only if still unsigned and eligible.
        # This conditional update guarantees that concurrent requests or revoked attendance status cannot succeed.
        with transaction.atomic():
            lock_mutable_meetings([meeting.pk])
            if qr_session:
                # Acquire authorization after the Meeting guard and before Attendance.
                qr_session = QRSession.objects.select_for_update().filter(
                    pk=qr_session.pk, token=qr_token, meeting=meeting
                ).first()
                if not qr_session:
                    return HttpResponseForbidden("Invalid QR code.")
                if qr_session.purpose != QRSession.PURPOSE_SIGNING:
                    return HttpResponseForbidden("Attendance QR tokens cannot be used for signing.")
                if qr_session.is_revoked:
                    return HttpResponseForbidden("This QR code has been revoked.")
                if qr_session.is_expired:
                    return HttpResponseForbidden("This QR code has expired.")
            else:
                # The HMAC was authenticated above; recheck its age after waiting.
                token_age = int(time.time()) - ts
                if token_age < 0 or token_age > 3600:
                    return HttpResponseForbidden("Invalid or expired QR code.")
            updated = Attendance.objects.filter(
                pk=attendance.pk,
                has_signed=False,
                meeting__status='Finished',
                status__in=['Attended', 'Late']
            ).update(
                annotation=annotation,
                has_signed=True,
                cryptographic_signature=digital_sig,
                signed_at=timezone.now()
            )

            if updated == 0:
                current = Attendance.objects.filter(pk=attendance.pk).first()
                if current and current.has_signed:
                    return HttpResponseForbidden("You have already signed this document.")
                return HttpResponseForbidden("Your attendance must be recorded as Attended or Late before you can sign.")

            if qr_session:
                QRUsage.objects.get_or_create(qr_session=qr_session, user=request.user)

            AuditLog.objects.create(
                department=meeting.department,
                meeting=meeting,
                user=request.user,
                event_type='signature.created', target_type='attendance', target_id=str(attendance.pk), metadata={'attendance_id': attendance.pk, 'officer_id': attendance.user_id, 'signed_at': Attendance.objects.get(pk=attendance.pk).signed_at.isoformat(), 'annotation_included': bool(annotation)},
                action="Signed document with annotation"
            )
        messages.success(request, 'Your document signature was recorded successfully.')
        return workflow_redirect(request, 'department_dashboard', dept_id=meeting.department_id)

    form = SignMeetingForm()
    return render(request, 'meetings/sign_document.html', {
        'meeting': meeting,
        'attendance': attendance,
        'form': form,
        'qr_token': qr_token,
        'timestamp': timestamp,
        'sig': received_sig,
    })


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
                    event_type='meeting.created', target_type='meeting', target_id=str(meeting.pk), metadata={'participant_count': len(participants)},
                    action=f"Created meeting '{meeting.title[:50]}' with {len(participants)} assigned participant(s)"
                )

            messages.success(request, f"Meeting '{meeting.title}' created successfully.")
            return workflow_redirect(request, 'department_dashboard', dept_id=department.id)
    else:
        form = MeetingForm(department=department)

    return render(request, 'meetings/create_meeting.html', {
        'form': form,
        'department': department,
    })


@login_required
@transaction.atomic
def assign_participants(request, meeting_id):
    """
    Authorized Personnel manages participant/intended-signer assignments
    for an existing Draft meeting within their department.
    """
    meeting = get_object_or_404(Meeting.objects.select_for_update(), id=meeting_id)
    department = meeting.department

    # Server-side authorization check
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden("You are not authorized to manage participant assignments for this department.")

    # Integrity check: cannot alter assignments for finalized or locked documents
    if meeting.status != 'Draft':
        return HttpResponseForbidden("Cannot modify participant assignments for a locked or finalized meeting.")

    if request.method == 'POST':
        lock_mutable_meetings([meeting.pk])
        meeting.refresh_from_db()
        if meeting.status != 'Draft':
            return HttpResponseForbidden("Cannot modify participant assignments for a locked or finalized meeting.")
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
                removed_ids = set()
                for uid in to_remove:
                    att = current_attendances[uid]
                    if not att.has_signed:
                        att.delete()
                        removed_ids.add(uid)

                if to_add or removed_ids:
                    AuditLog.objects.create(
                        department=department,
                        meeting=meeting,
                        user=request.user,
                        event_type='meeting.participants_changed', target_type='meeting', target_id=str(meeting.pk), metadata={'added_ids': sorted(to_add), 'removed_ids': sorted(removed_ids), 'added_count': len(to_add), 'removed_count': len(removed_ids)},
                        action=f"Updated participant assignments for meeting '{meeting.title[:50]}'"
                    )

            if to_add or removed_ids:
                messages.success(request, "Participant assignments updated successfully.")
            else:
                messages.info(request, "Participant assignments are unchanged.")
            return workflow_redirect(request, 'department_dashboard', dept_id=department.id)
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
@transaction.atomic
def edit_meeting(request, meeting_id):
    """
    Authorized Personnel edits an existing Draft meeting within their authorized department.
    Enforces that finalized or locked meetings cannot be modified.
    """
    meeting = get_object_or_404(Meeting.objects.select_for_update(), id=meeting_id)
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
            updated_meeting = meeting
            if form.has_changed():
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
                        event_type='meeting.edited', target_type='meeting', target_id=str(meeting.pk), metadata={'changed_fields': sorted(form.changed_data)},
                        action=f"Edited draft meeting minutes for '{updated_meeting.title[:50]}'"
                    )
            if form.has_changed():
                messages.success(request, f"Meeting '{updated_meeting.title}' updated successfully.")
            else:
                messages.info(request, 'No changes to save.')
            return workflow_redirect(request, 'department_dashboard', dept_id=department.id)
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


@login_required
@transaction.atomic
def meeting_attendance(request, meeting_id):
    """
    Authorized Personnel views attendance records and assigned participants
    for a meeting within their authorized department.
    """
    meeting = get_object_or_404(Meeting, id=meeting_id)
    department = meeting.department

    # Server-side authorization check: Global Admin or AP of the department
    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden("You are not authorized to view or manage attendance for this department.")

    # Allow AP to update attendance status directly via POST if attendance_id and status are provided
    if request.method == 'POST':
        lock_mutable_meetings([meeting.pk])
        attendance_id = request.POST.get('attendance_id')
        attendance = get_object_or_404(Attendance.objects.select_for_update(), id=attendance_id, meeting=meeting)

        form = AttendanceStatusUpdateForm(request.POST)
        if not form.is_valid():
            return HttpResponseBadRequest("Invalid attendance status.")

        cleaned_status = form.cleaned_data['status']
        old_status = attendance.status
        if old_status != cleaned_status:
            attendance.status = cleaned_status
            attendance.status_updated_at = timezone.now()
            attendance.save(update_fields=['status', 'status_updated_at'])

            AuditLog.objects.create(
                department=department,
                meeting=meeting,
                user=request.user,
                event_type='attendance.changed', target_type='attendance', target_id=str(attendance.pk), metadata={'attendance_id': attendance.pk, 'officer_id': attendance.user_id, 'previous_status': old_status, 'new_status': cleaned_status, 'method': 'manual'},
                action=f"Changed attendance for {attendance.user.username} from {old_status} to {cleaned_status}"
            )
            messages.success(request, f"Updated attendance for {attendance.user.username} to {cleaned_status}.")
        return workflow_redirect(request, 'meeting_attendance', meeting_id=meeting.id)

    attendees = meeting.attendees.select_related('user').order_by('user__username')

    return render(request, 'meetings/attendance.html', {
        'meeting': meeting,
        'department': department,
        'attendees': attendees,
        'status_choices': Attendance.ATTENDANCE_STATUS_CHOICES,
    })


@login_required
@transaction.atomic
def update_attendance_status(request, meeting_id, attendance_id):
    """
    Dedicated endpoint for updating an attendee's attendance status.
    Requires POST. Server-side validation and audit logging enforced.
    """
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'], "Attendance status update requires a POST request.")

    meeting = get_object_or_404(Meeting, id=meeting_id)
    department = meeting.department

    if not is_global_admin(request.user) and not has_membership(request.user, department, role='AP'):
        return HttpResponseForbidden("You are not authorized to manage attendance for this department.")

    lock_mutable_meetings([meeting.pk])

    attendance = get_object_or_404(Attendance.objects.select_for_update(), id=attendance_id, meeting=meeting)

    form = AttendanceStatusUpdateForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest("Invalid attendance status.")

    new_status = form.cleaned_data['status']
    old_status = attendance.status

    if old_status != new_status:
        attendance.status = new_status
        attendance.status_updated_at = timezone.now()
        attendance.save(update_fields=['status', 'status_updated_at'])

        AuditLog.objects.create(
            department=department,
            meeting=meeting,
            user=request.user,
            event_type='attendance.changed', target_type='attendance', target_id=str(attendance.pk), metadata={'attendance_id': attendance.pk, 'officer_id': attendance.user_id, 'previous_status': old_status, 'new_status': new_status, 'method': 'manual'},
            action=f"Changed attendance for {attendance.user.username} from {old_status} to {new_status}"
        )
        messages.success(request, f"Updated attendance for {attendance.user.username} to {new_status}.")

    return workflow_redirect(request, 'meeting_attendance', meeting_id=meeting.id)


@login_required
def my_attendance(request, meeting_id):
    """
    Officer view to inspect their personal attendance record and status for a meeting.
    Officers cannot view other attendees' private details or edit records.
    """
    meeting = get_object_or_404(Meeting, id=meeting_id)
    department = meeting.department

    if not user_in_department(request.user, meeting):
        return HttpResponseForbidden("You do not belong to this department.")

    try:
        attendance = Attendance.objects.get(meeting=meeting, user=request.user)
    except Attendance.DoesNotExist:
        return HttpResponseForbidden("You are not an assigned participant for this meeting.")

    if request.method == 'POST':
        return HttpResponseForbidden("Officers are not permitted to modify attendance records.")

    return render(request, 'meetings/my_attendance.html', {
        'meeting': meeting,
        'department': department,
        'attendance': attendance,
    })


# ==============================================================================
# Batch 08 — Individual Signature Verification QR System
# ==============================================================================

def _verify_single_signature(attendance) -> dict:
    """Cryptographically verifies a single Attendance record's stored ECDSA signature.

    Returns safe metadata only — no private keys, raw tokens, or private annotations.
    Tries canonical meeting-bound format first, then falls back to legacy format.
    """
    meeting = attendance.meeting
    user = attendance.user

    if not attendance.has_signed or not attendance.cryptographic_signature:
        return {
            'valid': False,
            'format': None,
            'is_legacy': False,
            'meeting_bound': False,
            'reason': 'No signature on record for this attendance entry.',
        }

    if not user.public_key:
        return {
            'valid': False,
            'format': None,
            'is_legacy': False,
            'meeting_bound': False,
            'reason': 'Signer public key not found on record.',
        }

    return verify_attendance_signature(
        public_key_pem=user.public_key,
        meeting_id=meeting.id,
        department_id=meeting.department_id,
        title=meeting.title,
        minutes_content=meeting.minutes_content,
        annotation=attendance.annotation or '',
        signature_hex=attendance.cryptographic_signature,
    )


@login_required
def my_signature_verification_qr(request, meeting_id):
    """Officer view: view, generate, or regenerate personal signature verification QR code.

    Available only to the assigned Officer for their own signed Attendance record on a
    Finished or Archived meeting.
    Unauthorized users, unsigned records, and Draft meetings return 403.
    GET is strictly read-only: displays active QR if exists, or an empty state with Generate button.
    POST generates the QR (or regenerates a new QR, invalidating previous active ones).
    """
    if request.method not in ('GET', 'POST'):
        return HttpResponseNotAllowed(['GET', 'POST'])

    meeting = get_object_or_404(Meeting, id=meeting_id)

    # 1. Department membership check
    if not user_in_department(request.user, meeting):
        return HttpResponseForbidden("You do not belong to this department.")

    # 2. Status check: Only Finished or Archived meetings
    if meeting.status not in ('Finished', 'Archived'):
        return HttpResponseForbidden("Signature verification QR codes are only available for finalized meetings.")

    # 3. Attendance check: Must be assigned
    try:
        attendance = Attendance.objects.select_related('user', 'meeting', 'meeting__department').get(
            meeting=meeting, user=request.user
        )
    except Attendance.DoesNotExist:
        return HttpResponseForbidden("You are not an assigned participant for this meeting.")

    # 4. Signature check: Must have signed
    if not attendance.has_signed or not attendance.cryptographic_signature:
        return HttpResponseForbidden("You must sign this document before generating a signature verification QR code.")

    # POST: Serialize generation for this Attendance where row locks are supported.
    if request.method == 'POST':
        try:
            with transaction.atomic():
                attendance = Attendance.objects.select_for_update().get(pk=attendance.pk)
                if not attendance.has_signed or not attendance.cryptographic_signature:
                    return HttpResponseForbidden("You must sign this document before generating a signature verification QR code.")
                active_qr = VerificationQR.objects.filter(attendance=attendance, is_revoked=False).first()
                previous_qr_id = active_qr.pk if active_qr else None
                if active_qr:
                    active_qr.is_revoked = True
                    active_qr.revoked_at = timezone.now()
                    active_qr.revoked_by = request.user
                    active_qr.save(update_fields=['is_revoked', 'revoked_at', 'revoked_by'])

                raw_token = generate_verification_token()
                token_hash = hash_verification_token(raw_token)
                encrypted_token = encrypt_verification_token(raw_token)

                active_qr = VerificationQR.objects.create(
                    attendance=attendance,
                    token_hash=token_hash,
                    encrypted_token=encrypted_token,
                )

                AuditLog.objects.create(
                    department=meeting.department, meeting=meeting, user=request.user,
                    action='Regenerated signature verification QR code' if previous_qr_id else 'Generated signature verification QR code',
                    event_type='verification_qr.regenerated' if previous_qr_id else 'verification_qr.generated',
                    target_type='verification_qr', target_id=str(active_qr.pk),
                    metadata={'attendance_id': attendance.pk, 'verification_qr_id': active_qr.pk,
                              'previous_qr_id': previous_qr_id, 'replacement_qr_id': active_qr.pk},
                )

        except IntegrityError:
            # Roll back revocation as well as the failed replacement.
            messages.warning(request, "QR generation conflicted with another request. Please review your current QR code and retry if needed.")
        else:
            messages.success(request, "Your personal signature verification QR code has been generated.")
        return workflow_redirect(request, 'my_signature_verification_qr', meeting_id=meeting.id)

    # GET: strictly read-only
    active_qr = VerificationQR.objects.filter(attendance=attendance, is_revoked=False).first()
    raw_token = None
    if active_qr:
        try:
            raw_token = decrypt_verification_token(active_qr.encrypted_token)
        except Exception:
            raw_token = None

    public_url = None
    qr_image_b64 = None
    if raw_token:
        verify_path = reverse('verify_individual_signature')
        public_url = request.build_absolute_uri(f"{verify_path}?token={raw_token}")
        qr_image_b64 = _generate_qr_png_b64(public_url, scale=7)

    return render(request, 'meetings/verification_qr_display.html', {
        'meeting': meeting,
        'attendance': attendance,
        'verification_qr': active_qr,
        'public_url': public_url,
        'qr_image_b64': qr_image_b64,
        'signer': request.user,
    })


@login_required
@transaction.atomic
def revoke_my_signature_verification_qr(request, meeting_id):
    """Revoke personal verification QR code. POST-only action.

    Only the signing Officer may revoke their own QR.
    Does NOT revoke or alter the underlying ECDSA signature.
    """
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    meeting = get_object_or_404(Meeting, id=meeting_id)
    if not user_in_department(request.user, meeting):
        return HttpResponseForbidden("You do not belong to this department.")

    if meeting.status not in ('Finished', 'Archived'):
        return HttpResponseForbidden("Action permitted on finalized meetings only.")

    try:
        attendance = Attendance.objects.get(meeting=meeting, user=request.user)
    except Attendance.DoesNotExist:
        return HttpResponseForbidden("You are not an assigned participant for this meeting.")

    if not attendance.has_signed or not attendance.cryptographic_signature:
        return HttpResponseForbidden("You have not signed this document.")

    Attendance.objects.select_for_update().get(pk=attendance.pk)
    active_qr = VerificationQR.objects.filter(attendance=attendance, is_revoked=False).first()
    if not active_qr:
        messages.info(request, "No active verification QR code to revoke.")
        return workflow_redirect(request, 'my_signature_verification_qr', meeting_id=meeting.id)

    with transaction.atomic():
        active_qr.is_revoked = True
        active_qr.revoked_at = timezone.now()
        active_qr.revoked_by = request.user
        active_qr.save(update_fields=['is_revoked', 'revoked_at', 'revoked_by'])
        AuditLog.objects.create(
            department=meeting.department, meeting=meeting, user=request.user,
            action='Revoked signature verification QR code', event_type='verification_qr.revoked',
            target_type='verification_qr', target_id=str(active_qr.pk),
            metadata={'attendance_id': attendance.pk, 'verification_qr_id': active_qr.pk},
        )

    messages.warning(request, "Signature verification QR code has been revoked.")
    return workflow_redirect(request, 'my_signature_verification_qr', meeting_id=meeting.id)


def verify_individual_signature(request):
    """Public read-only verification endpoint for an individual Officer's signature.

    Does NOT require authentication.
    Does NOT mutate any database state (no audit logs, no scan records, no usage counts).
    Displays ONLY:
      - Meeting title
      - Department name
      - Document status
      - Signer display name
      - Signing timestamp
      - Signature verification result (canonical / legacy / invalid)
    For revoked or unsupported tokens/statuses, displays generic messages without revealing
    meeting, department, or signer metadata.
    Never exposes other attendees, full minutes, annotations, usernames, public/private keys, or tokens.
    """
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])

    raw_token = request.GET.get('token', '').strip()
    if not raw_token:
        return render(request, 'meetings/individual_signature_verification.html', {
            'status': 'invalid',
            'error_message': 'No verification token provided.',
        }, status=400)

    token_hash = hash_verification_token(raw_token)
    qr_obj = VerificationQR.objects.select_related(
        'attendance',
        'attendance__user',
        'attendance__meeting',
        'attendance__meeting__department'
    ).filter(token_hash=token_hash).first()

    if not qr_obj:
        return render(request, 'meetings/individual_signature_verification.html', {
            'status': 'invalid',
            'error_message': 'Invalid verification token. No matching signature record found.',
        }, status=404)

    if qr_obj.is_revoked:
        return render(request, 'meetings/individual_signature_verification.html', {
            'status': 'revoked',
            'error_message': 'This signature verification QR code has been revoked by the signer and can no longer be used for verification.',
        })

    meeting = qr_obj.attendance.meeting
    if meeting.status not in ('Finished', 'Archived'):
        return render(request, 'meetings/individual_signature_verification.html', {
            'status': 'unsupported',
            'error_message': 'This document is in an unsupported status and cannot be verified.',
        })

    attendance = qr_obj.attendance
    if not attendance.has_signed or not attendance.cryptographic_signature:
        return render(request, 'meetings/individual_signature_verification.html', {
            'status': 'invalid',
            'error_message': 'No signature record found for this participant.',
        }, status=404)

    sig_result = _verify_single_signature(attendance)
    signer = attendance.user
    signer_display = signer.get_full_name().strip() or 'Name not provided'

    return render(request, 'meetings/individual_signature_verification.html', {
        'status': 'valid' if sig_result.get('valid') else 'invalid',
        'meeting': meeting,
        'signer_display': signer_display,
        'signed_at': attendance.signed_at,
        'sig_result': sig_result,
    })


@login_required
def document_history(request, meeting_id):
    """Read-only audit timeline; never resolve membership through a dashboard."""
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    meeting = get_object_or_404(Meeting, pk=meeting_id)
    if not is_global_admin(request.user) and not has_membership(request.user, meeting.department, role='AP'):
        return HttpResponseForbidden('Not authorized to view document history.')
    events = AuditLog.objects.filter(meeting=meeting).select_related('user').order_by('-timestamp', '-pk')
    page = Paginator(events, 25).get_page(request.GET.get('page'))
    return render(request, 'meetings/document_history.html', {'meeting': meeting, 'page_obj': page})


@login_required
def export_meeting_pdf(request, meeting_id):
    """Offer a private full-document export; never finalize, archive or sign."""
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    from .pdf import capture_document, generate_meeting_pdf, TEMPLATE_VERSION
    from django.utils.text import slugify
    from django.utils.http import content_disposition_header

    meeting = get_object_or_404(Meeting, pk=meeting_id)
    if not is_global_admin(request.user) and not has_membership(request.user, meeting.department, role='AP'):
        return HttpResponseForbidden('Not authorized to export this document.')
    if meeting.status not in ('Finished', 'Archived'):
        return HttpResponseForbidden('Only finalized documents can be exported.')
    try:
        document = capture_document(meeting.pk)
    except Meeting.DoesNotExist:
        return HttpResponse('Document no longer exists.', status=404)
    if not is_global_admin(request.user) and not has_membership(request.user, Department(pk=document['department_id']), role='AP'):
        return HttpResponseForbidden('Not authorized to export this document.')
    try:
        pdf_bytes = generate_meeting_pdf(document)
    except Exception:
        return HttpResponse('PDF generation is unavailable.', status=503)
    # Required audit must succeed before any PDF bytes are returned.
    with transaction.atomic():
        AuditLog.objects.create(
            user=request.user, meeting=meeting, department_id=document['department_id'],
            action='Exported document as PDF', event_type='document.exported',
            target_type='meeting', target_id=str(meeting.pk),
            metadata={'format': 'PDF', 'export_scope': 'full_document',
                      'template_version': TEMPLATE_VERSION, 'lifecycle_status': document['status'],
                      'attendee_count': len(document['attendees'])},
        )
    filename = f"{slugify(document['title'])[:80] or 'meeting'}-{meeting.pk}.pdf"
    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = content_disposition_header(True, filename)
    response['Cache-Control'] = 'private, no-store, max-age=0'
    response['Pragma'] = 'no-cache'
    response['X-Content-Type-Options'] = 'nosniff'
    return response
