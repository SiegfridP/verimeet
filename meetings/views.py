import hmac
from accounts.views import is_global_admin, has_membership
import time
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, HttpResponse
from django.utils import timezone
from .models import Meeting, Attendance, AuditLog
from .crypto import generate_hmac_qr_token, sign_document_data
from accounts.models import Membership

def user_in_department(user, meeting):
    return user.department == meeting.department

@login_required
def authorized_personnel_dashboard(request):
    # Authorized Personnel can view meetings for their department
    if not request.user.is_authenticated:
        return HttpResponseForbidden()
    # Determine department via membership
    try:
        membership = Membership.objects.get(user=request.user, department=request.user.department)
    except Membership.DoesNotExist:
        return HttpResponseForbidden()
    if membership.role != 'AP':
        return HttpResponseForbidden()
    department = membership.department
    meetings = Meeting.objects.filter(department=department)
    return render(request, 'meetings/authorized_personnel_dashboard.html', {'department': department, 'meetings': meetings})

@login_required
def student_dashboard(request):
    # Only show meetings the student has been assigned to attend
    attendances = Attendance.objects.filter(user=request.user, meeting__department=request.user.department)
    return render(request, 'meetings/student_dashboard.html', {'attendances': attendances})

@login_required
def lock_meeting(request, meeting_id):
    """Admin changes state from Draft to Finished."""
    meeting = get_object_or_404(Meeting, id=meeting_id)
    if not has_membership(request.user, meeting.department, role='AP'):
        return HttpResponseForbidden()
    
    if meeting.status == 'Draft':
        meeting.status = 'Finished'
        meeting.save()
        AuditLog.objects.create(
            department=meeting.department, meeting=meeting, user=request.user,
            action="Locked document for signing"
        )
    return redirect('authorized_personnel_dashboard')

@login_required
def projector_qr_view(request, meeting_id):
    """Displays the QR code for the projector."""
    meeting = get_object_or_404(Meeting, id=meeting_id)
    if not has_membership(request.user, meeting.department, role='AP') or meeting.status != 'Finished':
        return HttpResponseForbidden()
    
    timestamp = str(int(time.time()))
    sig = generate_hmac_qr_token(meeting_id, timestamp)
    
    # The URL the QR code will point to
    signing_url = f"{request.scheme}://{request.get_host()}/meetings/{meeting_id}/sign/?t={timestamp}&sig={sig}"
    
    return render(request, 'meetings/qr_projector.html', {'signing_url': signing_url})

@login_required
def sign_meeting(request, meeting_id):
    """Student view to annotate and sign."""
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

    # 2. Get the attendance record
    attendance, created = Attendance.objects.get_or_create(meeting=meeting, user=request.user)
    
    if request.method == 'POST':
        annotation = request.POST.get('annotation', '')
        
        # Core Cryptography: Combine minutes and annotation for the hash payload
        payload_to_hash = f"{meeting.minutes_content}\n---ANNOTATION---\n{annotation}"
        
        # Sign it with the user's private key
        digital_sig = sign_document_data(request.user.private_key, payload_to_hash)
        
        # Update database
        attendance.annotation = annotation
        attendance.has_signed = True
        attendance.cryptographic_signature = digital_sig
        attendance.signed_at = timezone.now()
        attendance.save()
        
        AuditLog.objects.create(
            department=meeting.department, meeting=meeting, user=request.user,
            action=f"Signed document with annotation"
        )
        return redirect('student_dashboard')

    return render(request, 'meetings/sign_document.html', {'meeting': meeting})