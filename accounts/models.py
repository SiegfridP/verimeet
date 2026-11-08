from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db.models.signals import post_save
from django.dispatch import receiver
from .signatures import SignatureStorage
from meetings.crypto import generate_ecdsa_keypair, encrypt_private_key  # Updated to include encryption helper

class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)
    contact_email = models.EmailField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class User(AbstractUser):
    username_confirmation_required = models.BooleanField(default=False)
    signature_validation_hash = models.CharField(max_length=64, blank=True)
    signature_validated = models.BooleanField(default=False)
    # Multi-tenancy anchor (Nullable for the "Waiting Room" state)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    
    # Strict PNG requirement for signatures
    signature_image = models.ImageField(
        storage=SignatureStorage(),
        upload_to='signatures/',
        validators=[FileExtensionValidator(allowed_extensions=['png'])],
        null=True, blank=True,
        help_text="Upload a transparent PNG of your signature."
    )
    
    # Cryptographic Keys (Auto-generated on account creation)
    public_key = models.TextField(blank=True, null=True)
    private_key = models.TextField(blank=True, null=True) # *Must be encrypted at rest in production*

    def __str__(self):
        return self.email or self.username

# Auto-generate ECDSA keys when a new user is created
@receiver(post_save, sender=User)
def create_user_keys(sender, instance, created, **kwargs):
    if created and not instance.public_key:
        priv_pem, pub_pem = generate_ecdsa_keypair()
        encrypted_priv = encrypt_private_key(priv_pem)

        # Save the encrypted private key and public key without
        # triggering another post_save signal.
        User.objects.filter(pk=instance.pk).update(
            private_key=encrypted_priv,
            public_key=pub_pem,
        )

        # Keep the in-memory instance consistent.
        instance.private_key = encrypted_priv
        instance.public_key = pub_pem

    # Legacy department is readable; user saves never create memberships.

# ====================
# RBAC / Multi‑tenancy models
# ====================

class Membership(models.Model):
    ROLE_CHOICES = [
        ('AP', 'Authorized Personnel'),
        ('O', 'Officer'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='memberships')
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(max_length=2, choices=ROLE_CHOICES, default='O')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'department')

    def __str__(self):
        return f"{self.user.email or self.user.username} – {self.department.name} ({self.get_role_display()})"

import uuid
from django.utils import timezone
from datetime import timedelta

# Helper for Invitation expiry – must be a top‑level callable so migrations can serialize it
def default_invitation_expiry():
    return timezone.now() + timedelta(days=7)

def generate_invitation_token():
    return uuid.uuid4().hex

class Invitation(models.Model):
    email = models.EmailField()
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='invitations')
    inviter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invitations')
    token = models.CharField(max_length=64, unique=True, default=generate_invitation_token)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=default_invitation_expiry)
    accepted = models.BooleanField(default=False)
    accepted_at = models.DateTimeField(null=True, blank=True)
    # Invitations grant Officer membership in the department.
    role = models.CharField(max_length=2, choices=[('O', 'Officer')], default='O')

    def is_valid(self):
        return not self.accepted and timezone.now() < self.expires_at

    def __str__(self):
        return f"Invitation for {self.email} to {self.department.name}"

class RoleElevationRequest(models.Model):
    STATUS_CHOICES = [
        ('P', 'Pending'),
        ('A', 'Approved'),
        ('R', 'Rejected'),
    ]
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='elevation_requests')
    target_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='elevation_requests')
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name='made_elevation_requests')
    status = models.CharField(max_length=1, choices=STATUS_CHOICES, default='P')
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewer = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='reviewed_elevation_requests')
    note = models.TextField(blank=True)

    class Meta:
        unique_together = ('department', 'target_user')

    def __str__(self):
        return f"Elevation request for {self.target_user.email} in {self.department.name} – {self.get_status_display()}"


class InvitationDelivery(models.Model):
    STATUS_CHOICES = [(value, value.title()) for value in
                      ('pending', 'processing', 'submitted', 'failed', 'cancelled', 'expired')]
    invitation = models.OneToOneField(Invitation, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='delivery')
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default='pending')
    attempts = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    next_attempt_at = models.DateTimeField(default=timezone.now)
    submitted_at = models.DateTimeField(null=True, blank=True)
    claim_id = models.UUIDField(null=True, blank=True, unique=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=100, blank=True)

    class Meta:
        indexes = [models.Index(fields=['status', 'next_attempt_at'], name='invite_delivery_due'),
                   models.Index(fields=['status', 'lease_expires_at'], name='invite_delivery_lease')]
        constraints = [models.CheckConstraint(condition=(
            models.Q(status='processing', claim_id__isnull=False, lease_expires_at__isnull=False)
            | (~models.Q(status='processing') & models.Q(claim_id__isnull=True, lease_expires_at__isnull=True))
        ), name='invite_delivery_claim_state')]
