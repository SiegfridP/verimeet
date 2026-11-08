from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db.models.signals import post_save
from django.dispatch import receiver
from .signatures import SignatureStorage
from .signature_guards import SignatureField, SignatureUserManager
from meetings.crypto import generate_ecdsa_keypair, encrypt_private_key  # Updated to include encryption helper

class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)
    contact_email = models.EmailField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class User(AbstractUser):
    session_version = models.PositiveBigIntegerField(default=0, editable=False)
    objects = SignatureUserManager()
    username_confirmation_required = models.BooleanField(default=False)
    signature_validation_hash = models.CharField(max_length=64, blank=True)
    signature_validated = models.BooleanField(default=False)
    # Multi-tenancy anchor (Nullable for the "Waiting Room" state)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    
    # Strict PNG requirement for signatures
    signature_image = SignatureField(
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

    def _get_session_auth_hash(self, secret=None):
        base = super()._get_session_auth_hash(secret=secret)
        if self.session_version == 0:
            return base  # Existing sessions remain compatible until revocation.
        from django.utils.crypto import salted_hmac
        return salted_hmac('accounts.session_version', f'{base}:{self.session_version}',
                           secret=secret, algorithm='sha256').hexdigest()

    def _do_update(self, base_qs, using, pk_val, values, update_fields, forced_update, *args, **kwargs):
        # Only the status service's locked internal update writes existing
        # activity/revocation state. Unrelated stale saves remain safe.
        values = [entry for entry in values if entry[0].name not in {'is_active', 'session_version'}]
        return super()._do_update(base_qs, using, pk_val, values, update_fields, forced_update, *args, **kwargs)

    def save(self, *args, **kwargs):
        from django.db import transaction
        from meetings.roster import lock_profile_names
        fields = kwargs.get('update_fields')
        using = kwargs.get('using') or self._state.db or 'default'
        if self._state.adding:
            # A supplied primary key does not make this an existing instance.
            # Never let insert fallback overwrite an existing account.
            kwargs['force_insert'] = True
            if self.department_id:
                from meetings.roster import lock_departments
                with transaction.atomic(using=using):
                    lock_departments([self.department_id], using)
                    return self._save_with_signature_guard(*args, **kwargs)
            return self._save_with_signature_guard(*args, **kwargs)
        names = {'first_name', 'last_name', 'department', 'department_id'}
        if self.pk and (fields is None or names.intersection(fields)):
            users = type(self).objects.using(using).filter(pk=self.pk)
            with transaction.atomic(using=using):
                frozen = lock_profile_names(users, using, [self.department_id])
                if not self._state.adding and not frozen.exists():
                    from django.core.exceptions import PermissionDenied
                    raise PermissionDenied('Profile no longer exists.')
                # A full stale instance still writes names: always serialize it.
                return self._save_with_signature_guard(*args, **kwargs)
        return self._save_with_signature_guard(*args, **kwargs)

    def _save_with_signature_guard(self, *args, **kwargs):
        from django.core.exceptions import PermissionDenied
        from django.db import transaction
        from django.db.models import F
        fields = kwargs.get('update_fields')
        if self.pk and (fields is None or 'signature_image' in fields):
            with transaction.atomic():
                type(self).objects.filter(pk=self.pk).update(username=F('username'))
                old = type(self).objects.filter(pk=self.pk).values_list('signature_image', flat=True).first()
                if old and (self.signature_image.name != old or not self.signature_image._committed):
                    raise PermissionDenied('Use the owner signature replacement service.')
                return super().save(*args, **kwargs)
        return super().save(*args, **kwargs)


class RetainedSignature(models.Model):
    import uuid
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    owner_identifier = models.CharField(max_length=64)
    storage_namespace = models.CharField(max_length=16)
    storage_identifier = models.CharField(max_length=255)
    superseded_at = models.DateTimeField()
    eligible_at = models.DateTimeField()
    content_sha256 = models.CharField(max_length=64, blank=True)
    file_size = models.PositiveBigIntegerField(null=True)
    state = models.CharField(max_length=16, default='retained')
    historical_hold = models.BooleanField(default=True)
    historical_association = models.CharField(max_length=16, default='unknown')
    source = models.CharField(max_length=16, default='owner')
    actor_identifier = models.CharField(max_length=64)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['owner_identifier', 'storage_namespace',
            'storage_identifier'], name='unique_signature_supersession')]

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

    def save(self, *args, **kwargs):
        from django.db import transaction
        from meetings.roster import lock_departments
        using = kwargs.get('using') or self._state.db or 'default'
        with transaction.atomic(using=using):
            from meetings.roster import lock_user_scope
            user_ids = [self.user_id]
            old = type(self).objects.using(using).filter(pk=self.pk).values('user_id','department_id','role').first() if self.pk else None
            departments = [self.department_id]
            if old:
                user_ids.append(old['user_id'])
                departments.append(old['department_id'])
            lock_user_scope(user_ids, using, departments)
            current = type(self).objects.using(using).filter(pk=self.pk).values('user_id','department_id','role').first() if self.pk else None
            if current != old:
                from django.core.exceptions import PermissionDenied
                raise PermissionDenied('Membership changed. Retry the entire operation.')
            return super().save(*args, **kwargs)

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


def verification_delivery_expiry():
    return timezone.now() + timedelta(days=3)


class VerificationEmailDelivery(models.Model):
    address = models.ForeignKey('account.EmailAddress', null=True, on_delete=models.SET_NULL)
    original_address_id = models.PositiveBigIntegerField()
    original_user_id = models.PositiveBigIntegerField()
    recipient = models.EmailField(max_length=254)
    session_version = models.PositiveBigIntegerField()
    signup = models.BooleanField(default=False)
    status = models.CharField(max_length=12, default='pending', choices=[(s, s) for s in
        ('pending', 'processing', 'submitted', 'failed', 'cancelled', 'expired')])
    attempts = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=verification_delivery_expiry)
    next_attempt_at = models.DateTimeField(default=timezone.now)
    last_attempt_at = models.DateTimeField(null=True)
    submitted_at = models.DateTimeField(null=True)
    claim_id = models.UUIDField(null=True, unique=True)
    lease_expires_at = models.DateTimeField(null=True)
    last_error = models.CharField(max_length=100, blank=True)

    class Meta:
        indexes = [models.Index(fields=['status', 'next_attempt_at'], name='verify_delivery_due'),
                   models.Index(fields=['status', 'lease_expires_at'], name='verify_delivery_lease')]
        constraints = [
            models.UniqueConstraint(fields=['original_address_id'], condition=models.Q(status__in=['pending', 'processing']), name='verify_one_active'),
            models.CheckConstraint(condition=(models.Q(status='processing', claim_id__isnull=False, lease_expires_at__isnull=False)
                | (~models.Q(status='processing') & models.Q(claim_id__isnull=True, lease_expires_at__isnull=True))), name='verify_claim_state')]


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
