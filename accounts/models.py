from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db.models.signals import post_save
from django.dispatch import receiver
from meetings.crypto import generate_ecdsa_keypair  # We will create this in the meetings app

class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)
    contact_email = models.EmailField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class User(AbstractUser):
    # Multi-tenancy anchor (Nullable for the "Waiting Room" state)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    
    # Strict PNG requirement for signatures
    signature_image = models.ImageField(
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
        instance.private_key = priv_pem
        instance.public_key = pub_pem
        instance.save()