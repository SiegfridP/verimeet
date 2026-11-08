from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from allauth.account.models import EmailAddress
from .models import User, VerificationEmailDelivery
from .verification_delivery import cancel


@receiver(post_save, sender=EmailAddress)
def address_changed(sender, instance, **kwargs):
    rows = VerificationEmailDelivery.objects.filter(original_address_id=instance.pk)
    if instance.verified:
        cancel(rows)
    else:
        cancel(rows.exclude(original_user_id=instance.user_id, recipient=instance.email))


@receiver(pre_delete, sender=EmailAddress)
def address_removed(sender, instance, **kwargs):
    cancel(VerificationEmailDelivery.objects.filter(original_address_id=instance.pk))


@receiver(pre_delete, sender=User)
def user_removed(sender, instance, **kwargs):
    cancel(VerificationEmailDelivery.objects.filter(original_user_id=instance.pk))
