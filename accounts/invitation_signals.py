"""Retain delivery history when any ORM path deletes an invitation."""
from django.db.models.signals import pre_delete
from django.dispatch import receiver
from .models import Invitation, InvitationDelivery


@receiver(pre_delete, sender=Invitation, dispatch_uid='cancel_invitation_delivery')
def cancel_delivery(sender, instance, using, **kwargs):
    InvitationDelivery.objects.using(using).filter(invitation_id=instance.pk,
        status__in=('pending', 'processing')).update(status='cancelled', claim_id=None,
                                                    lease_expires_at=None)
