from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from accounts.invitation_delivery import eligible, process_one, validate_configuration
from accounts.models import InvitationDelivery


class Command(BaseCommand):
    help = 'Submit due invitation emails once; schedule regularly. At-least-once delivery.'

    def add_arguments(self, parser):
        parser.add_argument('--base-url', required=True, help='Trusted site origin, e.g. https://verimeet.example')
        parser.add_argument('--limit', type=int, default=100)

    def handle(self, *args, **options):
        if not 1 <= options['limit'] <= 1000:
            raise CommandError('limit must be between 1 and 1000')
        counts = dict.fromkeys(('submitted', 'retried', 'failed', 'cancelled', 'expired'), 0)
        try:
            validate_configuration(options['base_url'])
            ids = list(InvitationDelivery.objects.filter(eligible(timezone.now())).order_by('next_attempt_at', 'pk')
                       .values_list('pk', flat=True)[:options['limit']])
            for pk in ids:
                result = process_one(pk, options['base_url'])
                if result:
                    counts[result] += 1
        except Exception:
            raise CommandError('Invitation processor stopped due to an operational error; inspect configuration and database availability.') from None
        self.stdout.write(' '.join(f'{key}={value}' for key, value in counts.items()))
