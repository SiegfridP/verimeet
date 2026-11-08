from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from accounts.models import VerificationEmailDelivery
from accounts.verification_delivery import eligible, process_one, validate_configuration


class Command(BaseCommand):
    help = 'Submit bounded due verification emails; schedule regularly.'

    def add_arguments(self, parser):
        parser.add_argument('--base-url', required=True)
        parser.add_argument('--limit', type=int, default=100)

    def handle(self, *args, **options):
        if not 1 <= options['limit'] <= 1000:
            raise CommandError('limit must be between 1 and 1000')
        counts = dict.fromkeys(('submitted', 'retried', 'failed', 'cancelled', 'expired'), 0)
        try:
            validate_configuration(options['base_url'])
            ids = list(VerificationEmailDelivery.objects.filter(eligible(timezone.now()))
                .order_by('next_attempt_at', 'pk').values_list('pk', flat=True)[:options['limit']])
            for pk in ids:
                result = process_one(pk, options['base_url'])
                if result:
                    counts[result] += 1
        except Exception:
            raise CommandError('Verification processor stopped; check configuration and database availability.') from None
        self.stdout.write(' '.join(f'{key}={value}' for key, value in counts.items()))
