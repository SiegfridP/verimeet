from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from accounts.models import RetainedSignature


class Command(BaseCommand):
    help = 'Read-only metadata inspection. Age eligibility is not deletion authorization.'

    def add_arguments(self, parser):
        parser.add_argument('--limit', type=int, default=100)
        parser.add_argument('--after', help='Exclusive record UUID cursor')

    def handle(self, *args, **options):
        if not 1 <= options['limit'] <= 1000:
            raise CommandError('limit must be 1..1000')
        rows = RetainedSignature.objects.order_by('pk')
        if options['after']:
            from uuid import UUID
            try:
                cursor = UUID(options['after'])
            except ValueError:
                raise CommandError('Invalid cursor') from None
            rows = rows.filter(pk__gt=cursor)
        count = 0
        for row in rows[:options['limit']]:
            self.stdout.write(f'{row.pk} state={row.state} held={row.historical_hold} age_eligible={row.eligible_at <= timezone.now()} association={row.historical_association}')
            count += 1
        self.stdout.write(f'Inspected {count}. Metadata only; file existence unverified. Physical deletion disabled.')
