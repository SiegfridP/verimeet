# Generated for Batch 08 — Individual Signature Verification QR

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('meetings', '0004_qrsession_token_max_length_128'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='VerificationQR',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token_hash', models.CharField(db_index=True, max_length=64, unique=True)),
                ('encrypted_token', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_revoked', models.BooleanField(default=False)),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('attendance', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='verification_qrs',
                    to='meetings.attendance',
                )),
                ('revoked_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='revoked_verification_qrs',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-created_at'],
                'constraints': [
                    models.UniqueConstraint(
                        condition=models.Q(is_revoked=False),
                        fields=('attendance',),
                        name='unique_active_verification_qr_per_attendance',
                    ),
                ],
            },
        ),
    ]
