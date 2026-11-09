from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('meetings', '0009_historical_roster')]
    operations = [migrations.CreateModel(
        name='PrivateEvidenceObject',
        fields=[
            ('key', models.CharField(primary_key=True, max_length=255, serialize=False)),
            ('data', models.BinaryField(editable=False)),
            ('content_sha256', models.CharField(max_length=64, editable=False)),
            ('created_at', models.DateTimeField(auto_now_add=True)),
        ],
    )]
