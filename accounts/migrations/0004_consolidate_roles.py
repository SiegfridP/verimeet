from django.db import migrations

def forward_consolidate_roles(apps, schema_editor):
    db_alias = schema_editor.connection.alias
    Membership = apps.get_model('accounts', 'Membership')
    Invitation = apps.get_model('accounts', 'Invitation')

    # Consolidate legacy Student ('S') role to canonical Officer ('O')
    Membership.objects.using(db_alias).filter(role='S').update(role='O')
    Invitation.objects.using(db_alias).filter(role='S').update(role='O')

def backward_consolidate_roles(apps, schema_editor):
    # VeriMeet has exactly three roles (Global Admin, Authorized Personnel, Officer).
    # Student is not a separate role. Rollback leaves canonical Officer ('O') intact
    # to avoid re-introducing deprecated 'S' records.
    pass

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_alter_invitation_token'),
    ]

    operations = [
        migrations.RunPython(forward_consolidate_roles, backward_consolidate_roles),
    ]
