# Generated by Django 5.1.5 on 2025-01-29 11:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_remove_customuser_totp_key_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='totp_key',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
    ]
