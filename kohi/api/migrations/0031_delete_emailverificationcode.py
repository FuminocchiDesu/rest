# Generated by Django 5.1.1 on 2024-10-30 10:25

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0030_emailverificationcode"),
    ]

    operations = [
        migrations.DeleteModel(
            name="EmailVerificationCode",
        ),
    ]
