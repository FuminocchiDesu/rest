# Generated by Django 5.1.1 on 2024-10-08 11:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0009_visit"),
    ]

    operations = [
        migrations.AlterField(
            model_name="coffeeshopapplication",
            name="status",
            field=models.CharField(
                choices=[("approved", "Approved"), ("flagged", "Flagged for Review")],
                default="approved",
                max_length=20,
            ),
        ),
    ]
