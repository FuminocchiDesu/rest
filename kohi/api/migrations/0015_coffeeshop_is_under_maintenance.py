# Generated by Django 5.1.1 on 2024-10-18 11:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0014_ratingtoken"),
    ]

    operations = [
        migrations.AddField(
            model_name="coffeeshop",
            name="is_under_maintenance",
            field=models.BooleanField(default=False),
        ),
    ]
