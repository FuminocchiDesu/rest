# Generated by Django 5.1.1 on 2024-11-24 13:42

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0033_alter_menuitem_description"),
    ]

    operations = [
        migrations.AddField(
            model_name="promo",
            name="has_specific_schedule",
            field=models.BooleanField(default=False),
        ),
        migrations.CreateModel(
            name="PromoSchedule",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "day_of_week",
                    models.IntegerField(
                        choices=[
                            (0, "Monday"),
                            (1, "Tuesday"),
                            (2, "Wednesday"),
                            (3, "Thursday"),
                            (4, "Friday"),
                            (5, "Saturday"),
                            (6, "Sunday"),
                        ]
                    ),
                ),
                ("start_time", models.TimeField()),
                ("end_time", models.TimeField()),
                (
                    "promo",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="schedules",
                        to="api.promo",
                    ),
                ),
            ],
            options={
                "ordering": ["day_of_week", "start_time"],
            },
        ),
    ]
