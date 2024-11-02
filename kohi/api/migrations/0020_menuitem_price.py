# Generated by Django 5.1.1 on 2024-10-20 13:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0019_alter_coffeeshop_latitude_alter_coffeeshop_longitude"),
    ]

    operations = [
        migrations.AddField(
            model_name="menuitem",
            name="price",
            field=models.DecimalField(
                blank=True, decimal_places=2, max_digits=6, null=True
            ),
        ),
    ]
