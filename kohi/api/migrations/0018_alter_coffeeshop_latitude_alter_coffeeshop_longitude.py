# Generated by Django 5.1.1 on 2024-10-20 10:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0017_menuitem_image_delete_menuitemimage"),
    ]

    operations = [
        migrations.AlterField(
            model_name="coffeeshop",
            name="latitude",
            field=models.DecimalField(
                blank=True, decimal_places=9, max_digits=18, null=True
            ),
        ),
        migrations.AlterField(
            model_name="coffeeshop",
            name="longitude",
            field=models.DecimalField(
                blank=True, decimal_places=9, max_digits=18, null=True
            ),
        ),
    ]