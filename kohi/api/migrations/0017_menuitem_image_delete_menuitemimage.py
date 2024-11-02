# Generated by Django 5.1.1 on 2024-10-18 13:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0016_remove_menuitem_image_menuitem_is_available_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="menuitem",
            name="image",
            field=models.ImageField(blank=True, null=True, upload_to="menu_items/"),
        ),
        migrations.DeleteModel(
            name="MenuItemImage",
        ),
    ]
