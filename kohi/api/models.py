from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db.models import Avg
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.utils import timezone

class Visit(models.Model):
    coffee_shop = models.ForeignKey('CoffeeShop', on_delete=models.CASCADE)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Visit to {self.coffee_shop.name} at {self.timestamp}"

class CoffeeShop(models.Model):
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    description = models.TextField()
    image = models.ImageField(upload_to='coffee_shops/', blank=True, null=True)
    latitude = models.DecimalField(
        max_digits=12,  # No more than 9 digits in total
        decimal_places=9,  # No more than 6 decimal places
        null=True,
        blank=True
    )
    longitude = models.DecimalField(
        max_digits=12,  # No more than 9 digits in total
        decimal_places=9,  # No more than 6 decimal places
        null=True,
        blank=True
    )
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='coffee_shops')
    is_owner = models.BooleanField(default=False)

    def __str__(self):
        return self.name

    def average_rating(self):
        return self.ratings.aggregate(Avg('stars'))['stars__avg'] or 0

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, default='')
    contact_number = models.CharField(max_length=20, blank=True, default='')
    full_name = models.CharField(max_length=100, blank=True, default='')
    profile_picture = models.ImageField(upload_to='profile_pictures/', default='profile_pictures/default.png')
    favorite_coffee_shops = models.ManyToManyField(CoffeeShop, related_name='favorited_by', blank=True)

    def __str__(self):
        return self.user.username

    def get_profile_picture_url(self):
        if self.profile_picture:
            return f"{settings.MEDIA_URL}{self.profile_picture}"
        return f"{settings.MEDIA_URL}profile_pictures/default.png"



class OpeningHour(models.Model):
    DAY_CHOICES = [
        ('mon', 'Monday'),
        ('tue', 'Tuesday'),
        ('wed', 'Wednesday'),
        ('thu', 'Thursday'),
        ('fri', 'Friday'),
        ('sat', 'Saturday'),
        ('sun', 'Sunday'),
    ]

    coffee_shop = models.ForeignKey(CoffeeShop, on_delete=models.CASCADE, related_name='opening_hours')
    day = models.CharField(max_length=3, choices=DAY_CHOICES)
    opening_time = models.TimeField()
    closing_time = models.TimeField()

    def __str__(self):
        return f"{self.coffee_shop.name} - {self.get_day_display()}"

class CoffeeShopApplication(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    description = models.TextField()
    image = models.ImageField(upload_to='applications/', blank=True, null=True)
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ], default='pending')
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)

    def __str__(self):
        return f"{self.name} - {self.status}"


class MenuCategory(models.Model):
    coffee_shop = models.ForeignKey(CoffeeShop, on_delete=models.CASCADE, related_name='menu_categories')
    name = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.coffee_shop.name} - {self.name}"

class MenuItem(models.Model):
    category = models.ForeignKey(MenuCategory, on_delete=models.CASCADE, related_name='items')
    name = models.CharField(max_length=100)
    description = models.TextField()
    image = models.ImageField(upload_to='menu_items/', blank=True, null=True)

    def __str__(self):
        return f"{self.category.coffee_shop.name} - {self.category.name} - {self.name}"

class MenuItemSize(models.Model):
    menu_item = models.ForeignKey(MenuItem, related_name='sizes', on_delete=models.CASCADE)
    size = models.CharField(max_length=50)  # e.g., Small, Medium, Large
    price = models.DecimalField(max_digits=6, decimal_places=2)

    def __str__(self):
        return f"{self.menu_item.name} - {self.size}: ₱{self.price}"


class Promo(models.Model):
    coffee_shop = models.ForeignKey(CoffeeShop, on_delete=models.CASCADE, related_name='promos')
    name = models.CharField(max_length=100)
    description = models.TextField()
    start_date = models.DateField()
    end_date = models.DateField()
    image = models.ImageField(upload_to='promos/', blank=True, null=True)

    def __str__(self):
        return f"{self.coffee_shop.name} - {self.name}"

class Rating(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    coffee_shop = models.ForeignKey(CoffeeShop, on_delete=models.CASCADE, related_name='ratings')
    stars = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'coffee_shop')

    def __str__(self):
        return f"{self.user.username}'s {self.stars}-star rating for {self.coffee_shop.name}"

class BugReport(models.Model):
    STATUS_CHOICES = [
        ('new', 'New'),
        ('in_process', 'In Process'),
        ('fixed', 'Fixed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Bug Report by {self.user.username} - {self.status}"


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()