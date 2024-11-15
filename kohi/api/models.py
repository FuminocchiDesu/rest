from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db.models import Avg
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.utils import timezone
import uuid
from django.contrib.auth import get_user_model
from datetime import timedelta
from django.core.validators import RegexValidator

# Model to store reset codes
class PasswordResetCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        # Check if the code has expired (15 minutes)
        return timezone.now() > self.created_at + timedelta(minutes=15)

class PasswordResetAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    attempted_at = models.DateTimeField(auto_now_add=True)

    def is_today(self):
        return self.attempted_at.date() == timezone.now().date()

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
        max_digits=18,  # No more than 9 digits in total
        decimal_places=15,  # No more than 6 decimal places
        null=True,
        blank=True
    )
    longitude = models.DecimalField(
        max_digits=18,  # No more than 9 digits in total
        decimal_places=15,  # No more than 6 decimal places
        null=True,
        blank=True
    )
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='coffee_shops')
    is_owner = models.BooleanField(default=False)
    is_under_maintenance = models.BooleanField(default=False)
    is_terminated = models.BooleanField(default=False)
    dti_permit = models.FileField(upload_to='dti_permits/', blank=True, null=True)

    def __str__(self):
        return self.name

    def average_rating(self):
        return self.ratings.aggregate(Avg('stars'))['stars__avg'] or 0
User = get_user_model()

class ContactInformation(models.Model):
    coffee_shop = models.OneToOneField(
        CoffeeShop,
        on_delete=models.CASCADE,
        related_name='contact_info'
    )
    contact_name = models.CharField(max_length=100, blank=True, null=True)
    # Updated regex to make + optional
    phone_regex = RegexValidator(
        regex=r'^(?:\+)?(?:1)?\d{9,15}$',
        message="Phone number must be 9-15 digits. Can optionally start with '+'."
    )
    primary_phone = models.CharField(
        validators=[phone_regex],
        max_length=17,
        blank=True,
        null=True
    )
    secondary_phone = models.CharField(
        validators=[phone_regex],
        max_length=17,
        blank=True,
        null=True
    )
    email = models.EmailField(max_length=254, blank=True, null=True)
    website = models.URLField(max_length=200, blank=True, null=True)
    facebook = models.URLField(max_length=200, blank=True, null=True)
    instagram = models.URLField(max_length=200, blank=True, null=True)
    twitter = models.URLField(max_length=200, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Contact Info for {self.coffee_shop.name}"

    class Meta:
        verbose_name = "Contact Information"
        verbose_name_plural = "Contact Information"

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, default='')
    contact_number = models.CharField(max_length=20, blank=True, default='')
    full_name = models.CharField(max_length=100, blank=True, default='')
    profile_picture = models.ImageField(upload_to='profile_pictures/', default='profile_pictures/default.png')
    favorite_coffee_shops = models.ManyToManyField('CoffeeShop', related_name='favorited_by', blank=True)
    email_verified = models.BooleanField(default=False)
    verification_token = models.UUIDField(default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.user.username

    def get_profile_picture_url(self):
        if self.profile_picture:
            return f"{settings.MEDIA_URL}{self.profile_picture}"
        return f"{settings.MEDIA_URL}profile_pictures/default.png"

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
       instance.profile.save()

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
        ('approved', 'Approved'),
        ('flagged', 'Flagged for Review')
    ], default='approved')
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
    description = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='menu_items/', blank=True, null=True)  # Primary image
    is_available = models.BooleanField(default=True)
    price = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)

    def __str__(self):
        return f"{self.category.coffee_shop.name} - {self.category.name} - {self.name}"

class MenuItemImage(models.Model):
    menu_item = models.ForeignKey(MenuItem, on_delete=models.CASCADE, related_name='additional_images')
    image = models.ImageField(upload_to='menu_items/additional/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

class MenuItemSize(models.Model):
    menu_item = models.ForeignKey(MenuItem, related_name='sizes', on_delete=models.CASCADE)
    size = models.CharField(max_length=50)
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

class RatingToken(models.Model):
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    coffee_shop = models.ForeignKey(CoffeeShop, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_valid(self):
        return timezone.now() <= self.expires_at

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
