from django.contrib import admin
from .models import CoffeeShop, CoffeeShopApplication, MenuCategory, MenuItem, Promo, Rating, BugReport, UserProfile, MenuItemSize, OpeningHour
from django import forms
from django.conf import settings

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'full_name', 'contact_number', 'bio', 'profile_picture')
    search_fields = ('user__username', 'full_name', 'contact_number')
    list_filter = ('user',)

class CoffeeShopAdminForm(forms.ModelForm):
    class Meta:
        model = CoffeeShop
        fields = ['name', 'address', 'description', 'latitude', 'longitude', 'image', 'owner', 'is_owner']

    class Media:
        js = (
            f'https://maps.googleapis.com/maps/api/js?key={settings.GOOGLE_MAPS_API_KEY}&libraries=places&callback=initMap&loading=async',
            'js/admin_gmaps.js',  # Update this path if necessary
        )

@admin.register(CoffeeShop)
class CoffeeShopAdmin(admin.ModelAdmin):
    form = CoffeeShopAdminForm
    list_display = ('name', 'address', 'owner', 'is_owner', 'latitude', 'longitude', 'image')
    search_fields = ('name', 'address')
    list_filter = ('owner',)

@admin.register(CoffeeShopApplication)
class CoffeeShopApplicationAdmin(admin.ModelAdmin):
    list_display = ('name', 'address', 'user', 'status', 'image')

@admin.register(MenuCategory)
class MenuCategoryAdmin(admin.ModelAdmin):
    list_display = ("coffee_shop", "name")

@admin.register(MenuItem)
class MenuItemAdmin(admin.ModelAdmin):
    list_display = ("category", "name", "description")

@admin.register(MenuItemSize)
class MenuItemSizeAdmin(admin.ModelAdmin):
    list_display = ("menu_item", "size", "price")

@admin.register(Promo)
class PromoAdmin(admin.ModelAdmin):
    list_display = ("coffee_shop", "name", "description", "start_date", "end_date")

@admin.register(Rating)
class RatingAdmin(admin.ModelAdmin):
    list_display = ("user", "coffee_shop", "stars", "description", "created_at")

@admin.register(BugReport)
class BugReportAdmin(admin.ModelAdmin):
    list_display = ("user", "description", "status", "created_at", "updated_at")

@admin.register(OpeningHour)
class OpeningHourAdmin(admin.ModelAdmin):
    list_display = ("coffee_shop", "day", "opening_time", "closing_time")
    list_filter = ("coffee_shop", "day")
    search_fields = ("coffee_shop__name",)