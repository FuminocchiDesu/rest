from django.contrib import admin
from .models import CoffeeShop, CoffeeShopApplication, MenuCategory, MenuItem, Promo, Rating, BugReport, UserProfile

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'full_name', 'contact_number', 'bio', 'profile_picture')
    search_fields = ('user__username', 'full_name', 'contact_number')
    list_filter = ('user',)
    
# Register your models here.
class CoffeeShopAdmin(admin.ModelAdmin):
    list_display = ('name', 'address', 'owner', 'is_owner', 'image')  # Remove 'image_url'

admin.site.register(CoffeeShop,CoffeeShopAdmin)

class CoffeeShopApplicationAdmin(admin.ModelAdmin):
    list_display = ('name', 'address', 'user', 'status', 'image')  # Remove 'image_url'

admin.site.register(CoffeeShopApplication,CoffeeShopApplicationAdmin)

class MenuCategoryAdmin(admin.ModelAdmin):
    list_display = ("coffee_shop","name")

admin.site.register(MenuCategory,MenuCategoryAdmin)

class MenuItemAdmin(admin.ModelAdmin):
    list_display = ("category","name","description","price")

admin.site.register(MenuItem,MenuItemAdmin)

class PromoAdmin(admin.ModelAdmin):
    list_display = ("coffee_shop","name","description","start_date","end_date")

admin.site.register(Promo,PromoAdmin)

class RatingAdmin(admin.ModelAdmin):
    list_display = ("user","coffee_shop","stars","description","created_at")

admin.site.register(Rating,RatingAdmin)

class BugReportAdmin(admin.ModelAdmin):
    list_display = ("STATUS_CHOICES","user","description","status","created_at","updated_at")

admin.site.register(BugReport,BugReportAdmin)


