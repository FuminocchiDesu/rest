#backend/backend/urls.py
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from api.views import (
    RegisterUserView, CoffeeShopViewSet, CoffeeShopApplicationViewSet, 
    MenuCategoryViewSet, MenuItemViewSet, PromoViewSet, RatingViewSet, 
    BugReportViewSet, MyTokenObtainPairView, OwnerTokenObtainPairView,
    custom_login, UserProfileViewSet, UserProfileView
)
from django.conf import settings
from django.conf.urls.static import static

# Setting up the DefaultRouter
router = DefaultRouter()
router.register(r'coffee-shops', CoffeeShopViewSet)
router.register(r'applications', CoffeeShopApplicationViewSet)
router.register(r'bug-reports', BugReportViewSet)
router.register(r'users', UserProfileViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/login/', custom_login, name='login'),
    path('api/register/', RegisterUserView.as_view(), name='register'),
    path('api/owner/', OwnerTokenObtainPairView.as_view(), name='token_obtain_owner'),
    path('api/owner/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/profile/', UserProfileView.as_view(), name='user-profile'),

    # Updated URL patterns for coffee shop-specific data
    path('api/coffee-shops/<int:coffee_shop_id>/menu-categories/', MenuCategoryViewSet.as_view({'get': 'list', 'post': 'create'}), name='menu-category-list'),
    path('api/coffee-shops/<int:coffee_shop_id>/menu-categories/<int:pk>/', MenuCategoryViewSet.as_view({'put': 'update', 'delete': 'destroy'}), name='menu-category-detail'),
    
    path('api/coffee-shops/<int:coffee_shop_id>/menu-items/', MenuItemViewSet.as_view({'get': 'list', 'post': 'create'}), name='menu-item-list'),
    path('api/coffee-shops/<int:coffee_shop_id>/menu-items/<int:pk>/', MenuItemViewSet.as_view({'put': 'update', 'delete': 'destroy'}), name='menu-item-detail'),
    
    path('api/coffee-shops/<int:coffee_shop_id>/promos/', PromoViewSet.as_view({'get': 'list', 'post': 'create'}), name='promo-list'),
    path('api/coffee-shops/<int:coffee_shop_id>/promos/<int:pk>/', PromoViewSet.as_view({'put': 'update', 'delete': 'destroy'}), name='promo-detail'),
    
    path('api/coffee-shops/<int:coffee_shop_id>/ratings/', RatingViewSet.as_view({'get': 'list', 'post': 'create'}), name='rating-list'),
    
    # New URL patterns for managing favorite coffee shops
    path('api/users/favorite-coffee-shops/', UserProfileViewSet.as_view({'get': 'favorite_coffee_shops', 'post': 'add_favorite_coffee_shop', 'delete': 'remove_favorite_coffee_shop'}), name='favorite-coffee-shops'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)