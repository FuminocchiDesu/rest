#backend/api/views.py
from rest_framework import viewsets, generics, status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework_simplejwt.tokens import RefreshToken
#from rest_framework import status
from .models import CoffeeShop, CoffeeShopApplication, MenuCategory, MenuItem, Promo, Rating, BugReport, UserProfile, MenuItemSize, OpeningHour
from .serializers import (
    CoffeeShopSerializer, CoffeeShopApplicationSerializer, MenuCategorySerializer,
    MenuItemSerializer, PromoSerializer, RatingSerializer, BugReportSerializer,
    UserSerializer, UserProfileSerializer, SimpleCoffeeShopSerializer, MenuItemSizeSerializer, OpeningHourSerializer, PasswordResetSerializer, ChangePasswordSerializer
)
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
import logging
import traceback
from django.db import transaction
from rest_framework.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.db.models import F
from django.db.models.functions import ACos, Sin, Cos, Radians
from django.shortcuts import get_object_or_404
import logging
import traceback
from django.db import connection
from django.contrib.auth import update_session_auth_hash

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if not user.check_password(serializer.validated_data['old_password']):
                return Response({"old_password": "Wrong password."}, status=status.HTTP_400_BAD_REQUEST)

            # Set new password
            user.set_password(serializer.validated_data['new_password'])
            user.save()

            # Update session to prevent logout
            update_session_auth_hash(request, user)

            return Response({"detail": "Password updated successfully."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileViewSet(viewsets.ModelViewSet):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    #permission_classes = [IsAuthenticated]
    @action(detail=False, methods=['get'])
    def favorite_coffee_shops(self, request):
        user = request.user
        favorite_shops = user.profile.favorite_coffee_shops.all()
        serializer = SimpleCoffeeShopSerializer(favorite_shops, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def add_favorite_coffee_shop(self, request):
        user = request.user
        coffee_shop_id = request.data.get('coffee_shop_id')
        try:
            coffee_shop = CoffeeShop.objects.get(id=coffee_shop_id)
            user.profile.favorite_coffee_shops.add(coffee_shop)
            return Response({'status': 'Coffee shop added to favorites'}, status=status.HTTP_200_OK)
        except CoffeeShop.DoesNotExist:
            return Response({'error': 'Coffee shop not found'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['delete'])
    def remove_favorite_coffee_shop(self, request):
        user = request.user
        coffee_shop_id = request.data.get('coffee_shop_id')
        try:
            coffee_shop = CoffeeShop.objects.get(id=coffee_shop_id)
            user.profile.favorite_coffee_shops.remove(coffee_shop)
            return Response({'status': 'Coffee shop removed from favorites'}, status=status.HTTP_200_OK)
        except CoffeeShop.DoesNotExist:
            return Response({'error': 'Coffee shop not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def custom_login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    if not username or not password:
        return Response({'error': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)
    if user is not None:
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {'username': user.username, 'email': user.email}
        })
    return Response({'error': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request):
        serializer = UserProfileSerializer(request.user.profile, context={'request': request})
        return Response(serializer.data)

    def put(self, request):
        serializer = UserProfileSerializer(request.user.profile, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OwnerTokenObtainPairView(TokenObtainPairView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        user = User.objects.get(username=request.data['username'])
        if not user.is_staff:
            return Response({"detail": "Not authorized"}, status=403)

        # Get the owner's coffee shop
        coffee_shop = CoffeeShop.objects.filter(owner=user).first()
        if coffee_shop:
            response.data['coffee_shop_id'] = coffee_shop.id

        return response

class MyTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        return response

@csrf_exempt
def custom_token_obtain_pair(request, *args, **kwargs):
    return MyTokenObtainPairView.as_view()(request, *args, **kwargs)

@transaction.atomic
def create(self, validated_data):
    profile_data = validated_data.pop('profile', {})
    try:
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        UserProfile.objects.create(user=user, **profile_data)
    except IntegrityError as e:
        logger.error(f"IntegrityError creating user: {str(e)}")
        raise ValidationError(f"A user with this username or email already exists: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        logger.error(traceback.format_exc())
        raise ValidationError(f"An error occurred during user creation: {str(e)}")

    return user

logger = logging.getLogger(__name__)


class RegisterUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            try:
                user = serializer.save()
                refresh = RefreshToken.for_user(user)
                response_data = {
                    'user': UserSerializer(user, context={'request': request}).data,
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
                return Response(response_data, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Unexpected error during user registration: {str(e)}")
                logger.error(traceback.format_exc())
                return Response({'error': f'An unexpected error occurred during registration: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CoffeeShopViewSet(viewsets.ModelViewSet):
    queryset = CoffeeShop.objects.all()
    serializer_class = CoffeeShopSerializer
    parser_classes = (MultiPartParser, FormParser)
    #permission_classes = [IsAuthenticated]
    # Nearby coffee shops based on user location
    @action(detail=False, methods=['get'])
    def nearby(self, request):
        latitude = float(request.query_params.get('latitude', 0))
        longitude = float(request.query_params.get('longitude', 0))
        radius_km = float(request.query_params.get('radius_km', 5))

        # Simple Haversine formula-based distance calculation
        nearby_shops = CoffeeShop.objects.annotate(
            distance=ACos(
                Sin(Radians(latitude)) * Sin(Radians(F('latitude'))) +
                Cos(Radians(latitude)) * Cos(Radians(F('latitude'))) *
                Cos(Radians(F('longitude')) - Radians(longitude))
            ) * 6371  # Earth radius in km
        ).filter(distance__lt=radius_km)

        serializer = self.get_serializer(nearby_shops, many=True)
        return Response(serializer.data)
    @api_view(['GET'])
    def coffee_shops_list(request):
        try:
            coffee_shops = CoffeeShop.objects.all()
            # Serialize the coffee shops
            serializer = CoffeeShopSerializer(coffee_shops, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    # Update location for a specific coffee shop
    @action(detail=True, methods=['patch'])
    def update_location(self, request, pk=None):
        coffee_shop = self.get_object()
        latitude = request.data.get('latitude')
        longitude = request.data.get('longitude')

        if latitude and longitude:
            coffee_shop.latitude = latitude
            coffee_shop.longitude = longitude
            coffee_shop.save()
            return Response({'status': 'location updated'})
        return Response({'status': 'invalid coordinates'}, status=status.HTTP_400_BAD_REQUEST)
    @action(detail=True, methods=['post'])
    def rate(self, request, pk=None):
        coffee_shop = self.get_object()
        stars = request.data.get('stars')
        description = request.data.get('description', '')
        if stars is not None:
            Rating.objects.update_or_create(
                user=request.user,
                coffee_shop=coffee_shop,
                defaults={'stars': stars, 'description': description}
            )
            return Response({'status': 'rating set'})
        return Response({'status': 'stars not provided'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def owner_coffee_shops(self, request):
        shops = CoffeeShop.objects.filter(owner=request.user)
        serializer = self.get_serializer(shops, many=True)
        return Response(serializer.data)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

class CoffeeShopApplicationViewSet(viewsets.ModelViewSet):
    queryset = CoffeeShopApplication.objects.all()
    serializer_class = CoffeeShopApplicationSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class MenuItemViewSet(viewsets.ModelViewSet):
    serializer_class = MenuItemSerializer
    parser_classes = (MultiPartParser, FormParser)

    def get_queryset(self):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        return MenuItem.objects.filter(category__coffee_shop_id=coffee_shop_id)

    def create(self, request, *args, **kwargs):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        category_id = request.data.get('category')

        try:
            category = MenuCategory.objects.get(id=category_id, coffee_shop_id=coffee_shop_id)
        except MenuCategory.DoesNotExist:
            return Response({"error": "Invalid category for this coffee shop"}, status=status.HTTP_400_BAD_REQUEST)

        request.data['category'] = category.id  # Ensure category ID is included in request data

        # Ensure sizes are included in the request data
        sizes_data = request.data.get('sizes', [])
        if not sizes_data:
            return Response({"error": "At least one size must be provided."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        menu_item = serializer.save(category=category)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class MenuCategoryViewSet(viewsets.ModelViewSet):
    serializer_class = MenuCategorySerializer
    #permission_classes = [IsAuthenticated]

    def get_queryset(self):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        return MenuCategory.objects.filter(coffee_shop_id=coffee_shop_id).prefetch_related('items')

    def create(self, request, *args, **kwargs):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')

        try:
            coffee_shop = CoffeeShop.objects.get(id=coffee_shop_id)
        except CoffeeShop.DoesNotExist:
            return Response({"error": "Invalid coffee shop"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(coffee_shop=coffee_shop)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class PromoViewSet(viewsets.ModelViewSet):
    serializer_class = PromoSerializer
    #permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get_queryset(self):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        return Promo.objects.filter(coffee_shop_id=coffee_shop_id)

    def create(self, request, *args, **kwargs):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')

        try:
            coffee_shop = CoffeeShop.objects.get(id=coffee_shop_id)
        except CoffeeShop.DoesNotExist:
            return Response({"error": "Invalid coffee shop"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(coffee_shop=coffee_shop)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class RatingViewSet(viewsets.ModelViewSet):
    serializer_class = RatingSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        return Rating.objects.filter(coffee_shop_id=coffee_shop_id)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def user_rating(self, request, coffee_shop_id):
        rating = self.queryset.filter(coffee_shop_id=coffee_shop_id, user=request.user).first()
        if rating:
            serializer = self.get_serializer(rating)
            return Response(serializer.data)
        return Response({"detail": "No rating found"}, status=status.HTTP_404_NOT_FOUND)

class BugReportViewSet(viewsets.ModelViewSet):
    queryset = BugReport.objects.all()
    serializer_class = BugReportSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=False, methods=['get'])
    def my_reports(self, request):
        reports = BugReport.objects.filter(user=request.user)
        serializer = self.get_serializer(reports, many=True)
        return Response(serializer.data)

class OpeningHourViewSet(viewsets.ModelViewSet):
    queryset = OpeningHour.objects.all()
    serializer_class = OpeningHourSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        coffee_shop = CoffeeShop.objects.get(owner=self.request.user)
        serializer.save(coffee_shop=coffee_shop)

class CoffeeShopDetailViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CoffeeShop.objects.all()
    serializer_class = CoffeeShopSerializer

    def get_coffee_shop_detail(self, instance):
        serializer = self.get_serializer(instance)

        menu_categories = MenuCategory.objects.filter(coffee_shop=instance).prefetch_related('items')
        promos = Promo.objects.filter(coffee_shop=instance)
        ratings = Rating.objects.filter(coffee_shop=instance)
        opening_hours = OpeningHour.objects.filter(coffee_shop=instance)

        return {
            **serializer.data,
            'menu_categories': MenuCategorySerializer(menu_categories, many=True, context={'request': self.request}).data,
            'promos': PromoSerializer(promos, many=True, context={'request': self.request}).data,
            'ratings': RatingSerializer(ratings, many=True).data,
            'opening_hours': OpeningHourSerializer(opening_hours, many=True).data,
        }

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        coffee_shops = [self.get_coffee_shop_detail(shop) for shop in queryset]
        return Response(coffee_shops)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        return Response(self.get_coffee_shop_detail(instance))

class CoffeeShopDetailView(generics.RetrieveAPIView):
    queryset = CoffeeShop.objects.all()
    serializer_class = CoffeeShopSerializer

    def get(self, request, *args, **kwargs):
        coffee_shop = self.get_object()
        serializer = self.get_serializer(coffee_shop)

        # Fetch related data
        menu_categories = MenuCategory.objects.filter(coffee_shop=coffee_shop).prefetch_related('items')
        promos = Promo.objects.filter(coffee_shop=coffee_shop)
        ratings = Rating.objects.filter(coffee_shop=coffee_shop)
        opening_hours = OpeningHour.objects.filter(coffee_shop=coffee_shop)

        # Add latitude and longitude to the response
        return Response({
            'coffee_shop': {
                **serializer.data,
                'latitude': coffee_shop.latitude,
                'longitude': coffee_shop.longitude,
            },
            'menu_categories': MenuCategorySerializer(menu_categories, many=True, context={'request': request}).data,
            'promos': PromoSerializer(promos, many=True, context={'request': request}).data,
            'ratings': RatingSerializer(ratings, many=True).data,
            'opening_hours': OpeningHourSerializer(opening_hours, many=True, context={'request': request}).data,  # Add this line
        })

