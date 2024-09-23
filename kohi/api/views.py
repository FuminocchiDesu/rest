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
from .models import CoffeeShop, CoffeeShopApplication, MenuCategory, MenuItem, Promo, Rating, BugReport, UserProfile
from .serializers import (
    CoffeeShopSerializer, CoffeeShopApplicationSerializer, MenuCategorySerializer,
    MenuItemSerializer, PromoSerializer, RatingSerializer, BugReportSerializer,
    UserSerializer, UserProfileSerializer, SimpleCoffeeShopSerializer
)
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
import logging
import traceback
from django.db import transaction
from rest_framework.exceptions import ValidationError
from django.db.utils import IntegrityError

class UserProfileViewSet(viewsets.ModelViewSet):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer

    @action(detail=False, methods=['get'])
    def favorite_coffee_shops(self, request):
        user_profile = request.user.profile
        favorite_shops = user_profile.favorite_coffee_shops.all()
        serializer = SimpleCoffeeShopSerializer(favorite_shops, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def add_favorite_coffee_shop(self, request):
        user_profile = request.user.profile
        coffee_shop_id = request.data.get('coffee_shop_id')
        try:
            coffee_shop = CoffeeShop.objects.get(id=coffee_shop_id)
            user_profile.favorite_coffee_shops.add(coffee_shop)
            return Response({'status': 'coffee shop added to favorites'})
        except CoffeeShop.DoesNotExist:
            return Response({'error': 'coffee shop not found'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['delete'])
    def remove_favorite_coffee_shop(self, request):
        user_profile = request.user.profile
        coffee_shop_id = request.data.get('coffee_shop_id')
        try:
            coffee_shop = CoffeeShop.objects.get(id=coffee_shop_id)
            user_profile.favorite_coffee_shops.remove(coffee_shop)
            return Response({'status': 'coffee shop removed from favorites'})
        except CoffeeShop.DoesNotExist:
            return Response({'error': 'coffee shop not found'}, status=status.HTTP_404_NOT_FOUND)

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
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

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
    permission_classes = [IsAuthenticated]
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

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(category=category)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class MenuCategoryViewSet(viewsets.ModelViewSet):
    serializer_class = MenuCategorySerializer
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]
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

class CoffeeShopDetailView(generics.RetrieveAPIView):
    queryset = CoffeeShop.objects.all()
    serializer_class = CoffeeShopSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        coffee_shop = self.get_object()
        serializer = self.get_serializer(coffee_shop)

        # Fetch related data
        menu_categories = MenuCategory.objects.filter(coffee_shop=coffee_shop).prefetch_related('items')
        promos = Promo.objects.filter(coffee_shop=coffee_shop)
        ratings = Rating.objects.filter(coffee_shop=coffee_shop)

        return Response({
            'coffee_shop': serializer.data,
            'menu_categories': MenuCategorySerializer(menu_categories, many=True).data,
            'promos': PromoSerializer(promos, many=True).data,
            'ratings': RatingSerializer(ratings, many=True).data,
        })
