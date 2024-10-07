#backend/api/views.py
from rest_framework import viewsets, generics, status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
#from rest_framework import status
from .models import (CoffeeShop, CoffeeShopApplication, MenuCategory, MenuItem, Promo, Rating,
                    BugReport, UserProfile, MenuItemSize, OpeningHour, Visit)
from .serializers import (
    CoffeeShopSerializer, CoffeeShopApplicationSerializer, MenuCategorySerializer,
    MenuItemSerializer, PromoSerializer, RatingSerializer, BugReportSerializer,
    UserSerializer, UserProfileSerializer, SimpleCoffeeShopSerializer, MenuItemSizeSerializer,
    OpeningHourSerializer, ChangePasswordSerializer, VerifyPasswordSerializer
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
from rest_framework.response import Response
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import update_session_auth_hash
from django.db.models import F, ExpressionWrapper, FloatField
from django.db.models.functions import Power, Sqrt

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_password(request):
    serializer = VerifyPasswordSerializer(data=request.data)
    if serializer.is_valid():
        user = request.user
        if user.check_password(serializer.data.get('old_password')):
            return Response({'isValid': True}, status=status.HTTP_200_OK)
        return Response({'isValid': False, 'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    serializer = ChangePasswordSerializer(data=request.data)
    if serializer.is_valid():
        user = request.user
        user.set_password(serializer.data.get('new_password'))
        user.save()
        update_session_auth_hash(request, user)  # To keep the user logged in after password change
        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_data(request):
    # Assuming the authenticated user is the owner of the coffee shop
    coffee_shop = request.user.coffee_shops.first()

    if not coffee_shop:
        return Response({"error": "No coffee shop found for this user"}, status=400)

    # Get visits data for the last 30 days
    thirty_days_ago = timezone.now() - timedelta(days=30)
    visits_data = coffee_shop.visit_set.filter(timestamp__gte=thirty_days_ago) \
        .extra(select={'date': 'DATE(timestamp)'}) \
        .values('date') \
        .annotate(visits=Count('id')) \
        .order_by('date')

    # Get favorite count
    favorite_count = coffee_shop.favorited_by.count()

    # Get recent reviews
    recent_reviews = coffee_shop.ratings.order_by('-created_at')[:3]

    return Response({
        "visits_data": list(visits_data),
        "favorite_count": favorite_count,
        "recent_reviews": [
            {
                "content": review.description,
                "author": review.user.username,
                "rating": review.stars
            } for review in recent_reviews
        ]
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def record_visit(request):
    coffee_shop_id = request.data.get('coffee_shop_id')
    try:
        coffee_shop = CoffeeShop.objects.get(id=coffee_shop_id)
        Visit.objects.create(coffee_shop=coffee_shop, timestamp=timezone.now())
        return Response({'status': 'Visit recorded successfully'}, status=201)
    except CoffeeShop.DoesNotExist:
        return Response({'error': 'Coffee shop not found'}, status=404)

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

logger = logging.getLogger(__name__)

class NearbyCoffeeShopViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CoffeeShopSerializer

    def get_queryset(self):
        latitude = self.request.query_params.get('latitude')
        longitude = self.request.query_params.get('longitude')
        radius = float(self.request.query_params.get('radius', 5000))  # Default 5km radius

        if latitude and longitude:
            lat = float(latitude)
            lon = float(longitude)

            # Log the input parameters
            logger.info(f"Searching for coffee shops near lat: {lat}, lon: {lon}, radius: {radius}m")

            # Calculate distance using Haversine formula
            queryset = CoffeeShop.objects.annotate(
                distance=ExpressionWrapper(
                    6371 * Sqrt(
                        Power(F('latitude') - lat, 2) +
                        Power((F('longitude') - lon) * Sqrt(Power(F('latitude'), 2) + Power(lat, 2)), 2)
                    ) * 1000,  # Convert to meters
                    output_field=FloatField()
                )
            ).filter(distance__lte=radius)

            # Log the number of shops found and their details
            shops = list(queryset.order_by('distance'))
            logger.info(f"Found {len(shops)} shops within {radius}m:")
            for shop in shops:
                logger.info(f"  - {shop.name}: {shop.distance:.2f}m")

            return shops
        return CoffeeShop.objects.none()

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            if not queryset:
                logger.warning("No nearby coffee shops found")
                return Response([], status=status.HTTP_200_OK)

            serializer = self.get_serializer(queryset, many=True)
            data = serializer.data
            for item in data:
                item['distance'] = float(item['distance'])  # Ensure distance is a float

            logger.info(f"Returning {len(data)} coffee shops")
            return Response(data)
        except Exception as e:
            logger.exception(f"Error in NearbyCoffeeShopViewSet: {str(e)}")
            return Response({"error": "An error occurred while fetching nearby coffee shops"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CoffeeShopDetailViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CoffeeShop.objects.all()
    serializer_class = CoffeeShopSerializer

    def get_coffee_shop_detail(self, instance):
        try:
            serializer = self.get_serializer(instance)
            menu_categories = MenuCategory.objects.filter(coffee_shop=instance).prefetch_related('items')
            promos = Promo.objects.filter(coffee_shop=instance)
            ratings = Rating.objects.filter(coffee_shop=instance)
            opening_hours = OpeningHour.objects.filter(coffee_shop=instance)

            data = {
                **serializer.data,
                'menu_categories': MenuCategorySerializer(menu_categories, many=True, context={'request': self.request}).data,
                'promos': PromoSerializer(promos, many=True, context={'request': self.request}).data,
                'ratings': RatingSerializer(ratings, many=True).data,
                'opening_hours': OpeningHourSerializer(opening_hours, many=True).data,
            }

            if hasattr(instance, 'distance'):
                data['distance'] = instance.distance.km

            return data
        except Exception as e:
            logger.error(f"Error in get_coffee_shop_detail: {str(e)}", exc_info=True)
            raise

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.filter_queryset(self.get_queryset())
            coffee_shops = [self.get_coffee_shop_detail(shop) for shop in queryset]
            return Response(coffee_shops)
        except Exception as e:
            logger.error(f"Error in list: {str(e)}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            return Response(self.get_coffee_shop_detail(instance))
        except Exception as e:
            logger.error(f"Error in retrieve: {str(e)}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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

