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
from .models import (CoffeeShop, CoffeeShopApplication, MenuCategory, MenuItem, Promo, Rating, RatingToken, MenuItemImage,
                    BugReport, UserProfile, MenuItemSize, OpeningHour, Visit, PasswordResetCode, PasswordResetAttempt, ContactInformation)
from .serializers import (
    CoffeeShopSerializer, MenuCategorySerializer, CoffeeShopApplicationSerializer,
    MenuItemSerializer, PromoSerializer, RatingSerializer, BugReportSerializer, PasswordResetSerializer, ContactInformationSerializer,
    UserSerializer, UserProfileSerializer, SimpleCoffeeShopSerializer, MenuItemSizeSerializer, RatingTokenSerializer,
    OpeningHourSerializer, ChangePasswordSerializer, VerifyPasswordSerializer, UserRegistrationSerializer, MenuItemImageSerializer, UpdateEmailSerializer,
    UpdateUsernameSerializer)
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
import logging
import traceback
from django.db import transaction
from rest_framework.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.db.models import F
from django.db.models.functions import ACos, Sin, Cos, Radians
from django.db.models import Count, Avg
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import update_session_auth_hash
from django.db.models import ExpressionWrapper, FloatField
from django.shortcuts import get_object_or_404
import json
from django.core.mail import send_mail, EmailMessage
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from anymail.message import AnymailMessage
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.shortcuts import render
from django.http import JsonResponse
import random
import string
import qrcode
import io
from django.http import HttpResponse
from django.core.files.storage import default_storage
import os
import PyPDF2
from better_profanity import profanity
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth
import calendar

def censor_bad_words(text, censor_char='*'):
    if not text:
        return text
    try:
        # Add custom local/regional profanities
        custom_bad_words = [
            'putangina', 'tangina', 'tarantado', 'tarantada', 'gago', 'gaga',
            'ulol', 'leche', 'lintik', 'buwisit', 'animal', 'punyeta',
            'hudas', 'yawa', 'bwakanangina', 'bwesit', 'tanga', 'bobo',
            'inutil', 'amputa', 'kupal', 'ungas', 'tarantado', 'tanginamo',
            'putragis', 'peste', 'hayop', 'gunggong', 'bwisit', 'kagaguhan',
            'katangahan', 'tarantismado', 'tarantismada', 'hinayupak', 'lintek',
            'buang', 'yabag', 'kampret', 'demonyo', 'ulupong', 'walanghiya',
            'putres', 'hudas ka', 'lapastangan'
        ]

        # Load default profanities
        profanity.load_censor_words()

        # Add custom words to the existing profanity list
        profanity.add_censor_words(custom_bad_words)

        # Censor the text
        return profanity.censor(text, censor_char)
    except Exception as e:
        print(f"Error in censor_bad_words: {e}")
        return text

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

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_email(request):
    serializer = UpdateEmailSerializer(data=request.data)
    if serializer.is_valid():
        user = request.user
        user.email = serializer.data.get('new_email')
        user.save()
        return Response({'message': 'Email updated successfully.'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_username(request):
    serializer = UpdateUsernameSerializer(data=request.data)
    if serializer.is_valid():
        user = request.user
        user.username = serializer.data.get('new_username')
        user.save()
        return Response({'message': 'Username updated successfully.'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def get_date_range_and_annotate(start_date=None, end_date=None):
    now = timezone.now()

    # If no start date provided, default to current month's first day
    if start_date is None:
        start_date = timezone.datetime(now.year, now.month, 1)

    # If no end date provided, default to current month's last day
    if end_date is None:
        _, last_day = calendar.monthrange(now.year, now.month)
        end_date = timezone.datetime(now.year, now.month, last_day)

    return {
        'start_date': start_date,
        'end_date': end_date,
        'annotation': TruncDay('timestamp'),
        'group_by': ['day']
    }

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def visits_data(request):
    coffee_shop = request.user.coffee_shops.first()
    if not coffee_shop:
        return Response({"error": "No coffee shop found for this user"}, status=400)

    # Get start and end dates from query params
    start_date_str = request.GET.get('start_date')
    end_date_str = request.GET.get('end_date')

    start_date = timezone.datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
    end_date = timezone.datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None

    # Get date configuration
    date_config = get_date_range_and_annotate(
        start_date=start_date,
        end_date=end_date
    )

    # Base query
    visits_query = coffee_shop.visit_set.filter(
        timestamp__gte=date_config['start_date'],
        timestamp__lte=date_config['end_date']
    )

    # Annotate and aggregate
    visits_data = visits_query.annotate(
        period=TruncDay('timestamp')
    ).values('period').annotate(
        visits=Count('id')
    ).order_by('period')

    return Response({
        "visits_data": list(visits_data)
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def reviews_data(request):
    coffee_shop = request.user.coffee_shops.first()
    if not coffee_shop:
        return Response({"error": "No coffee shop found for this user"}, status=400)

    # Get start and end dates from query params
    start_date_str = request.GET.get('start_date')
    end_date_str = request.GET.get('end_date')

    start_date = timezone.datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
    end_date = timezone.datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None

    # Get date configuration
    date_config = get_date_range_and_annotate(
        start_date=start_date,
        end_date=end_date
    )

    # Base query
    reviews_query = coffee_shop.ratings.filter(
        created_at__gte=date_config['start_date'],
        created_at__lte=date_config['end_date']
    )

    # Annotate and aggregate
    reviews_data = reviews_query.annotate(
        period=TruncDay('created_at')
    ).values('period').annotate(
        average_rating=Avg('stars'),
        review_count=Count('id')
    ).order_by('period')

    # Recent reviews (independent of filter)
    recent_reviews = coffee_shop.ratings.order_by('-created_at')[:3]

    return Response({
        "reviews_data": list(reviews_data),
        "recent_reviews": [
            {
                "content": censor_bad_words(review.description),  # Censor description here
                "author": review.user.username,
                "rating": review.stars
            } for review in recent_reviews
        ]
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_data(request):
    coffee_shop = request.user.coffee_shops.first()
    if not coffee_shop:
        return Response({"error": "No coffee shop found for this user"}, status=400)

    # Get favorite count and users who favorited
    favorite_users = coffee_shop.favorited_by.all().select_related('user')
    favorite_users_data = [{
        'username': profile.user.username,
        'full_name': profile.full_name,
        'profile_picture': profile.get_profile_picture_url()
    } for profile in favorite_users]

    return Response({
        "favorite_count": len(favorite_users_data),
        "favorite_users": favorite_users_data
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
    permission_classes = [IsAuthenticated]
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
    # Accept either username or email
    login_identifier = request.data.get('login_identifier')
    password = request.data.get('password')

    if not login_identifier or not password:
        return Response({'error': 'Login identifier and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Try to authenticate with username or email
    user = None
    if '@' in login_identifier:
        # If the identifier contains '@', try to authenticate with email
        try:
            user_obj = User.objects.get(email=login_identifier)
            user = authenticate(username=user_obj.username, password=password)
        except User.DoesNotExist:
            user = None
    else:
        # Otherwise, try to authenticate with username
        user = authenticate(username=login_identifier, password=password)

    if user is not None:
        if not user.is_active or not user.profile.email_verified:
            return Response({'error': 'Please verify your email before logging in.'}, status=status.HTTP_400_BAD_REQUEST)

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
        profile = request.user.profile
        old_image_path = None

        # Store the old image path if it exists and is not the default
        if profile.profile_picture and hasattr(profile.profile_picture, 'name'):
            if not profile.profile_picture.name.endswith('default.png'):
                old_image_path = profile.profile_picture.path

        serializer = UserProfileSerializer(profile, data=request.data, partial=True, context={'request': request})

        if serializer.is_valid():
            if 'profile_picture' in request.FILES:
                # Save new image
                serializer.validated_data['profile_picture'] = request.FILES['profile_picture']
                # Delete old image if it exists and is not default
                if old_image_path and os.path.exists(old_image_path):
                    try:
                        os.remove(old_image_path)
                    except Exception as e:
                        # Log the error but don't stop the update process
                        print(f"Error deleting old profile picture: {e}")

            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OwnerTokenObtainPairView(TokenObtainPairView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        # Try to find user by username or email
        login_input = request.data.get('username', '')
        password = request.data.get('password', '')

        # First try to find by username
        user = User.objects.filter(username=login_input).first()

        # If not found, try by email
        if not user:
            user = User.objects.filter(email=login_input).first()

        # If no user found, return error
        if not user:
            return Response({"detail": "Invalid credentials"}, status=401)

        # Validate password
        if not user.check_password(password):
            return Response({"detail": "Invalid credentials"}, status=401)

        # Check if user is staff
        if not user.is_staff:
            return Response({"detail": "Not authorized"}, status=403)

        # Proceed with token generation
        serializer = self.get_serializer(data={'username': user.username, 'password': password})
        serializer.is_valid(raise_exception=True)

        # Get response with tokens
        response = Response(serializer.validated_data)

        # Add coffee shop ID if exists
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

@api_view(['GET'])
def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True  # Assuming you set user to inactive initially
        user.profile.email_verified = True  # Update email verification status
        user.save()
        user.profile.save()  # Save the profile to ensure changes are persisted
        return render(request, 'verification_success.html')  # Render the success template
    else:
        return Response({'error': 'Verification link is invalid or has expired.'}, status=status.HTTP_400_BAD_REQUEST)

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
                # Send verification email
                self.send_verification_email(user, request)

                # Generate tokens
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

    def send_verification_email(self, user, request):
        token = generate_verification_token(user)  # Implement token generation
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verification_link = request.build_absolute_uri(
            reverse('verify_email', kwargs={'uidb64': uid, 'token': token})
        )

        subject = 'Activate Your Account'
        message = render_to_string('email_verification.html', {
            'user': user,
            'verification_link': verification_link,
        })

        email = AnymailMessage(subject, message, to=[user.email])
        email.send()
def generate_verification_token(user):
    # Implement your token generation logic here
    # For example, using Django's built-in token generation methods
    return default_token_generator.make_token(user)

@csrf_exempt
def password_reset_request(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email_or_username = data.get('email_or_username')

            if not email_or_username:
                return JsonResponse({"error": "Email or username is required."}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format."}, status=400)

        # Try to retrieve the user by email or username
        try:
            user = User.objects.get(email=email_or_username)
        except User.DoesNotExist:
            try:
                user = User.objects.get(username=email_or_username)
            except User.DoesNotExist:
                return JsonResponse({"error": "User with this email/username does not exist."}, status=400)

        # Check the number of attempts today
        today_attempts = PasswordResetAttempt.objects.filter(user=user, attempted_at__date=timezone.now().date()).count()
        if today_attempts >= 3:
            return JsonResponse({"error": "Maximum password reset attempts reached for today."}, status=429)

        # Delete any previous reset code for the user
        PasswordResetCode.objects.filter(user=user).delete()

        # Generate a 6-digit verification code
        code = ''.join(random.choices(string.digits, k=6))

        # Save the code in the database
        PasswordResetCode.objects.create(user=user, code=code)

        # Save the attempt
        PasswordResetAttempt.objects.create(user=user)

        # Prepare email using the template
        subject = 'Password Reset Code'
        message = render_to_string('password_reset_email.html', {
            'reset_code': code,
            'user': user,
        })

        # Send email
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
            return JsonResponse({"error": f"Error sending email: {str(e)}"}, status=500)

        return JsonResponse({"success": "Password reset code sent."})

    return JsonResponse({"error": "Invalid request method."}, status=405)

@csrf_exempt
def verify_reset_code(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email_or_username = data.get('email_or_username')
            reset_code = data.get('reset_code')  # Change to reset_code for consistency

            if not email_or_username or not reset_code:
                return JsonResponse({"error": "Email/username and reset code are required."}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format."}, status=400)

        # Try to retrieve the user by email or username
        try:
            user = User.objects.get(email=email_or_username)
        except User.DoesNotExist:
            try:
                user = User.objects.get(username=email_or_username)
            except User.DoesNotExist:
                return JsonResponse({"error": "User with this email/username does not exist."}, status=400)

        # Retrieve the code for this user
        try:
            reset_code_obj = PasswordResetCode.objects.get(user=user, code=reset_code)
            if reset_code_obj.is_expired():
                return JsonResponse({"error": "The reset code has expired."}, status=400)
        except PasswordResetCode.DoesNotExist:
            return JsonResponse({"error": "Invalid reset code."}, status=400)

        # Code is valid; allow user to proceed with resetting their password
        return JsonResponse({"success": "Code verified. You may reset your password."})

    return JsonResponse({"error": "Invalid request method."}, status=405)

@api_view(['POST'])
def reset_password(request):
    email_or_username = request.data.get('email_or_username')
    new_password = request.data.get('new_password')
    reset_code_value = request.data.get('code')

    # Validate email or username
    try:
        user = User.objects.get(email=email_or_username)
    except User.DoesNotExist:
        try:
            user = User.objects.get(username=email_or_username)
        except User.DoesNotExist:
            return Response({'error': "User with this email/username does not exist."},
                            status=status.HTTP_400_BAD_REQUEST)

    # Validate reset code
    try:
        reset_code = PasswordResetCode.objects.get(user=user, code=reset_code_value)
        if reset_code.is_expired():
            return Response({'error': "The code has expired."},
                            status=status.HTTP_400_BAD_REQUEST)
    except PasswordResetCode.DoesNotExist:
        return Response({'error': "Invalid code."}, status=status.HTTP_400_BAD_REQUEST)

    # Check password length
    if len(new_password) < 8:
        return Response({'error': "Password must be at least 8 characters long."},
                        status=status.HTTP_400_BAD_REQUEST)

    # Reset the password
    user.set_password(new_password)
    user.save()

    # Delete the reset code
    reset_code.delete()

    return Response({'success': 'Password reset successfully'}, status=status.HTTP_200_OK)

logger = logging.getLogger(__name__)

class CoffeeShopViewSet(viewsets.ModelViewSet):
    queryset = CoffeeShop.objects.all()
    serializer_class = CoffeeShopSerializer
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        try:
            # Validate required fields
            required_fields = ['name', 'address', 'description', 'latitude', 'longitude']
            for field in required_fields:
                if field not in request.data:
                    return Response(
                        {"error": f"{field} is required"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            serializer = self.get_serializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    {"error": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate DTI permit
            dti_permit = request.FILES.get('dti_permit')
            if not dti_permit:
                return Response(
                    {"error": "DTI permit is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not dti_permit.content_type == 'application/pdf':
                return Response(
                    {"error": "DTI permit must be a PDF file"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Process DTI permit
            try:
                file_copy = io.BytesIO(dti_permit.read())
                dti_permit.seek(0)
                pdf_reader = PyPDF2.PdfReader(file_copy)
                pdf_text = ''
                for page in pdf_reader.pages:
                    pdf_text += page.extract_text()

                if not verify_dti_permit(pdf_text):
                    return Response(
                        {"error": "Invalid DTI permit"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except Exception as e:
                logger.error(f"DTI permit processing error: {str(e)}")
                return Response(
                    {"error": "Error processing DTI permit"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create coffee shop
            coffee_shop = serializer.save(
                owner=request.user,
                is_owner=True,
                is_under_maintenance=False,
                is_terminated=False
            )

            # Update user status
            request.user.is_staff = True
            request.user.save()

            # Send welcome email
            try:
                send_welcome_email(request.user, coffee_shop)
            except Exception as e:
                logger.error(f"Failed to send welcome email: {str(e)}")

            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
                headers=self.get_success_headers(serializer.data)
            )

        except Exception as e:
            logger.error(f"Unexpected error in coffee shop creation: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_queryset(self):
        return CoffeeShop.objects.filter(owner=self.request.user)

    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def generate_qr(self, request, pk=None):
        coffee_shop = self.get_object()
        duration = request.query_params.get('duration', '1d')  # Get duration from query params

        # Convert duration to timedelta
        if duration == '1d':
            expires_at = timezone.now() + timezone.timedelta(days=1)
        elif duration == '1w':
            expires_at = timezone.now() + timezone.timedelta(weeks=1)
        elif duration == '1m':
            expires_at = timezone.now() + timezone.timedelta(days=30)
        else:
            return Response({"error": "Invalid duration"}, status=status.HTTP_400_BAD_REQUEST)

        # Create a new RatingToken
        token = RatingToken.objects.create(
            coffee_shop=coffee_shop,
            expires_at=expires_at
        )

        # Generate QR code
        qr_data = f'https://khlcle.pythonanywhere.com/rate-coffee-shop/{token.token}/'
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        return HttpResponse(buffer, content_type='image/png')

    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def latest_qr_code(self, request, pk=None):
        coffee_shop = self.get_object()
        latest_token = RatingToken.objects.filter(
            coffee_shop=coffee_shop,
            expires_at__gt=timezone.now()
        ).order_by('-created_at').first()

        if latest_token:
            # Generate QR code
            qr_data = f'https://khlcle.pythonanywhere.com/rate-coffee-shop/{latest_token.token}/'
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(qr_data)
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            buffer.seek(0)
            return HttpResponse(buffer, content_type='image/png')
        else:
            return Response({"message": "No active QR code found"}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def qr_metadata(self, request, pk=None):
        coffee_shop = self.get_object()
        latest_token = RatingToken.objects.filter(
            coffee_shop=coffee_shop,
            expires_at__gt=timezone.now()
        ).order_by('-created_at').first()

        if latest_token:
            return Response({
                'expires_at': latest_token.expires_at,
                'created_at': latest_token.created_at
            })
        return Response({"message": "No active QR code found"}, status=status.HTTP_404_NOT_FOUND)

def verify_dti_permit(dti_permit_text):
    """Enhanced DTI permit verification"""
    if not dti_permit_text:
        return False

    required_keywords = [
        "Department of Trade and Industry",
        "Certificate of Business Name Registration",
        "Business Name",
        "Act 3383",
        "Act 4147"
    ]

    dti_permit_text_lower = dti_permit_text.lower()
    keyword_count = sum(
        1 for keyword in required_keywords
        if keyword.lower() in dti_permit_text_lower
    )

    # Require at least 80% of keywords to be present
    return keyword_count >= len(required_keywords) * 0.8

def send_welcome_email(user, coffee_shop):
    try:
        email = EmailMessage(
            subject='Your Coffee Shop Account is Ready',
            body=f'''
            <html>
            <body>
                <h1>Hello {user.username},</h1>

                <p>Your coffee shop account has been successfully created!</p>
                <p>Log in using your account, which you used to apply for the Coffee Shop</p>
                <p>To access your coffee shop page, please click the link below:</p>

                <p><a href="https://kohilocale.vercel.app/" style="display: inline-block;
                    background-color: #4CAF50;
                    color: white;
                    padding: 10px 20px;
                    text-decoration: none;
                    border-radius: 5px;">
                    Access Your Coffee Shop
                </a></p>

                <p>Best regards,<br>Kohi Locale Team</p>
            </body>
            </html>
            ''',
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )

        # Set the email content type to HTML
        email.content_subtype = "html"

        # Send the email
        email.send(fail_silently=False)

    except Exception as e:
        # Log the email sending error but don't prevent account creation
        logger.error(f"Failed to send welcome email: {str(e)}")


@api_view(['GET'])
def validate_rating_token(request, token):
    rating_token = get_object_or_404(RatingToken, token=token)

    if not rating_token.is_valid():
        return Response({"error": "Token has expired"}, status=400)

    coffee_shop = rating_token.coffee_shop
    serializer = CoffeeShopSerializer(coffee_shop)
    return Response(serializer.data)


class CoffeeShopOwnerViewSet(viewsets.ModelViewSet):
    serializer_class = CoffeeShopSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return CoffeeShop.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        # Handle image deletion if a new image is being uploaded
        if 'image' in request.FILES:
            # Delete the old image if it exists
            if instance.image:
                try:
                    # Get the file path
                    old_image_path = instance.image.path
                    # Delete the file from storage
                    default_storage.delete(old_image_path)
                except Exception as e:
                    print(f"Error deleting old image: {e}")

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # Handle is_under_maintenance update
        if 'is_under_maintenance' in request.data:
            instance.is_under_maintenance = request.data['is_under_maintenance']

        # Handle is_terminated update
        if 'is_terminated' in request.data:
            instance.is_terminated = request.data['is_terminated']

        self.perform_update(serializer)
        return Response(serializer.data)

class ContactInformationCreateUpdateView(generics.GenericAPIView):
    # Rest of the view remains the same
    #permission_classes = [IsAuthenticated]
    serializer_class = ContactInformationSerializer

    def get_coffee_shop(self, coffee_shop_id):
        """Helper method to get coffee shop and verify ownership"""
        coffee_shop = get_object_or_404(CoffeeShop, id=coffee_shop_id)
        if coffee_shop.owner != self.request.user:
            raise PermissionError("You don't have permission to access this coffee shop")
        return coffee_shop

    def get_object(self, coffee_shop_id):
        coffee_shop = self.get_coffee_shop(coffee_shop_id)
        return ContactInformation.objects.filter(coffee_shop=coffee_shop).first()

    def get(self, request, coffee_shop_id):
        try:
            contact_info = self.get_object(coffee_shop_id)
            if not contact_info:
                return Response(status=status.HTTP_404_NOT_FOUND)
            serializer = self.get_serializer(contact_info)
            return Response(serializer.data)
        except PermissionError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN
            )

    def post(self, request, coffee_shop_id):
        try:
            coffee_shop = self.get_coffee_shop(coffee_shop_id)
            # Check if contact info already exists
            existing_contact = self.get_object(coffee_shop_id)
            if existing_contact:
                return Response(
                    {'error': 'Contact information already exists for this coffee shop'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                serializer.save(coffee_shop=coffee_shop)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except PermissionError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN
            )

    def put(self, request, coffee_shop_id):
        try:
            contact_info = self.get_object(coffee_shop_id)
            if not contact_info:
                # If no contact info exists, create it
                return self.post(request, coffee_shop_id)
            serializer = self.get_serializer(
                contact_info,
                data=request.data,
                partial=True
            )
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except PermissionError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN
            )

class MenuItemViewSet(viewsets.ModelViewSet):
    serializer_class = MenuItemSerializer
    parser_classes = (MultiPartParser, FormParser)

    def get_queryset(self):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        return MenuItem.objects.filter(
            category__coffee_shop_id=coffee_shop_id,
            category__coffee_shop__owner=self.request.user
        ).prefetch_related('additional_images')

    def create(self, request, *args, **kwargs):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        mutable_data = request.data.copy()

        # Handle category
        category_id = mutable_data.get('category')
        try:
            category = MenuCategory.objects.get(
                id=category_id,
                coffee_shop_id=coffee_shop_id,
                coffee_shop__owner=self.request.user
            )
        except MenuCategory.DoesNotExist:
            return Response(
                {"error": "Invalid category for this coffee shop"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Handle sizes data
        sizes_data = mutable_data.get('sizes')
        if sizes_data:
            if isinstance(sizes_data, str):
                try:
                    sizes_data = json.loads(sizes_data)
                except json.JSONDecodeError:
                    return Response(
                        {"error": "Invalid JSON for sizes"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            mutable_data['sizes'] = sizes_data

        # Handle additional images
        additional_images = request.FILES.getlist('additional_images')

        serializer = self.get_serializer(data=mutable_data)
        serializer.is_valid(raise_exception=True)
        menu_item = serializer.save(category=category)

        # Create sizes if provided and no main price
        if not menu_item.price and sizes_data:
            for size_data in sizes_data:
                MenuItemSize.objects.create(menu_item=menu_item, **size_data)

        # Create additional images
        for image in additional_images:
            MenuItemImage.objects.create(menu_item=menu_item, image=image)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def remove_primary_image(self, request, *args, **kwargs):
        menu_item = self.get_object()
        if menu_item.image:
            # Delete the actual file
            menu_item.image.delete(save=False)
            menu_item.image = None
            menu_item.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def remove_additional_image(self, request, *args, **kwargs):
        menu_item = self.get_object()
        image_id = kwargs.get('image_id')
        try:
            image = menu_item.additional_images.get(id=image_id)
            # Delete the actual file
            image.image.delete(save=False)
            image.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except MenuItemImage.DoesNotExist:
            return Response(
                {"error": "Image not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    def remove_size(self, request, *args, **kwargs):
        menu_item = self.get_object()
        size_id = kwargs.get('size_id')
        try:
            size = menu_item.sizes.get(id=size_id)
            size.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except MenuItemSize.DoesNotExist:
            return Response(
                {"error": "Size not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()

        # Handle sizes data
        sizes_data = request.data.get('sizes')
        if sizes_data:
            if isinstance(sizes_data, str):
                try:
                    sizes_data = json.loads(sizes_data)
                except json.JSONDecodeError:
                    return Response(
                        {"error": "Invalid JSON for sizes"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Get existing size IDs from the data
                submitted_size_ids = set(
                    size.get('id') for size in sizes_data
                    if size.get('id') is not None
                )

                # Delete sizes that aren't in the submitted data
                instance.sizes.exclude(id__in=submitted_size_ids).delete()

                # Update or create sizes
                for size_data in sizes_data:
                    size_id = size_data.get('id')
                    if size_id:
                        # Update existing size
                        try:
                            size = instance.sizes.get(id=size_id)
                            for key, value in size_data.items():
                                if key != 'id':  # Skip updating the ID field
                                    setattr(size, key, value)
                            size.save()
                        except MenuItemSize.DoesNotExist:
                            continue
                    else:
                        # Create new size
                        size_data.pop('id', None)  # Remove null id if present
                        MenuItemSize.objects.create(menu_item=instance, **size_data)

        # Handle additional images
        additional_images = request.FILES.getlist('additional_images')
        for image in additional_images:
            MenuItemImage.objects.create(menu_item=instance, image=image)

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

# Add this new view for managing additional images
class MenuItemImageViewSet(viewsets.ModelViewSet):
    serializer_class = MenuItemImageSerializer

    def get_queryset(self):
        menu_item_id = self.kwargs.get('menu_item_id')
        return MenuItemImage.objects.filter(
            menu_item_id=menu_item_id,
            menu_item__category__coffee_shop__owner=self.request.user
        )

    def perform_create(self, serializer):
        menu_item = get_object_or_404(
            MenuItem,
            id=self.kwargs.get('menu_item_id'),
            category__coffee_shop__owner=self.request.user
        )
        serializer.save(menu_item=menu_item)


# The rest of your viewsets remain the same
class MenuItemSizeViewSet(viewsets.ModelViewSet):
    serializer_class = MenuItemSizeSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return MenuItemSize.objects.filter(menu_item__category__coffee_shop__owner=self.request.user)

class MenuCategoryViewSet(viewsets.ModelViewSet):
    serializer_class = MenuCategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        return MenuCategory.objects.filter(coffee_shop_id=coffee_shop_id, coffee_shop__owner=self.request.user)

    def perform_create(self, serializer):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        coffee_shop = get_object_or_404(CoffeeShop, id=coffee_shop_id, owner=self.request.user)
        serializer.save(coffee_shop=coffee_shop)

    def perform_update(self, serializer):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        coffee_shop = get_object_or_404(CoffeeShop, id=coffee_shop_id, owner=self.request.user)
        serializer.save(coffee_shop=coffee_shop)

class PromoViewSet(viewsets.ModelViewSet):
    serializer_class = PromoSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        return Promo.objects.filter(coffee_shop_id=coffee_shop_id, coffee_shop__owner=self.request.user)

    def perform_create(self, serializer):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        coffee_shop = get_object_or_404(CoffeeShop, id=coffee_shop_id, owner=self.request.user)
        serializer.save(coffee_shop=coffee_shop)

    def perform_update(self, serializer):
        coffee_shop_id = self.kwargs.get('coffee_shop_id')
        coffee_shop = get_object_or_404(CoffeeShop, id=coffee_shop_id, owner=self.request.user)
        serializer.save(coffee_shop=coffee_shop)

class RatingViewSet(viewsets.ModelViewSet):
    serializer_class = RatingSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        shop_id = self.kwargs.get('coffee_shop_id')
        queryset = Rating.objects.all() if shop_id is None else Rating.objects.filter(coffee_shop_id=shop_id)

        # Censor descriptions in the queryset
        for rating in queryset:
            rating.description = censor_bad_words(rating.description)

        return queryset

    def create(self, request, *args, **kwargs):
        token_value = request.data.get('token')
        token = get_object_or_404(RatingToken, token=token_value)

        # Check recent ratings and token validity first
        recent_ratings = Rating.objects.filter(
            user=request.user,
            coffee_shop=token.coffee_shop,
            created_at__gte=timezone.now() - timedelta(hours=24)
        )
        if recent_ratings.exists():
            return Response(
                {"detail": "You can only rate once per 24 hours."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not token.is_valid():
            return Response(
                {"detail": "Token has expired or is invalid."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare data for serializer
        data = request.data.copy()
        description = data.get('description', '')
        data['description'] = censor_bad_words(description)

        # Use the modified data in the serializer
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user, coffee_shop=get_object_or_404(RatingToken, token=self.request.data.get('token')).coffee_shop)

    def update(self, request, *args, **kwargs):
        # Prepare data for update
        data = request.data.copy()
        description = data.get('description', '')
        data['description'] = censor_bad_words(description)

        # Perform partial or full update
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

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

    def get_queryset(self):
        return OpeningHour.objects.filter(coffee_shop__owner=self.request.user)

    def create(self, request, *args, **kwargs):
        coffee_shop = CoffeeShop.objects.get(owner=self.request.user)
        # Delete existing opening hours for this coffee shop
        OpeningHour.objects.filter(coffee_shop=coffee_shop).delete()

        opening_hours_data = request.data if isinstance(request.data, list) else [request.data]
        created_hours = []

        for item in opening_hours_data:
            serializer = self.get_serializer(data=item)
            serializer.is_valid(raise_exception=True)
            opening_hour = OpeningHour.objects.create(coffee_shop=coffee_shop, **serializer.validated_data)
            created_hours.append(opening_hour)

        # Serialize the created objects
        response_serializer = self.get_serializer(created_hours, many=True)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

logger = logging.getLogger(__name__)

class NearbyCoffeeShopViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CoffeeShopSerializer

    def get_queryset(self):
        try:
            latitude = self.request.query_params.get('latitude')
            longitude = self.request.query_params.get('longitude')
            radius = float(self.request.query_params.get('radius', 5))  # Default 5km radius

            if not latitude or not longitude:
                raise ValidationError("Both latitude and longitude are required.")

            latitude = float(latitude)
            longitude = float(longitude)

            # Haversine formula
            distance_expr = ExpressionWrapper(
                6371 * ACos(
                    Cos(Radians(latitude)) *
                    Cos(Radians(F('latitude'))) *
                    Cos(Radians(F('longitude')) - Radians(longitude)) +
                    Sin(Radians(latitude)) *
                    Sin(Radians(F('latitude')))
                ),  # This now gives the result directly in kilometers
                output_field=FloatField()
            )
            queryset = CoffeeShop.objects.annotate(
                distance=distance_expr
            ).filter(distance__lte=radius).order_by('distance')
            return queryset
        except ValidationError as ve:
            logger.error(f"Validation error in get_queryset: {str(ve)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in get_queryset: {str(e)}", exc_info=True)
            raise

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
                data['distance'] = round(instance.distance, 2)  # Round to 2 decimal places
            return data
        except Exception as e:
            logger.error(f"Error in get_coffee_shop_detail: {str(e)}", exc_info=True)
            raise

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            coffee_shops = [self.get_coffee_shop_detail(shop) for shop in queryset]
            return Response(coffee_shops)
        except ValidationError as ve:
            return Response({'error': str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in list: {str(e)}", exc_info=True)
            return Response({'error': 'An unexpected error occurred. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            return Response(self.get_coffee_shop_detail(instance))
        except Exception as e:
            logger.error(f"Error in retrieve: {str(e)}", exc_info=True)
            return Response({'error': 'An unexpected error occurred. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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

class CoffeeShopApplicationViewSet(viewsets.ModelViewSet):
    queryset = CoffeeShopApplication.objects.all()
    serializer_class = CoffeeShopApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return CoffeeShopApplication.objects.filter(user=self.request.user)


class CoffeeShopDetailView(generics.RetrieveAPIView):
    queryset = CoffeeShop.objects.all()
    serializer_class = CoffeeShopSerializer

    def get(self, request, *args, **kwargs):
        try:
            coffee_shop = self.get_object()

            # Validate coffee shop exists
            if not coffee_shop:
                return Response(
                    {"error": "Coffee shop not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = self.get_serializer(coffee_shop)

            # Fetch related data with error handling
            try:
                menu_categories = MenuCategory.objects.filter(coffee_shop=coffee_shop).prefetch_related('items')
                promos = Promo.objects.filter(coffee_shop=coffee_shop)
                ratings = Rating.objects.filter(coffee_shop=coffee_shop)
                opening_hours = OpeningHour.objects.filter(coffee_shop=coffee_shop)
            except Exception as related_data_error:
                print(f"Error fetching related data: {related_data_error}")
                return Response(
                    {"error": "Error fetching related coffee shop data"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Safe rating censoring
            censored_ratings = []
            for rating in ratings:
                try:
                    # Use get() with a default empty string to handle None
                    original_description = rating.description or ''
                    censored_description = censor_bad_words(original_description)

                    rating_data = RatingSerializer(rating).data
                    rating_data['description'] = censored_description
                    censored_ratings.append(rating_data)
                except Exception as rating_error:
                    print(f"Error processing rating: {rating_error}")
                    # Use original rating data without modification if censoring fails
                    censored_ratings.append(RatingSerializer(rating).data)

            # Safe contact information retrieval
            contact_data = {
                'contact_name': None,
                'primary_phone': None,
                'secondary_phone': None,
                'email': None,
                'website': None,
                'facebook': None,
                'instagram': None,
                'twitter': None,
            }

            try:
                contact_info = coffee_shop.contact_info
                contact_data.update({
                    'contact_name': contact_info.contact_name,
                    'primary_phone': contact_info.primary_phone,
                    'secondary_phone': contact_info.secondary_phone,
                    'email': contact_info.email,
                    'website': contact_info.website,
                    'facebook': contact_info.facebook,
                    'instagram': contact_info.instagram,
                    'twitter': contact_info.twitter,
                })
            except ContactInformation.DoesNotExist:
                # Use default empty contact_data
                pass
            except Exception as contact_error:
                print(f"Error retrieving contact information: {contact_error}")

            # Comprehensive response
            return Response({
                'coffee_shop': {
                    **serializer.data,
                    'latitude': coffee_shop.latitude,
                    'longitude': coffee_shop.longitude,
                    'is_under_maintenance': coffee_shop.is_under_maintenance,
                    'contact_information': contact_data,
                },
                'menu_categories': MenuCategorySerializer(menu_categories, many=True, context={'request': request}).data,
                'promos': PromoSerializer(promos, many=True, context={'request': request}).data,
                'ratings': censored_ratings,
                'opening_hours': OpeningHourSerializer(opening_hours, many=True, context={'request': request}).data,
            })

        except Exception as e:
            print(f"Unexpected error in CoffeeShopDetailView: {e}")
            return Response(
                {"error": "An unexpected error occurred while fetching coffee shop details"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

