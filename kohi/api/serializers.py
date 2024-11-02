#backend/api/serializers.py
from rest_framework import serializers
from .models import CoffeeShop, CoffeeShopApplication, MenuCategory, MenuItem, Promo, Rating, BugReport, UserProfile, MenuItemSize, OpeningHour, RatingToken, MenuItemImage, ContactInformation
from django.contrib.auth.models import User
from django.db import transaction
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import logging
import traceback
from django.db import IntegrityError
from django.contrib.auth import get_user_model

class VerifyPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)

class ChangePasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "The two password fields didn't match."})
        return data

class UpdateEmailSerializer(serializers.Serializer):
    new_email = serializers.EmailField(required=True)

class UpdateUsernameSerializer(serializers.Serializer):
    new_username = serializers.CharField(required=True)

class SimpleCoffeeShopSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=False)

    class Meta:
        model = CoffeeShop
        fields = ['id', 'name', 'address', 'image', 'average_rating']
    def get_image_url(self, obj):
        request = self.context.get('request')
        if obj.image:
            return request.build_absolute_uri(obj.image.url)
        return None
logger = logging.getLogger(__name__)

class UserRegistrationSerializer(serializers.ModelSerializer):
       class Meta:
           model = User
           fields = ('username', 'email', 'password')
           extra_kwargs = {'password': {'write_only': True}}

       def create(self, validated_data):
           user = User.objects.create_user(
               username=validated_data['username'],
               email=validated_data['email'],
               password=validated_data['password']
           )
           return user

class UserProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    profile_picture_url = serializers.SerializerMethodField()
    favorite_coffee_shops = SimpleCoffeeShopSerializer(many=True, read_only=True)
    profile_picture = serializers.ImageField(required=False, write_only=True)

    class Meta:
        model = UserProfile
        fields = ['username', 'email', 'bio', 'contact_number', 'full_name', 'profile_picture', 'profile_picture_url', 'favorite_coffee_shops']
        extra_kwargs = {
           'bio': {'required': False, 'default': ''},
           'contact_number': {'required': False, 'default': ''},
           'full_name': {'required': False, 'default': ''},
        }

    def get_profile_picture_url(self, obj):
        if obj.profile_picture:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None

    def update(self, instance, validated_data):
        profile_picture = validated_data.pop('profile_picture', None)
        if profile_picture:
            instance.profile_picture = profile_picture
        return super().update(instance, validated_data)

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(required=False)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'profile']
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'required': True},
        }

    def validate(self, data):
        """
        Perform additional validation on the entire data set.
        """
        logger.info("Starting validation for user data")
        try:
            # Log validation attempt (excluding password)
            safe_data = {k: v for k, v in data.items() if k != 'password'}
            logger.info(f"Validating user data: {safe_data}")

            return data
        except Exception as e:
            logger.error(f"Validation error: {str(e)}")
            logger.error(traceback.format_exc())
            raise serializers.ValidationError(f"Validation error: {str(e)}")

    def validate_email(self, value):
        """
        Validate email with detailed error messages.
        """
        try:
            # Normalize email to lowercase
            value = value.lower().strip()

            # Check email format
            if '@' not in value:
                raise serializers.ValidationError("Invalid email format. Must contain @.")

            # Check if email exists
            if User.objects.filter(email=value).exists():
                raise serializers.ValidationError(
                    "This email is already registered. Please use a different email or reset your password."
                )

            return value
        except serializers.ValidationError:
            raise
        except Exception as e:
            logger.error(f"Email validation error: {str(e)}")
            raise serializers.ValidationError(f"Email validation error: {str(e)}")

    def validate_username(self, value):
        """
        Validate username with detailed error messages.
        """
        try:
            # Basic username validation
            if len(value) < 3:
                raise serializers.ValidationError(
                    "Username must be at least 3 characters long."
                )

            if len(value) > 150:
                raise serializers.ValidationError(
                    "Username must be less than 150 characters long."
                )

            # Check for spaces in username
            if ' ' in value:
                raise serializers.ValidationError(
                    "Username cannot contain spaces."
                )

            # Check if username exists
            if User.objects.filter(username__iexact=value).exists():
                raise serializers.ValidationError(
                    "This username is already taken. Please choose a different username."
                )

            return value
        except serializers.ValidationError:
            raise
        except Exception as e:
            logger.error(f"Username validation error: {str(e)}")
            raise serializers.ValidationError(f"Username validation error: {str(e)}")

    def validate_password(self, value):
        """
        Validate password with detailed error messages.
        """
        try:
            # Django's password validation
            validate_password(value)

            # Additional custom password requirements
            if len(value) < 8:
                raise serializers.ValidationError(
                    "Password must be at least 8 characters long."
                )

            if not any(char.isdigit() for char in value):
                raise serializers.ValidationError(
                    "Password must contain at least one number."
                )

            if not any(char.isupper() for char in value):
                raise serializers.ValidationError(
                    "Password must contain at least one uppercase letter."
                )

            return value
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        except Exception as e:
            logger.error(f"Password validation error: {str(e)}")
            raise serializers.ValidationError(f"Password validation error: {str(e)}")

    @transaction.atomic
    def create(self, validated_data):
        """
        Create user with detailed error handling and logging.
        """
        profile_data = validated_data.pop('profile', {})
        logger.info("Starting user creation")

        try:
            with transaction.atomic():
                # Create the user
                user = User.objects.create_user(
                    username=validated_data['username'],
                    email=validated_data['email'],
                    password=validated_data['password']
                )

                # Create or update profile
                if not UserProfile.objects.filter(user=user).exists():
                    UserProfile.objects.create(user=user, **profile_data)
                    logger.info(f"Created profile for user: {user.username}")

                logger.info(f"Successfully created user: {user.username}")
                return user

        except IntegrityError as e:
            logger.error(f"IntegrityError creating user: {str(e)}")
            raise serializers.ValidationError({
                "error": "Database integrity error. User might already exist.",
                "details": str(e)
            })
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            logger.error(traceback.format_exc())
            raise serializers.ValidationError({
                "error": "Failed to create user account.",
                "details": str(e)
            })

    def to_representation(self, instance):
        """
        Customize the output representation of the user.
        """
        try:
            ret = super().to_representation(instance)
            profile = UserProfile.objects.filter(user=instance).first()
            if profile:
                ret['profile'] = UserProfileSerializer(profile, context=self.context).data
            return ret
        except Exception as e:
            logger.error(f"Error in to_representation: {str(e)}")
            logger.error(traceback.format_exc())
            raise serializers.ValidationError(f"Error retrieving user data: {str(e)}")

    @transaction.atomic
    def update(self, instance, validated_data):
        # Update user fields
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)

        # Handle password update if provided
        password = validated_data.get('password')
        if password:
            instance.set_password(password)

        instance.save()

        # Update or create profile
        profile_data = validated_data.get('profile')
        if profile_data:
            profile, created = UserProfile.objects.get_or_create(user=instance)
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()

        return instance

class PasswordResetSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is not correct")
        return value

    def validate_new_password(self, value):
        try:
            validate_password(value, self.context['request'].user)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        return value

    @transaction.atomic
    def save(self):
        user = self.context['request'].user
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        return user


class OpeningHourSerializer(serializers.ModelSerializer):
    opening_time = serializers.TimeField(allow_null=True, required=False)
    closing_time = serializers.TimeField(allow_null=True, required=False)

    class Meta:
        model = OpeningHour
        fields = ['id', 'day', 'opening_time', 'closing_time']

    def validate(self, data):
        if (data.get('opening_time') is None) != (data.get('closing_time') is None):
            raise serializers.ValidationError("Both opening and closing times must be set, or both must be null.")
        return data

class CoffeeShopSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    average_rating = serializers.FloatField(read_only=True)
    image = serializers.ImageField(required=False)

    class Meta:
        model = CoffeeShop
        fields = [
            'id',
            'name',
            'address',
            'description',
            'opening_hours',
            'image',
            'latitude',
            'longitude',
            'average_rating',
            'owner',  # Include the owner field here
            'is_under_maintenance',
            'is_terminated'
        ]

    def create(self, validated_data):
        # Set is_under_maintenance to True by default (optional)
        validated_data['is_under_maintenance'] = True
        return super().create(validated_data)

class ContactInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactInformation
        fields = [
            'contact_name',
            'primary_phone',
            'secondary_phone',
            'email',
            'website',
            'facebook',
            'instagram',
            'twitter'
        ]

    def format_phone_number(self, phone):
        """Helper method to format phone numbers consistently"""
        if not phone:
            return phone
        # Remove any existing + prefix
        phone = phone.lstrip('+')
        # If it's a PH number (11 digits starting with 0)
        if phone.startswith('0') and len(phone) == 11:
            # Convert 09123456789 to +639123456789
            return f"+63{phone[1:]}"
        # If it's already in international format without +
        if len(phone) >= 9:
            return f"+{phone}"
        return phone

    def validate_primary_phone(self, value):
        if value:
            return self.format_phone_number(value)
        return value

    def validate_secondary_phone(self, value):
        if value:
            return self.format_phone_number(value)
        return value

User = get_user_model()

class CoffeeShopApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoffeeShopApplication
        fields = ['id', 'name', 'address', 'description', 'image', 'latitude', 'longitude']
        read_only_fields = ['user', 'status']

    def create(self, validated_data):
        user = self.context['request'].user
        application = CoffeeShopApplication.objects.create(user=user, **validated_data)

        # Auto-approve and create CoffeeShop
        coffee_shop = CoffeeShop.objects.create(
            name=application.name,
            address=application.address,
            description=application.description,
            image=application.image,
            latitude=application.latitude,
            longitude=application.longitude,
            owner=user,
            is_owner=True
        )

        # Approve the application and set the user as staff (owner)
        application.status = 'approved'
        application.save()

        # Grant the user staff privileges after approval
        user.is_staff = True
        user.save()

        return application


class MenuItemSizeSerializer(serializers.ModelSerializer):
    class Meta:
        model = MenuItemSize
        fields = ['size', 'price']

class MenuItemImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = MenuItemImage
        fields = ['id', 'image']

class MenuItemSerializer(serializers.ModelSerializer):
    sizes = MenuItemSizeSerializer(many=True, required=False)
    image = serializers.ImageField(required=False)
    additional_images = MenuItemImageSerializer(many=True, required=False, read_only=True)

    class Meta:
        model = MenuItem
        fields = ['id', 'name', 'description', 'is_available', 'category',
                 'image', 'price', 'sizes', 'additional_images']

    def validate(self, data):
        if 'price' in data or 'sizes' in data:
            price = data.get('price')
            sizes = data.get('sizes')
            if price is None and not sizes:
                raise serializers.ValidationError("Either a price or at least one size with price must be provided.")
        return data

    def update(self, instance, validated_data):
        # Handle partial updates
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

class MenuCategorySerializer(serializers.ModelSerializer):
    items = MenuItemSerializer(many=True, read_only=True)

    class Meta:
        model = MenuCategory
        fields = ['id', 'name', 'items']

class PromoSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=False)

    class Meta:
        model = Promo
        fields = ['id', 'name', 'description', 'start_date', 'end_date', 'image']

class RatingSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Rating
        fields = '__all__'
    def create(self, validated_data):
       return Rating.objects.create(**validated_data)

class RatingTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = RatingToken
        fields = ['token', 'created_at', 'expires_at']

class BugReportSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = BugReport
        fields = '__all__'
