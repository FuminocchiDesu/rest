#backend/api/serializers.py
from rest_framework import serializers
from .models import CoffeeShop, CoffeeShopApplication, MenuCategory, MenuItem, Promo, Rating, BugReport, UserProfile, MenuItemSize, OpeningHour
from django.contrib.auth.models import User
from django.db import transaction
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import logging
import traceback
from django.db import IntegrityError

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_new_password = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_new_password']:
            raise serializers.ValidationError("New passwords do not match.")
        return data

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

class UserProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    profile_picture_url = serializers.SerializerMethodField()
    favorite_coffee_shops = SimpleCoffeeShopSerializer(many=True, read_only=True)
    class Meta:
        model = UserProfile
        fields = ['username', 'email', 'bio', 'contact_number', 'full_name', 'profile_picture', 'profile_picture_url', 'favorite_coffee_shops']
        extra_kwargs = {
            'bio': {'required': False, 'default': ''},
            'contact_number': {'required': False, 'default': ''},
            'full_name': {'required': False, 'default': ''},
            'profile_picture': {'required': False, 'write_only': True}
        }

    def get_profile_picture_url(self, obj):
        if obj.profile_picture:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None


class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(required=False)
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'profile']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        profile = UserProfile.objects.filter(user=instance).first()
        if profile:
            ret['profile'] = UserProfileSerializer(profile, context=self.context).data
        return ret

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        return value
    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        return value

    @transaction.atomic
    def create(self, validated_data):
        profile_data = validated_data.pop('profile', {})
        logger.info(f"Validated data: {validated_data}")
        try:
            user = User.objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password']
            )
            # Check if the profile already exists before creating it
            if not UserProfile.objects.filter(user=user).exists():
                UserProfile.objects.create(user=user, **profile_data)
        except IntegrityError as e:
            logger.error(f"IntegrityError creating user: {str(e)}")
            raise serializers.ValidationError(f"A user with this username or email already exists: {str(e)}")
        except Exception as e:
            logger.error(f"Error creating user or profile: {str(e)}")
            logger.error(traceback.format_exc())
            raise serializers.ValidationError(f"An error occurred during user creation: {str(e)}")

        return user

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
    class Meta:
        model = OpeningHour
        fields = ['day', 'opening_time', 'closing_time']

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
            'owner'  # Include the owner field here
        ]



class CoffeeShopApplicationSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    image = serializers.ImageField(required=False)

    class Meta:
        model = CoffeeShopApplication
        fields = '__all__'

class MenuItemSizeSerializer(serializers.ModelSerializer):
    class Meta:
        model = MenuItemSize
        fields = ['size', 'price']
    def get_price(self, obj):
        return f"₱{obj.price}"

class MenuItemSerializer(serializers.ModelSerializer):
    sizes = MenuItemSizeSerializer(many=True)

    class Meta:
        model = MenuItem
        fields = ['id', 'category', 'name', 'description', 'image', 'sizes']
    def get_price(self, obj):
        return f"₱{obj.price}"
    def create(self, validated_data):
        sizes_data = validated_data.pop('sizes')
        menu_item = MenuItem.objects.create(**validated_data)
        for size_data in sizes_data:
            MenuItemSize.objects.create(menu_item=menu_item, **size_data)
        return menu_item

    def update(self, instance, validated_data):
        sizes_data = validated_data.pop('sizes', None)
        instance = super().update(instance, validated_data)

        if sizes_data is not None:
            # Clear existing sizes
            instance.sizes.all().delete()
            for size_data in sizes_data:
                MenuItemSize.objects.create(menu_item=instance, **size_data)

        return instance
    def get_image_url(self, obj):
        request = self.context.get('request')
        if obj.image:
            return request.build_absolute_uri(obj.image.url)
        return None
    def validate_category(self, value):
        coffee_shop_id = self.context['view'].kwargs.get('coffee_shop_id')
        if value.coffee_shop_id != int(coffee_shop_id):
            raise serializers.ValidationError("Invalid category for this coffee shop")
        return value

"""class MenuCategorySerializer(serializers.ModelSerializer):
    coffee_shop = serializers.PrimaryKeyRelatedField(queryset=CoffeeShop.objects.all(), write_only=True)

    class Meta:
        model = MenuCategory
        fields = ['id', 'name', 'coffee_shop']

    def validate_coffee_shop(self, value):
        coffee_shop_id = self.context['view'].kwargs.get('coffee_shop_id')
        if value.id != int(coffee_shop_id):
            raise serializers.ValidationError("Invalid coffee shop")
        return value"""

class MenuCategorySerializer(serializers.ModelSerializer):
    coffee_shop = serializers.PrimaryKeyRelatedField(queryset=CoffeeShop.objects.all(), write_only=True)
    items = MenuItemSerializer(many=True, read_only=True)

    class Meta:
        model = MenuCategory
        fields = ['id', 'name', 'coffee_shop', 'items']

    def validate_coffee_shop(self, value):
        coffee_shop_id = self.context['view'].kwargs.get('coffee_shop_id')
        if value.id != int(coffee_shop_id):
            raise serializers.ValidationError("Invalid coffee shop")
        return value

class PromoSerializer(serializers.ModelSerializer):
    coffee_shop = serializers.PrimaryKeyRelatedField(queryset=CoffeeShop.objects.all(), write_only=True)
    image = serializers.ImageField(required=False)

    class Meta:
        model = Promo
        fields = ['id', 'name', 'description', 'start_date', 'end_date', 'coffee_shop', 'image']
    def get_image_url(self, obj):
        request = self.context.get('request')
        if obj.image:
            return request.build_absolute_uri(obj.image.url)
        return None
    def validate_coffee_shop(self, value):
        coffee_shop_id = self.context['view'].kwargs.get('coffee_shop_id')
        if value.id != int(coffee_shop_id):
            raise serializers.ValidationError("Invalid coffee shop")
        return value
    def get_price(self, obj):
        return f"₱{obj.price}"

class RatingSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Rating
        fields = '__all__'
    def create(self, validated_data):
       return Rating.objects.create(**validated_data)

class BugReportSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = BugReport
        fields = '__all__'
