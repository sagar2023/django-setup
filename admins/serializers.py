from django.db import transaction
from rest_framework import serializers
from rest_framework.fields import SerializerMethodField

from accounts.models import User, UserPermission
from core import utils as core_utils
from core.exception import CustomException
from core.messages import validation_message
from core.serializers import DynamicFieldsModelSerializer


class UserPermissionSerializer(DynamicFieldsModelSerializer):
    """
    UserPermissionSerializer used for the user permission addition
    """
    user_id = serializers.IntegerField(required=True, error_messages={
        'required': validation_message.get('USER_ID_REQUIRED')})
    business_group = serializers.CharField(max_length=10000)
    category = serializers.CharField(max_length=10000)
    business_unit = serializers.CharField(max_length=10000)
    country = serializers.CharField(max_length=10000)

    def create(self, validated_data):
        with transaction.atomic():
            user_id = validated_data.pop('user_id')
            user_instance = User.all_objects.filter(id=user_id).first()
            if not user_instance:
                raise CustomException(status_code=400,
                                      message=validation_message.get("USER_NOT_FOUND"),
                                      location=validation_message.get("LOCATION"))
            instance, is_created = UserPermission.objects.update_or_create(user_id=user_id, defaults=validated_data)
            return instance

    class Meta:
        model = UserPermission
        fields = '__all__'


# Admin User Management Module


class AdminUserSerializer(serializers.ModelSerializer):
    """
    AdminUserSerializer used for the new user sign up
    """
    email = serializers.EmailField(min_length=5, max_length=50, required=True, error_messages={
        'required': validation_message.get('EMAIL_REQUIRED')})
    first_name = serializers.CharField(min_length=3, max_length=50, required=True, error_messages={
        'required': validation_message.get('FIRST_NAME_REQUIRED')})
    last_name = serializers.CharField(min_length=3, max_length=50, required=True, error_messages={
        'required': validation_message.get('LAST_NAME_REQUIRED')})
    password = serializers.CharField(min_length=8, max_length=15, required=True, allow_blank=True,
                                     error_messages={
                                         'required': validation_message.get('PASSWORD_REQUIRED')})
    role = serializers.ChoiceField(choices=User.RoleType, required=True, error_messages={
        'required': validation_message.get('ROLE_REQUIRED')})
    is_active = serializers.BooleanField(required=True, error_messages={
        'required': validation_message.get('IS_ACTIVE_REQUIRED')})
    business_group = serializers.CharField(max_length=10000, write_only=True)
    category = serializers.CharField(max_length=10000, write_only=True)
    business_unit = serializers.CharField(max_length=10000, write_only=True)
    country = serializers.CharField(max_length=10000, write_only=True)

    def validate_email(self, email: str):
        """
        method used to check email number already exist or not
        :param email:
        :return email:
        """
        if self.instance is None:
            if User.all_objects.filter(email=email):
                raise serializers.ValidationError(validation_message.get('EMAIL_ALREADY_EXIST'))
        return email

    @staticmethod
    def validate_role(role):
        """
        method used to check user role is admin or normal
        :param role:
        :return role:
        """
        if role == User.RoleType.SUPER_ADMIN_USER:
            raise serializers.ValidationError(validation_message.get('SUPER_ADMIN_CREATION_NOT_ALLOW'))
        return role

    def create(self, validated_data):
        with transaction.atomic():
            password = validated_data.pop('password')
            permission_data = {
                'business_group': validated_data.pop('business_group'),
                'category': validated_data.pop('category'),
                'business_unit': validated_data.pop('business_unit'),
                'country': validated_data.pop('country')
            }
            user_instance = User.objects.create(**validated_data)
            user_instance.set_password(password)
            user_instance.save()
            # To generate authentication token
            core_utils.user_token(user_instance, 'CREATE')
            # To create user permissions
            UserPermission.objects.create(user_id=user_instance.id, **permission_data)
            return True

    def update(self, instance, validated_data):
        with transaction.atomic():
            print(validated_data)
            password = validated_data.pop('password')
            permission_data = {
                'business_group': validated_data.pop('business_group'),
                'category': validated_data.pop('category'),
                'business_unit': validated_data.pop('business_unit'),
                'country': validated_data.pop('country')
            }
            user_instance = super(AdminUserSerializer, self).update(instance, validated_data)
            if password:
                user_instance.set_password(password)
                user_instance.save()
            # To create user permissions
            UserPermission.objects.update_or_create(user_id=user_instance.id, defaults=permission_data)
            return True

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'password', 'role', 'is_active',
                  'business_group', 'category', 'business_unit', 'country')


class AdminUserDetailSerializer(DynamicFieldsModelSerializer):
    """
    AdminUserDetailSerializer used for the user info
    """
    user_permission = SerializerMethodField()

    def get_user_permission(self, instance):
        user_permission_instance = UserPermission.objects.filter(user=instance).first()
        if user_permission_instance:
            return UserPermissionSerializer(user_permission_instance,
                                            exclude_fields=('user', 'user_id',)).data
        return dict()

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'is_active', 'role', 'user_permission',)
