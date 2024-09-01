from django.contrib.auth import authenticate
from django.db import transaction
from rest_framework import serializers

from accounts.models import User
from admins.models import *
from core.exception import CustomException
from core.messages import validation_message
from core import utils as core_utils
from core.serializers import DynamicFieldsModelSerializer


class RegisterSerializer(serializers.ModelSerializer):
    """
    RegisterSerializer used for the user sign up
    """
    email = serializers.EmailField(min_length=5, max_length=50, required=True, error_messages={
        'required': validation_message.get('EMAIL_REQUIRED')})
    first_name = serializers.CharField(min_length=3, max_length=50, required=True, error_messages={
        'required': validation_message.get('FIRST_NAME_REQUIRED')})
    last_name = serializers.CharField(min_length=3, max_length=50, required=True, error_messages={
        'required': validation_message.get('LAST_NAME_REQUIRED')})
    password = serializers.CharField(min_length=8, max_length=15, required=True, error_messages={
        'required': validation_message.get('PASSWORD_REQUIRED')})
    role = serializers.ChoiceField(choices=User.RoleType, required=True, error_messages={
        'required': validation_message.get('ROLE_REQUIRED')})
    is_active = serializers.BooleanField(required=True, error_messages={
        'required': validation_message.get('IS_ACTIVE_REQUIRED')})

    @staticmethod
    def validate_email(email):
        """
        method used to check email number already exist or not
        :param email:
        :return email:
        """
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
            instance = User.objects.create(**validated_data)
            instance.set_password(password)
            instance.save()
            # To generate authentication token
            core_utils.user_token(instance, 'CREATE')
            return True

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'password', 'role', 'is_active')


class LoginSerializer(serializers.ModelSerializer):
    """
        LoginSerializer is used to verify the user credentials
    """
    email = serializers.EmailField(min_length=5, max_length=50, required=True, error_messages={
        'required': validation_message.get('EMAIL_REQUIRED')})
    password = serializers.CharField(min_length=8, max_length=15, required=True, write_only=True,
                                     error_messages={
                                         'required': validation_message.get('PASSWORD_REQUIRED')})

    def to_representation(self, instance):
        data = super(LoginSerializer, self).to_representation(instance)
        # To get auth token
        data['auth_token'] = core_utils.user_token(instance, 'GET')
        # To get first time login detail
        data['is_first_time_login'] = True if not instance.last_login else False
        return data

    def create(self, validated_data):
        with transaction.atomic():
            user = User.all_objects.filter(email=validated_data.get('email')).first()
            if not user:
                raise CustomException(status_code=400,
                                      message=validation_message.get("INVALID_CREDENTIAL"),
                                      location=validation_message.get("LOCATION"))
            instance = user.check_password(validated_data.get('password'))
            if not instance:
                raise CustomException(status_code=400,
                                      message=validation_message.get("INVALID_CREDENTIAL"),
                                      location=validation_message.get("LOCATION"))
            if not user.is_active:
                raise CustomException(status_code=400,
                                      message=validation_message.get("ACCOUNT_DEACTIVATED"),
                                      location=validation_message.get("LOCATION"))
            return user

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'is_active', 'password', 'role',)


class UserProfileSerializer(DynamicFieldsModelSerializer):
    """
        UserProfileSerializer is used to get user info
    """

    class Meta:
        model = User
        fields = ('id', 'email', 'role',)


