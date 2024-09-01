import datetime
import logging
import os
import re
import json
import pickle
from decouple import config
from django.db.models import F, Max
from django.http import HttpResponse
from django.utils import timezone

from core.authentication import CustomTokenAuthentication
from django.shortcuts import redirect
from rest_framework import status as status_code
from rest_framework import viewsets
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.db.models import Q
from django.core.serializers.json import DjangoJSONEncoder

from accounts.models import UserPermission
from accounts.serializers import (
    RegisterSerializer, LoginSerializer, UserProfileSerializer,
)
from admins.models import*
from accounts.models import (User)
from core.exception import get_custom_error
from core.permissions import CheckSuperAdminRolePermission, CheckAdminAndUserRolePermission
from core.response import SuccessResponse
from core.messages import success_message, validation_message, variables
from core import utils as core_utils

logger = logging.getLogger(__name__)


# Create your views here.

# class AfterSsoSuccessViewSet(viewsets.ViewSet):
#     """ AfterSsoSuccessViewSet view to perform operation after sso success """
#     # permission_classes = (AllowAny,)
#
#     def retrieve(self, request):
#         """ method to perform operation after sso success """
#         error_msg = validation_message.get('SOMETHING_WENT_WRONG')
#         try:
#             logger.info("\n\nInside AfterSSoSuccess viewset is up. \n\n")
#             try:
#                 print("asas")
#                 print(self.request)
#                 print(self.request.user)
#                 user_id = request.user.id
#                 print(user_id)
#             except Exception:
#                 print("Exception")
#                 msg = error_msg
#                 return redirect(config('FRONTEND_REDIRECT_URL'))
#             response = redirect(config('FRONTEND_REDIRECT_URL'))
#             auth_token = Token.objects.get_or_create(user_id=user_id)
#             response['Authorization'] = f'Token {auth_token}'
#             print(auth_token)
#             return response
#         except Exception as e:
#             logger.info(f"AfterSsoSuccessViewSet Retrieve API Error : {str(e)}")
#             msg = error_msg
#             return redirect("https://sem-app-dev.64sqs.com/auth/login")





class HealthViewSet(viewsets.ViewSet):
    """ HealthViewSet view where user can check if server is up or not """
    permission_classes = (AllowAny,)

    def retrieve(self, request):
        """ method to check server is up """
        try:
            logger.info("\n\nServer is up. \n\n")
            return SuccessResponse({'message': success_message.get('SERVER_IS_UP')},
                                   status=status_code.HTTP_200_OK)
        except Exception as e:
            logger.info(f"HealthViewSet Retrieve API Error : {str(e)}")
            return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
                                             status=400), status=status_code.HTTP_400_BAD_REQUEST)


class ValidateTokenViewSet(viewsets.ViewSet):
    """ ValidateTokenViewSet view to validate user token """
    permission_classes = (IsAuthenticated,)

    def create(self, request):
        """ method to validate the user token """
        try:
            logger.info("\n\nToken Validated. \n\n")
            return SuccessResponse({'message': success_message.get('TOKEN_VALIDATED')},
                                   status=status_code.HTTP_200_OK)
        except Exception as e:
            logger.info(f"ValidateTokenViewSet Create API Error : {str(e)}")
            return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
                                             status=400), status=status_code.HTTP_400_BAD_REQUEST)


class RegisterViewSet(viewsets.ViewSet):
    """ RegisterViewSet view where user provides basic information and should be able to register """
    authentication_classes = (CustomTokenAuthentication,)
    permission_classes = (IsAuthenticated, CheckSuperAdminRolePermission,)
    serializer_class = RegisterSerializer

    def create(self, request):
        """ method for user signup """
        # try:
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return SuccessResponse({"message": success_message.get('USER_REGISTERED')},
                               status=status_code.HTTP_200_OK)
        # except Exception as e:
        #     logger.info(f"RegisterViewSet Create API Error : {str(e)}")
        #     return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
        #                                      status=400), status=status_code.HTTP_400_BAD_REQUEST)


class LoginViewSet(viewsets.ViewSet):
    """
        LoginViewSet to check the user credentials
    """
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def create(self, request):
        """ method for user login """
        # try:
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        extra_data = {'message': success_message.get('LOGIN_SUCCESS')}
        return SuccessResponse(data=serializer.data, extra_data=extra_data,
                               status=status_code.HTTP_200_OK)
        # except Exception as e:
        #     logger.info(f"LoginViewSet Create API Error : {str(e)}")
        #     return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
        #                                      status=400), status=status_code.HTTP_400_BAD_REQUEST)


class UpdatePasswordViewSet(viewsets.ViewSet):
    """
        UpdatePasswordViewSet to update the user password at first time login
    """
    authentication_classes = (CustomTokenAuthentication,)
    permission_classes = (IsAuthenticated, CheckAdminAndUserRolePermission,)

    def update(self, request):
        """ method used to update user password """
        new_password = request.data.get('password')
        user_instance = self.request.user
        user_instance.set_password(new_password)
        user_instance.last_login = timezone.now()
        user_instance.save()
        return SuccessResponse(data={'message': success_message.get('PASSWORD_UPDATED')},
                               status=status_code.HTTP_200_OK)


class UserProfileViewSet(viewsets.ViewSet):
    """
        UserProfileViewSet to get the user profile
    """
    authentication_classes = (CustomTokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = UserProfileSerializer

    def retrieve(self, request):
        """ method to get user profile details """
        try:
            serializer = self.serializer_class(self.request.user)
            extra_data = {'message': success_message.get('USER_INFO_RETRIEVE')}
            return SuccessResponse(data=serializer.data, extra_data=extra_data,
                                   status=status_code.HTTP_200_OK)
        except Exception as e:
            logger.info(f"UserProfileViewSet Retrieve API Error : {str(e)}")
            return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
                                             status=400), status=status_code.HTTP_400_BAD_REQUEST)


