import logging
import os

from decouple import config
from django.conf import settings
from rest_framework import status as status_code
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from accounts.models import User
from accounts.serializers import *
from admins.models import *
from admins.serializers import UserPermissionSerializer, AdminUserDetailSerializer, AdminUserSerializer
from core.authentication import CustomTokenAuthentication
from core.exception import get_custom_error
from core.messages import validation_message, success_message
from core.permissions import CheckSuperAdminRolePermission, CheckAdminAndSuperAdminRolePermission
from core.response import SuccessResponse

logger = logging.getLogger(__name__)


# Create your views here.

class UserPermissionViewSet(viewsets.ViewSet):
    """
        UserPermissionViewSet to update the user permission
    """
    permission_classes = (IsAuthenticated, CheckSuperAdminRolePermission,)
    serializer_class = UserPermissionSerializer

    def create(self, request):
        """ method to update user permission """
        # try:
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        extra_data = {'message': success_message.get('USER_PERMISSION_UPDATED')}
        return SuccessResponse(data=serializer.data, extra_data=extra_data,
                               status=status_code.HTTP_200_OK)
        # except Exception as e:
        #     logger.info(f"UserPermissionViewSet Create API Error : {str(e)}")
        #     return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
        #                                      status=400), status=status_code.HTTP_400_BAD_REQUEST)


class LogViewSet(viewsets.GenericViewSet):
    """ LogViewSet view to get the logs data """
    permission_classes = (IsAuthenticated, CheckSuperAdminRolePermission,)

    def retrieve(self, request):
        """ method to get log file data """
        # try:
        page_size = request.GET.get('page_size')
        log_file_path = os.path.join(settings.BASE_DIR, config('LOG_FILE_NAME'))
        if os.path.exists(log_file_path):
            with open(log_file_path, 'r') as log_file:
                log_data = log_file.readlines()[::-1]
            if page_size:
                page = self.paginate_queryset(log_data)
                return SuccessResponse(self.get_paginated_response(page).data)
            return SuccessResponse(log_data)
        return Response(get_custom_error(message=validation_message.get('LOG_NOT_FOUND'),
                                         status=404), status=status_code.HTTP_404_NOT_FOUND)
        # except Exception as e:
        #     logger.info(f"LogViewSet Retrieve API Error : {str(e)}")
        #     return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
        #                                      status=400), status=status_code.HTTP_400_BAD_REQUEST)


# Admin User Management


class AdminUserViewSet(viewsets.ViewSet):
    """
        AdminUserViewSet to add, edit, retrieve, list and delete the user
    """
    authentication_classes = (CustomTokenAuthentication,)
    permission_classes = (IsAuthenticated, CheckAdminAndSuperAdminRolePermission)
    serializer_class = {
        'create': AdminUserSerializer,
        'update': AdminUserSerializer,
        'list': AdminUserDetailSerializer,
        'retrieve': AdminUserDetailSerializer
    }

    def create(self, request):
        """ method to create new user and it's permissions """
        serializer = self.serializer_class.get(self.action)(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return SuccessResponse({"message": success_message.get('USER_REGISTERED')},
                               status=status_code.HTTP_200_OK)

    def update(self, request, user_id):
        """ method to edit user info and it's permissions """
        user_instance = User.all_objects.filter(id=user_id).first()
        if not user_instance:
            return Response(get_custom_error(message=validation_message.get('USER_NOT_FOUND'),
                                             status=400), status=status_code.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class.get(self.action)(data=self.request.data, instance=user_instance)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return SuccessResponse({"message": success_message.get('USER_INFO_UPDATED')},
                               status=status_code.HTTP_200_OK)

    def list(self, request):
        """ method to get user list """
        try:
            user_instances = User.all_objects.exclude(role=User.RoleType.SUPER_ADMIN_USER).order_by('email')
            serializer = self.serializer_class.get(self.action)(user_instances, many=True,
                                                                exclude_fields=('user_permission',))
            return SuccessResponse(data=serializer.data, status=status_code.HTTP_200_OK)
        except Exception as e:
            logger.info(f"AdminUserViewSet List API Error : {str(e)}")
            return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
                                             status=400), status=status_code.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, user_id):
        """ method to get user info """
        try:
            user_instance = User.all_objects.filter(id=user_id).first()
            if not user_instance:
                return Response(get_custom_error(message=validation_message.get('USER_NOT_FOUND'),
                                                 status=400), status=status_code.HTTP_400_BAD_REQUEST)
            serializer = self.serializer_class.get(self.action)(user_instance)
            return SuccessResponse(data=serializer.data, status=status_code.HTTP_200_OK)
        except Exception as e:
            logger.info(f"AdminUserViewSet Retrieve API Error : {str(e)}")
            return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
                                             status=400), status=status_code.HTTP_400_BAD_REQUEST)

    def destroy(self, request, user_id):
        """ method to delete the user """
        try:
            user_instance = User.all_objects.filter(id=user_id).first()
            if not user_instance:
                return Response(get_custom_error(message=validation_message.get('USER_NOT_FOUND'),
                                                 status=400), status=status_code.HTTP_400_BAD_REQUEST)
            user_instance.is_deleted = True
            user_instance.save()
            return SuccessResponse(data={'message': success_message.get('USER_DELETED')}, status=status_code.HTTP_200_OK)
        except Exception as e:
            logger.info(f"AdminUserViewSet List API Error : {str(e)}")
            return Response(get_custom_error(message=validation_message.get('SOMETHING_WENT_WRONG'),
                                             status=400), status=status_code.HTTP_400_BAD_REQUEST)
