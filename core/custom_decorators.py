from rest_framework import status as status_code
from rest_framework.response import Response

from accounts.models import UserPermission
from core.exception import get_custom_error
from core.messages import validation_message

