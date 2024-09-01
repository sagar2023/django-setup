import copy
import datetime
import io
import json
import logging
import os
import re
from decimal import Decimal
from io import BytesIO
from itertools import groupby
from datetime import datetime, timedelta
import jwt
import math
from decouple import config
from django.db.models import Q
from rest_framework.authtoken.models import Token
import pandas as pd

from admins.models import *
from core.messages import success_message

logger = logging.getLogger(__name__)


def generate_jwt_authorization_token(request_user, auth_token):
    """Function to generate authentication token"""
    try:
        is_first_time_login = True if not request_user.last_login else False
        encoded_token = jwt.encode(
            {
                "id": request_user.id,
                "email": request_user.email,
                "first_name": request_user.first_name,
                "last_name": request_user.last_name,
                "is_active": request_user.is_active,
                "role": request_user.role,
                "auth_token": str(auth_token),
                "is_first_time_login": is_first_time_login,
                "message": success_message.get("LOGIN_SUCCESS"),
                'exp': datetime.utcnow() + timedelta(minutes=int(config('EXPIRATION_TIME'))),
            }, key=config('JWT_SECRET_KEY'), algorithm='HS256')
    except Exception as e:
        logger.info(f"Error in encoded_token: {str(e)}")
        return None
    return encoded_token


def user_token(instance, request_type="GET"):
    """
        method used to get or create the user token
    :param instance:
    :param request_type:
    :return: token key
    """
    try:
        if request_type == "GET":
            token = Token.objects.get(user=instance)
        else:
            token = Token.objects.create(user=instance)
    except Exception as e:
        logger.exception(f"Issue in create user token: \n\nstr({e})\n\n")
        return True
    return token.key


