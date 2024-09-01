# authentication.py
from rest_framework.authentication import TokenAuthentication, exceptions
from django.utils.translation import gettext as _


from core.messages import validation_message


class CustomTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed(validation_message.get('INVALID_TOKEN'))
        if token.user.is_deleted:  # Here I added something new !!
            raise exceptions.AuthenticationFailed(validation_message.get('USER_DELETED'))
        if not token.user.is_active:  # Here I added something new !!
            raise exceptions.AuthenticationFailed(validation_message.get('ACCOUNT_DEACTIVATED'))
        return token.user, token
