from .utils import (get_email_from_token, is_email_verified_from_token,
                    get_login_url, get_logout_url, get_tokens,
                    get_user_info)
from base64 import urlsafe_b64encode
from django.conf import settings
try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User

    def get_user_model(*args, **kwargs):
        return User
from hashlib import sha1

log = __import__('logging').getLogger('auth0_auth.backends')


class Auth0Backend(object):
    USER_CREATION = getattr(settings, 'AUTH0_USER_CREATION', True)

    supports_anonymous_user = False
    supports_inactive_user = True
    supports_object_permissions = False

    def __init__(self):
        self.User = get_user_model()

    def login_url(self, redirect_uri, state):
        return get_login_url(
            redirect_uri=redirect_uri,
            state=state
        )

    def logout_url(self, redirect_uri):
        return get_logout_url(redirect_uri=redirect_uri)

    def authenticate(self, token=None, **kwargs):
        '''Given an id_token, extracts email, ensures there is a User and
        returns it.
        '''
        if token is None:
            return None

        email = get_email_from_token(token=token)

        if email is None:
            log.error('No email in the user info')
            return None

        # I couldn't get this to work - jwt.decode fails to deserialize the key
        if not is_email_verified_from_token(token=token):
            log.error('User has not verified their email')
            return None

        # Create user if necessary
        users = self.User.objects.filter(email=email)
        if len(users) == 0:
            user = self.create_user(email)
            if user is None:
                return None
            log.info('Creating user {}'.format(email))
        elif len(users) == 1:
            user = users[0]
            log.info('Existing user {}'.format(user))
        else:
            log.error('Multiple users with email {}'.format(email))
            return None

        user.backend = '{}.{}'.format(self.__class__.__module__, self.__class__.__name__)
        return user

    def authenticate_code(self, code, request):
        '''Given an code, requests the access token and then user info.
        Extracts email, ensures there is a User and returns it.
        '''
        tokens = get_tokens(code, request)
        user_info = get_user_info(tokens['access_token'])
        log.info('Logged in: {}'.format(user_info))
        email = user_info['email']

        if email is None:
            log.error('No email in the user info')
            return None
        if not user_info.get('email_verified', ''):
            log.error('User has not verified their Github email address')
            return None

        # Create user if necessary
        users = self.User.objects.filter(email=email)
        if len(users) == 0:
            user = self.create_user(email)
            if user is None:
                return None
            log.info('Creating user {}'.format(email))
        elif len(users) == 1:
            user = users[0]
            log.info('Existing user {}'.format(user))
        else:
            log.error('Multiple users with email {}'.format(email))
            return None

        user.backend = '{}.{}'.format(self.__class__.__module__, self.__class__.__name__)
        return user

    def get_user(self, user_id):
        try:
            user = self.User.objects.get(pk=user_id)
            return user
        except self.User.DoesNotExist:
            return None

    def create_user(self, email):
        if self.USER_CREATION:
            username_field = getattr(self.User, 'USERNAME_FIELD', 'username')
            user_kwargs = {'email': email}
            user_kwargs[username_field] = self.username_generator(email)
            return self.User.objects.create_user(**user_kwargs)
        else:
            return None

    @staticmethod
    def username_generator(email):
        return urlsafe_b64encode(sha1(email.encode('ascii', 'ignore')).digest()).rstrip(b'=')

