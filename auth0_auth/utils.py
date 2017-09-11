from base64 import urlsafe_b64decode
import json

from django.conf import settings
from django.core.urlresolvers import reverse
import jwt
from auth0.v3.authentication import GetToken
from auth0.v3.authentication import Users
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

logger = __import__('logging').getLogger('auth0_auth.utils')


DOMAIN = getattr(settings, 'AUTH0_DOMAIN')
SCOPE = getattr(settings, 'AUTH0_SCOPE', 'openid email')
CLIENT_ID = getattr(settings, 'AUTH0_CLIENT_ID')
CLIENT_SECRET = getattr(settings, 'AUTH0_CLIENT_SECRET')


def get_callback_url(request):
    return request.build_absolute_uri(reverse('auth0_callback'))


def get_login_url(domain=DOMAIN, scope=SCOPE, client_id=CLIENT_ID, redirect_uri=None, response_mode='form_post', state=None):
    param_dict = {
        'response_type': 'code',  # "code" because it is a server-side app
        'response_mode': response_mode,
        'scope': scope,
        'client_id': client_id,
    }
    if redirect_uri is not None:
        param_dict['redirect_uri'] = redirect_uri
    if state is not None:
        param_dict['state'] = state
    params = urlencode(param_dict)
    return 'https://{domain}/authorize?{params}'.format(
        domain=domain,
        params=params,
    )


def get_logout_url(redirect_uri, client_id=CLIENT_ID, domain=DOMAIN):
    params = urlencode({
        'returnTo': redirect_uri,
        'client_id': client_id,
    })
    return 'https://{domain}/v2/logout?{params}'.format(
        domain=domain,
        params=params,
    )


def get_email_from_token(token=None, key=CLIENT_SECRET, audience=CLIENT_ID):
    try:
        payload = jwt.decode(token, key=key, audience=audience, leeway=300)
        if 'email' in payload:
            return payload['email']
        elif 'sub' in payload:
            return payload['sub'].split('|').pop()
    except (jwt.InvalidTokenError, IndexError) as e:
        logger.error('Could not get email from token: {}'.format(e))

    return None


def is_email_verified_from_token(token=None, key=CLIENT_SECRET, audience=CLIENT_ID):
    try:
        payload = jwt.decode(token, key=key, audience=audience, leeway=300)
        return payload.get('email_verified', True)
    except (jwt.InvalidTokenError, IndexError) as e:
        pass

    return None

def get_tokens(code, request):
    '''Given an auth code, by making an Auth0 API call, returns an access_token
    and id_token.
    '''
    get_token = GetToken(DOMAIN)
    # exchange the Authorization Code for tokens: access_token, id_token
    tokens = get_token.authorization_code(
        CLIENT_ID,
        CLIENT_SECRET,
        code, get_callback_url(request))
    # tokens is a dict including access_token and id_token
    return tokens

def get_user_info(access_token):
    '''Given an auth token, requests the user info'''
    auth0_users = Users(DOMAIN)
    user_info_str = auth0_users.userinfo(access_token)
    # e.g. '{"sub":"github|12345","email":"david.read@xyz.com","email_verified":true}''
    return json.loads(user_info_str)