"""
Provides OAuth authentication policies.
"""
from __future__ import unicode_literals

from django.core.exceptions import ImproperlyConfigured
from django.conf import settings

from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header, BaseAuthentication

from .compat import oauth, oauth_provider, oauth_provider_store
from .compat import oauth2_provider, provider_now, check_nonce


class OAuthAuthentication(BaseAuthentication):
    """
    OAuth 1.0a authentication backend using `django-oauth-plus` and `oauth2`.
    Note: The `oauth2` package actually provides oauth1.0a support.  Urg.
          We import it from the `compat` module as `oauth`.
    """
    www_authenticate_realm = 'api'

    def __init__(self, *args, **kwargs):
        super(OAuthAuthentication, self).__init__(*args, **kwargs)

        if oauth is None:
            raise ImproperlyConfigured(
                "The 'oauth2' package could not be imported."
                "It is required for use with the 'OAuthAuthentication' class.")

        if oauth_provider is None:
            raise ImproperlyConfigured(
                "The 'django-oauth-plus' package could not be imported."
                "It is required for use with the 'OAuthAuthentication' class.")

    def authenticate(self, request):
        """
        Returns two-tuple of (user, token) if authentication succeeds,
        or None otherwise.
        """
        try:
            oauth_request = oauth_provider.utils.get_oauth_request(request)
        except oauth.Error as err:
            raise exceptions.AuthenticationFailed(err.message)

        if not oauth_request:
            return None

        oauth_params = oauth_provider.consts.OAUTH_PARAMETERS_NAMES

        found = any(param for param in oauth_params if param in oauth_request)
        missing = list(param for param in oauth_params if param not in oauth_request)

        if not found:
            # OAuth authentication was not attempted.
            return None

        if missing:
            # OAuth was attempted but missing parameters.
            msg = 'Missing parameters: %s' % (', '.join(missing))
            raise exceptions.AuthenticationFailed(msg)

        if not self.check_nonce(request, oauth_request):
            msg = 'Nonce check failed'
            raise exceptions.AuthenticationFailed(msg)

        try:
            consumer_key = oauth_request.get_parameter('oauth_consumer_key')
            consumer = oauth_provider_store.get_consumer(request, oauth_request, consumer_key)
        except oauth_provider.store.InvalidConsumerError:
            msg = 'Invalid consumer token: %s' % oauth_request.get_parameter('oauth_consumer_key')
            raise exceptions.AuthenticationFailed(msg)

        if consumer.status != oauth_provider.consts.ACCEPTED:
            msg = 'Invalid consumer key status: %s' % consumer.get_status_display()
            raise exceptions.AuthenticationFailed(msg)

        try:
            token_param = oauth_request.get_parameter('oauth_token')
            token = oauth_provider_store.get_access_token(request, oauth_request, consumer, token_param)
        except oauth_provider.store.InvalidTokenError:
            msg = 'Invalid access token: %s' % oauth_request.get_parameter('oauth_token')
            raise exceptions.AuthenticationFailed(msg)

        try:
            self.validate_token(request, consumer, token)
        except oauth.Error as err:
            raise exceptions.AuthenticationFailed(err.message)

        user = token.user

        if not user.is_active:
            msg = 'User inactive or deleted: %s' % user.username
            raise exceptions.AuthenticationFailed(msg)

        return (token.user, token)

    def authenticate_header(self, request):
        """
        If permission is denied, return a '401 Unauthorized' response,
        with an appropraite 'WWW-Authenticate' header.
        """
        return 'OAuth realm="%s"' % self.www_authenticate_realm

    def validate_token(self, request, consumer, token):
        """
        Check the token and raise an `oauth.Error` exception if invalid.
        """
        oauth_server, oauth_request = oauth_provider.utils.initialize_server_request(request)
        oauth_server.verify_request(oauth_request, consumer, token)

    def check_nonce(self, request, oauth_request):
        """
        Checks nonce of request, and return True if valid.
        """
        oauth_nonce = oauth_request['oauth_nonce']
        oauth_timestamp = oauth_request['oauth_timestamp']
        return check_nonce(request, oauth_request, oauth_nonce, oauth_timestamp)


class OAuth2Authentication(BaseAuthentication):
    """
    OAuth 2 authentication backend using `django-oauth2-provider`
    """
    www_authenticate_realm = 'api'
    allow_query_params_token = settings.DEBUG

    def __init__(self, *args, **kwargs):
        super(OAuth2Authentication, self).__init__(*args, **kwargs)

        if oauth2_provider is None:
            raise ImproperlyConfigured(
                "The 'django-oauth2-provider' package could not be imported. "
                "It is required for use with the 'OAuth2Authentication' class.")

    def authenticate(self, request):
        """
        Returns two-tuple of (user, token) if authentication succeeds,
        or None otherwise.
        """

        auth = get_authorization_header(request).split()

        if len(auth) == 1:
            msg = 'Invalid bearer header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid bearer header. Token string should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)

        if auth and auth[0].lower() == b'bearer':
            access_token = auth[1]
        elif 'access_token' in request.POST:
            access_token = request.POST['access_token']
        elif 'access_token' in request.GET and self.allow_query_params_token:
            access_token = request.GET['access_token']
        else:
            return None

        return self.authenticate_credentials(request, access_token)

    def authenticate_credentials(self, request, access_token):
        """
        Authenticate the request, given the access token.
        """

        try:
            token = oauth2_provider.oauth2.models.AccessToken.objects.select_related('user')
            # provider_now switches to timezone aware datetime when
            # the oauth2_provider version supports to it.
            token = token.get(token=access_token, expires__gt=provider_now())
        except oauth2_provider.oauth2.models.AccessToken.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid token')

        user = token.user

        if not user.is_active:
            msg = 'User inactive or deleted: %s' % user.get_username()
            raise exceptions.AuthenticationFailed(msg)

        return (user, token)

    def authenticate_header(self, request):
        """
        Bearer is the only finalized type currently
        Check details on the `OAuth2Authentication.authenticate` method
        """
        return 'Bearer realm="%s"' % self.www_authenticate_realm
