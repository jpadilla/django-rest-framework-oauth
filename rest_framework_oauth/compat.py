"""
The `compat` module provides support for backwards compatibility with older
versions of django/python, and compatibility wrappers around optional packages.
"""

# flake8: noqa
from __future__ import unicode_literals
import django
import inspect

from django.utils import six
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


# OAuth2 is optional
try:
    # Note: The `oauth2` package actually provides oauth1.0a support.  Urg.
    import oauth2 as oauth
except ImportError:
    oauth = None


# OAuthProvider is optional
try:
    import oauth_provider
    from oauth_provider.store import store as oauth_provider_store

    # check_nonce's calling signature in django-oauth-plus changes sometime
    # between versions 2.0 and 2.2.1
    def check_nonce(request, oauth_request, oauth_nonce, oauth_timestamp):
        check_nonce_args = inspect.getargspec(oauth_provider_store.check_nonce).args
        if 'timestamp' in check_nonce_args:
            return oauth_provider_store.check_nonce(
                request, oauth_request, oauth_nonce, oauth_timestamp
            )
        return oauth_provider_store.check_nonce(
            request, oauth_request, oauth_nonce
        )

except (ImportError, ImproperlyConfigured):
    oauth_provider = None
    oauth_provider_store = None
    check_nonce = None


# OAuth 2 support is optional
try:
    import provider as oauth2_provider
    from provider import scope as oauth2_provider_scope
    from provider import constants as oauth2_constants
    if oauth2_provider.__version__ in ('0.2.3', '0.2.4'):
        # 0.2.3 and 0.2.4 are supported version that do not support
        # timezone aware datetimes
        import datetime
        provider_now = datetime.datetime.now
    else:
        # Any other supported version does use timezone aware datetimes
        from django.utils.timezone import now as provider_now
except ImportError:
    oauth2_provider = None
    oauth2_provider_scope = None
    oauth2_constants = None
    provider_now = None
