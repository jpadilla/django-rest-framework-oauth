"""
Provides permission policies for OAuth.
"""
from __future__ import unicode_literals

from rest_framework.permissions import SAFE_METHODS, BasePermission

from .compat import oauth2_provider_scope, oauth2_constants


class TokenHasReadWriteScope(BasePermission):
    """
    The request is authenticated as a user and the token used has the right scope
    """

    def has_permission(self, request, view):
        token = request.auth
        read_only = request.method in SAFE_METHODS

        if not token:
            return False

        if hasattr(token, 'resource'):  # OAuth 1
            return read_only or not request.auth.resource.is_readonly
        elif hasattr(token, 'scope'):  # OAuth 2
            required = oauth2_constants.READ if read_only else oauth2_constants.WRITE
            return oauth2_provider_scope.check(required, request.auth.scope)

        assert False, (
            'TokenHasReadWriteScope requires either the'
            '`OAuthAuthentication` or `OAuth2Authentication` authentication '
            'class to be used.'
        )
