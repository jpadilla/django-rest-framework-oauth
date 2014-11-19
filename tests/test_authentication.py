from __future__ import unicode_literals
import time
import datetime

from django.conf.urls import patterns, url, include
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.test import TestCase
from django.utils import unittest
from django.utils.http import urlencode

from rest_framework import status, permissions
from rest_framework_oauth.authentication import OAuthAuthentication, OAuth2Authentication
from rest_framework_oauth.compat import oauth2_provider, oauth2_provider_scope
from rest_framework_oauth.compat import oauth, oauth_provider
from rest_framework.test import APIRequestFactory, APIClient
from rest_framework.views import APIView


factory = APIRequestFactory()


class MockView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        return HttpResponse({'a': 1, 'b': 2, 'c': 3})

    def post(self, request):
        return HttpResponse({'a': 1, 'b': 2, 'c': 3})

    def put(self, request):
        return HttpResponse({'a': 1, 'b': 2, 'c': 3})


class OAuth2AuthenticationDebug(OAuth2Authentication):
    allow_query_params_token = True


urlpatterns = patterns(
    '',
    (r'^oauth/$', MockView.as_view(authentication_classes=[OAuthAuthentication])),
    (
        r'^oauth-with-scope/$',
        MockView.as_view(
            authentication_classes=[OAuthAuthentication],
            permission_classes=[permissions.TokenHasReadWriteScope]
        )
    ),

    url(r'^oauth2/', include('provider.oauth2.urls', namespace='oauth2')),
    url(r'^oauth2-test/$', MockView.as_view(authentication_classes=[OAuth2Authentication])),
    url(r'^oauth2-test-debug/$', MockView.as_view(authentication_classes=[OAuth2AuthenticationDebug])),
    url(
        r'^oauth2-with-scope-test/$',
        MockView.as_view(
            authentication_classes=[OAuth2Authentication],
            permission_classes=[permissions.TokenHasReadWriteScope]
        )
    ),
)


class OAuthTests(TestCase):
    """OAuth 1.0a authentication"""
    urls = 'tests.test_authentication'

    def setUp(self):
        # these imports are here because oauth is optional and hiding them in try..except block or compat
        # could obscure problems if something breaks
        from oauth_provider.models import Consumer, Scope
        from oauth_provider.models import Token as OAuthToken
        from oauth_provider import consts

        self.consts = consts

        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.username = 'john'
        self.email = 'lennon@thebeatles.com'
        self.password = 'password'
        self.user = User.objects.create_user(self.username, self.email, self.password)

        self.CONSUMER_KEY = 'consumer_key'
        self.CONSUMER_SECRET = 'consumer_secret'
        self.TOKEN_KEY = "token_key"
        self.TOKEN_SECRET = "token_secret"

        self.consumer = Consumer.objects.create(
            key=self.CONSUMER_KEY, secret=self.CONSUMER_SECRET,
            name='example', user=self.user, status=self.consts.ACCEPTED
        )

        self.scope = Scope.objects.create(name="resource name", url="api/")
        self.token = OAuthToken.objects.create(
            user=self.user, consumer=self.consumer, scope=self.scope,
            token_type=OAuthToken.ACCESS, key=self.TOKEN_KEY, secret=self.TOKEN_SECRET,
            is_approved=True
        )

    def _create_authorization_header(self):
        params = {
            'oauth_version': "1.0",
            'oauth_nonce': oauth.generate_nonce(),
            'oauth_timestamp': int(time.time()),
            'oauth_token': self.token.key,
            'oauth_consumer_key': self.consumer.key
        }

        req = oauth.Request(method="GET", url="http://example.com", parameters=params)

        signature_method = oauth.SignatureMethod_PLAINTEXT()
        req.sign_request(signature_method, self.consumer, self.token)

        return req.to_header()["Authorization"]

    def _create_authorization_url_parameters(self):
        params = {
            'oauth_version': "1.0",
            'oauth_nonce': oauth.generate_nonce(),
            'oauth_timestamp': int(time.time()),
            'oauth_token': self.token.key,
            'oauth_consumer_key': self.consumer.key
        }

        req = oauth.Request(method="GET", url="http://example.com", parameters=params)

        signature_method = oauth.SignatureMethod_PLAINTEXT()
        req.sign_request(signature_method, self.consumer, self.token)
        return dict(req)

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_post_form_passing_oauth(self):
        """Ensure POSTing form over OAuth with correct credentials passes and does not require CSRF"""
        auth = self._create_authorization_header()
        response = self.csrf_client.post('/oauth/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_post_form_repeated_nonce_failing_oauth(self):
        """Ensure POSTing form over OAuth with repeated auth (same nonces and timestamp) credentials fails"""
        auth = self._create_authorization_header()
        response = self.csrf_client.post('/oauth/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

        # simulate reply attack auth header containes already used (nonce, timestamp) pair
        response = self.csrf_client.post('/oauth/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_post_form_token_removed_failing_oauth(self):
        """Ensure POSTing when there is no OAuth access token in db fails"""
        self.token.delete()
        auth = self._create_authorization_header()
        response = self.csrf_client.post('/oauth/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_post_form_consumer_status_not_accepted_failing_oauth(self):
        """Ensure POSTing when consumer status is anything other than ACCEPTED fails"""
        for consumer_status in (self.consts.CANCELED, self.consts.PENDING, self.consts.REJECTED):
            self.consumer.status = consumer_status
            self.consumer.save()

            auth = self._create_authorization_header()
            response = self.csrf_client.post('/oauth/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)
            self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_post_form_with_request_token_failing_oauth(self):
        """Ensure POSTing with unauthorized request token instead of access token fails"""
        self.token.token_type = self.token.REQUEST
        self.token.save()

        auth = self._create_authorization_header()
        response = self.csrf_client.post('/oauth/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_post_form_with_urlencoded_parameters(self):
        """Ensure POSTing with x-www-form-urlencoded auth parameters passes"""
        params = self._create_authorization_url_parameters()
        auth = self._create_authorization_header()
        response = self.csrf_client.post('/oauth/', params, HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_get_form_with_url_parameters(self):
        """Ensure GETing with auth in url parameters passes"""
        params = self._create_authorization_url_parameters()
        response = self.csrf_client.get('/oauth/', params)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_post_hmac_sha1_signature_passes(self):
        """Ensure POSTing using HMAC_SHA1 signature method passes"""
        params = {
            'oauth_version': "1.0",
            'oauth_nonce': oauth.generate_nonce(),
            'oauth_timestamp': int(time.time()),
            'oauth_token': self.token.key,
            'oauth_consumer_key': self.consumer.key
        }

        req = oauth.Request(method="POST", url="http://testserver/oauth/", parameters=params)

        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        req.sign_request(signature_method, self.consumer, self.token)
        auth = req.to_header()["Authorization"]

        response = self.csrf_client.post('/oauth/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_get_form_with_readonly_resource_passing_auth(self):
        """Ensure POSTing with a readonly scope instead of a write scope fails"""
        read_only_access_token = self.token
        read_only_access_token.scope.is_readonly = True
        read_only_access_token.scope.save()
        params = self._create_authorization_url_parameters()
        response = self.csrf_client.get('/oauth-with-scope/', params)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_post_form_with_readonly_resource_failing_auth(self):
        """Ensure POSTing with a readonly resource instead of a write scope fails"""
        read_only_access_token = self.token
        read_only_access_token.scope.is_readonly = True
        read_only_access_token.scope.save()
        params = self._create_authorization_url_parameters()
        response = self.csrf_client.post('/oauth-with-scope/', params)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_post_form_with_write_resource_passing_auth(self):
        """Ensure POSTing with a write resource succeed"""
        read_write_access_token = self.token
        read_write_access_token.scope.is_readonly = False
        read_write_access_token.scope.save()
        params = self._create_authorization_url_parameters()
        auth = self._create_authorization_header()
        response = self.csrf_client.post('/oauth-with-scope/', params, HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_bad_consumer_key(self):
        """Ensure POSTing using HMAC_SHA1 signature method passes"""
        params = {
            'oauth_version': "1.0",
            'oauth_nonce': oauth.generate_nonce(),
            'oauth_timestamp': int(time.time()),
            'oauth_token': self.token.key,
            'oauth_consumer_key': 'badconsumerkey'
        }

        req = oauth.Request(method="POST", url="http://testserver/oauth/", parameters=params)

        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        req.sign_request(signature_method, self.consumer, self.token)
        auth = req.to_header()["Authorization"]

        response = self.csrf_client.post('/oauth/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    @unittest.skipUnless(oauth_provider, 'django-oauth-plus not installed')
    @unittest.skipUnless(oauth, 'oauth2 not installed')
    def test_bad_token_key(self):
        """Ensure POSTing using HMAC_SHA1 signature method passes"""
        params = {
            'oauth_version': "1.0",
            'oauth_nonce': oauth.generate_nonce(),
            'oauth_timestamp': int(time.time()),
            'oauth_token': 'badtokenkey',
            'oauth_consumer_key': self.consumer.key
        }

        req = oauth.Request(method="POST", url="http://testserver/oauth/", parameters=params)

        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        req.sign_request(signature_method, self.consumer, self.token)
        auth = req.to_header()["Authorization"]

        response = self.csrf_client.post('/oauth/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)


class OAuth2Tests(TestCase):
    """OAuth 2.0 authentication"""
    urls = 'tests.test_authentication'

    def setUp(self):
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.username = 'john'
        self.email = 'lennon@thebeatles.com'
        self.password = 'password'
        self.user = User.objects.create_user(self.username, self.email, self.password)

        self.CLIENT_ID = 'client_key'
        self.CLIENT_SECRET = 'client_secret'
        self.ACCESS_TOKEN = "access_token"
        self.REFRESH_TOKEN = "refresh_token"

        self.oauth2_client = oauth2_provider.oauth2.models.Client.objects.create(
            client_id=self.CLIENT_ID,
            client_secret=self.CLIENT_SECRET,
            redirect_uri='',
            client_type=0,
            name='example',
            user=None,
        )

        self.access_token = oauth2_provider.oauth2.models.AccessToken.objects.create(
            token=self.ACCESS_TOKEN,
            client=self.oauth2_client,
            user=self.user,
        )
        self.refresh_token = oauth2_provider.oauth2.models.RefreshToken.objects.create(
            user=self.user,
            access_token=self.access_token,
            client=self.oauth2_client
        )

    def _create_authorization_header(self, token=None):
        return "Bearer {0}".format(token or self.access_token.token)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_get_form_with_wrong_authorization_header_token_type_failing(self):
        """Ensure that a wrong token type lead to the correct HTTP error status code"""
        auth = "Wrong token-type-obsviously"
        response = self.csrf_client.get('/oauth2-test/', {}, HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)
        response = self.csrf_client.get('/oauth2-test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_get_form_with_wrong_authorization_header_token_format_failing(self):
        """Ensure that a wrong token format lead to the correct HTTP error status code"""
        auth = "Bearer wrong token format"
        response = self.csrf_client.get('/oauth2-test/', {}, HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)
        response = self.csrf_client.get('/oauth2-test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_get_form_with_wrong_authorization_header_token_failing(self):
        """Ensure that a wrong token lead to the correct HTTP error status code"""
        auth = "Bearer wrong-token"
        response = self.csrf_client.get('/oauth2-test/', {}, HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)
        response = self.csrf_client.get('/oauth2-test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_get_form_with_wrong_authorization_header_token_missing(self):
        """Ensure that a missing token lead to the correct HTTP error status code"""
        auth = "Bearer"
        response = self.csrf_client.get('/oauth2-test/', {}, HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)
        response = self.csrf_client.get('/oauth2-test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_get_form_passing_auth(self):
        """Ensure GETing form over OAuth with correct client credentials succeed"""
        auth = self._create_authorization_header()
        response = self.csrf_client.get('/oauth2-test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_post_form_passing_auth_url_transport(self):
        """Ensure GETing form over OAuth with correct client credentials in form data succeed"""
        response = self.csrf_client.post(
            '/oauth2-test/',
            data={'access_token': self.access_token.token}
        )
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_get_form_passing_auth_url_transport(self):
        """Ensure GETing form over OAuth with correct client credentials in query succeed when DEBUG is True"""
        query = urlencode({'access_token': self.access_token.token})
        response = self.csrf_client.get('/oauth2-test-debug/?%s' % query)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_get_form_failing_auth_url_transport(self):
        """Ensure GETing form over OAuth with correct client credentials in query fails when DEBUG is False"""
        query = urlencode({'access_token': self.access_token.token})
        response = self.csrf_client.get('/oauth2-test/?%s' % query)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_post_form_passing_auth(self):
        """Ensure POSTing form over OAuth with correct credentials passes and does not require CSRF"""
        auth = self._create_authorization_header()
        response = self.csrf_client.post('/oauth2-test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_post_form_token_removed_failing_auth(self):
        """Ensure POSTing when there is no OAuth access token in db fails"""
        self.access_token.delete()
        auth = self._create_authorization_header()
        response = self.csrf_client.post('/oauth2-test/', HTTP_AUTHORIZATION=auth)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_post_form_with_refresh_token_failing_auth(self):
        """Ensure POSTing with refresh token instead of access token fails"""
        auth = self._create_authorization_header(token=self.refresh_token.token)
        response = self.csrf_client.post('/oauth2-test/', HTTP_AUTHORIZATION=auth)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_post_form_with_expired_access_token_failing_auth(self):
        """Ensure POSTing with expired access token fails with an 'Invalid token' error"""
        self.access_token.expires = datetime.datetime.now() - datetime.timedelta(seconds=10)  # 10 seconds late
        self.access_token.save()
        auth = self._create_authorization_header()
        response = self.csrf_client.post('/oauth2-test/', HTTP_AUTHORIZATION=auth)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))
        self.assertIn('Invalid token', response.content)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_post_form_with_invalid_scope_failing_auth(self):
        """Ensure POSTing with a readonly scope instead of a write scope fails"""
        read_only_access_token = self.access_token
        read_only_access_token.scope = oauth2_provider_scope.SCOPE_NAME_DICT['read']
        read_only_access_token.save()
        auth = self._create_authorization_header(token=read_only_access_token.token)
        response = self.csrf_client.get('/oauth2-with-scope-test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)
        response = self.csrf_client.post('/oauth2-with-scope-test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @unittest.skipUnless(oauth2_provider, 'django-oauth2-provider not installed')
    def test_post_form_with_valid_scope_passing_auth(self):
        """Ensure POSTing with a write scope succeed"""
        read_write_access_token = self.access_token
        read_write_access_token.scope = oauth2_provider_scope.SCOPE_NAME_DICT['write']
        read_write_access_token.save()
        auth = self._create_authorization_header(token=read_write_access_token.token)
        response = self.csrf_client.post('/oauth2-with-scope-test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)
