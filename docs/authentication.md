source: authentication.py

# Authentication

## OAuthAuthentication

This authentication uses [OAuth 1.0a][oauth-1.0a] authentication scheme. OAuth 1.0a provides signature validation which provides a reasonable level of security over plain non-HTTPS connections. However, it may also be considered more complicated than OAuth2, as it requires clients to sign their requests.

This authentication class depends on the `django-oauth-plus` and `oauth2` packages. In order to make it work you must install these packages and add `oauth_provider` to your `INSTALLED_APPS`:

    INSTALLED_APPS = (
        ...
        `oauth_provider`,
    )

Don't forget to run `syncdb` once you've added the package.

    python manage.py syncdb

#### Getting started with django-oauth-plus

The OAuthAuthentication class only provides token verification and signature validation for requests. It doesn't provide authorization flow for your clients. You still need to implement your own views for accessing and authorizing tokens.

The `django-oauth-plus` package provides simple foundation for classic 'three-legged' oauth flow. Please refer to [the documentation][django-oauth-plus] for more details.

## OAuth2Authentication

This authentication uses [OAuth 2.0][rfc6749] authentication scheme. OAuth2 is more simple to work with than OAuth1, and provides much better security than simple token authentication. It is an unauthenticated scheme, and requires you to use an HTTPS connection.

This authentication class depends on the [django-oauth2-provider][django-oauth2-provider] project. In order to make it work you must install this package and add `provider` and `provider.oauth2` to your `INSTALLED_APPS`:

    INSTALLED_APPS = (
        ...
        'provider',
        'provider.oauth2',
    )

Then add `OAuth2Authentication` to your global `DEFAULT_AUTHENTICATION` setting:

    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.OAuth2Authentication',
    ),

You must also include the following in your root `urls.py` module:

    url(r'^oauth2/', include('provider.oauth2.urls', namespace='oauth2')),

Note that the `namespace='oauth2'` argument is required.

Finally, sync your database.

    python manage.py syncdb
    python manage.py migrate

---

**Note:** If you use `OAuth2Authentication` in production you must ensure that your API is only available over `https`.

---

#### Getting started with django-oauth2-provider

The `OAuth2Authentication` class only provides token verification for requests.  It doesn't provide authorization flow for your clients.

The OAuth 2 authorization flow is taken care by the [django-oauth2-provider][django-oauth2-provider] dependency. A walkthrough is given here, but for more details you should refer to [the documentation][django-oauth2-provider-docs].

To get started:

##### 1. Create a client

You can create a client, either through the shell, or by using the Django admin.

Go to the admin panel and create a new `Provider.Client` entry. It will create the `client_id` and `client_secret` properties for you.

##### 2. Request an access token

To request an access token, submit a `POST` request to the url `/oauth2/access_token` with the following fields:

* `client_id` the client id you've just configured at the previous step.
* `client_secret` again configured at the previous step.
* `username` the username with which you want to log in.
* `password` well, that speaks for itself.

You can use the command line to test that your local configuration is working:

    curl -X POST -d "client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&grant_type=password&username=YOUR_USERNAME&password=YOUR_PASSWORD" http://localhost:8000/oauth2/access_token/

You should get a response that looks something like this:

    {"access_token": "<your-access-token>", "scope": "read", "expires_in": 86399, "refresh_token": "<your-refresh-token>"}

##### 3. Access the API

The only thing needed to make the `OAuth2Authentication` class work is to insert the `access_token` you've received in the `Authorization` request header.

The command line to test the authentication looks like:

    curl -H "Authorization: Bearer <your-access-token>" http://localhost:8000/api/

[oauth-1.0a]: http://oauth.net/core/1.0a
[django-oauth-plus]: http://code.larlet.fr/django-oauth-plus
[django-oauth2-provider]: https://github.com/caffeinehit/django-oauth2-provider
[django-oauth2-provider-docs]: https://django-oauth2-provider.readthedocs.org/en/latest/
[rfc6749]: http://tools.ietf.org/html/rfc6749
[django-oauth-toolkit]: https://github.com/evonove/django-oauth-toolkit
