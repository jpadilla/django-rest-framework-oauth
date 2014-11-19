source: permissions.py

# Permissions

## TokenHasReadWriteScope

This permission class is intended for use with either of the `OAuthAuthentication` and `OAuth2Authentication` classes, and ties into the scoping that their backends provide.

Requests with a safe methods of `GET`, `OPTIONS` or `HEAD` will be allowed if the authenticated token has read permission.

Requests for `POST`, `PUT`, `PATCH` and `DELETE` will be allowed if the authenticated token has write permission.

This permission class relies on the implementations of the [django-oauth-plus][django-oauth-plus] and [django-oauth2-provider][django-oauth2-provider] libraries, which both provide limited support for controlling the scope of access tokens:

* `django-oauth-plus`: Tokens are associated with a `Resource` class which has a `name`, `url` and `is_readonly` properties.
* `django-oauth2-provider`: Tokens are associated with a bitwise `scope` attribute, that defaults to providing bitwise values for `read` and/or `write`.

If you require more advanced scoping for your API, such as restricting tokens to accessing a subset of functionality of your API then you will need to provide a custom permission class.  See the source of the `django-oauth-plus` or `django-oauth2-provider` package for more details on scoping token access.

[django-oauth-plus]: http://code.larlet.fr/django-oauth-plus
[django-oauth2-provider]: https://github.com/caffeinehit/django-oauth2-provider
