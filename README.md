# djangorestframework-oauth

[![build-status-image]][travis]
[![pypi-version]][pypi]

## Overview

OAuth support for Django REST Framework. Provides two authentication classes: [OAuthAuthentication][oauth-authentication] and [OAuth2Authentication][oauth2-authentication] and a [TokenHasReadWriteScope][token-has-read-write-scope] permission class

## Requirements

* Python (2.6.5+, 2.7)
* Django (1.4.11+, 1.5.5+, 1.6, 1.7)

## Installation

Install using `pip`...

```bash
$ pip install djangorestframework-oauth
```

## Documentation & Support

Full documentation for the project is available at http://jpadilla.github.io/django-rest-framework-oauth/.

You may also want to follow the [author][jpadilla] on Twitter.

[build-status-image]: https://secure.travis-ci.org/jpadilla/django-rest-framework-oauth.png?branch=master
[travis]: http://travis-ci.org/jpadilla/django-rest-framework-oauth?branch=master
[pypi-version]: https://pypip.in/version/djangorestframework-oauth/badge.svg
[pypi]: https://pypi.python.org/pypi/djangorestframework-oauth
[oauth-authentication]: authentication.md#oauthauthentication
[oauth2-authentication]: authentication.md#oauth2authentication
[token-has-read-write-scope]: permissions.md#tokenhasreadwritescope
[jpadilla]: https://twitter.com/jpadilla_

