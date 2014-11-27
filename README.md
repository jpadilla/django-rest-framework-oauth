# REST Framework OAuth

[![build-status-image]][travis]
[![pypi-version]][pypi]

## Overview

OAuth support extracted as a third party package directly from the official Django REST Framework implementation. It's built using the [django-oauth-plus][django-oauth-plus] and [django-oauth2-provider][django-oauth2-provider] packages.

This package provides two authentication classes: [OAuthAuthentication][oauth-authentication] and [OAuth2Authentication][oauth2-authentication] and a [TokenHasReadWriteScope][token-has-read-write-scope] permission class.

## Requirements

* Python 2.7
* Django (1.6, 1.7)
* Django REST Framework (2.4.3, 2.4.4, 3.0-beta)

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
[django-oauth-plus]: http://code.larlet.fr/django-oauth-plus/wiki/Home
[django-oauth2-provider]: http://django-oauth2-provider.readthedocs.org/
[oauth-authentication]: http://jpadilla.github.io/django-rest-framework-oauth/authentication/#oauthauthentication
[oauth2-authentication]: http://jpadilla.github.io/django-rest-framework-oauth/authentication/#oauth2authentication
[token-has-read-write-scope]: http://jpadilla.github.io/django-rest-framework-oauth/permissions/#tokenhasreadwritescope
[jpadilla]: https://twitter.com/jpadilla_

