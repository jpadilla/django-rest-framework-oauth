# djangorestframework-oauth

<div class="badges">
    <a href="http://travis-ci.org/jpadilla/django-rest-framework-oauth?branch=master">
        <img src="https://secure.travis-ci.org/jpadilla/django-rest-framework-oauth.png?branch=master">
    </a>
    <a href="https://pypi.python.org/pypi/djangorestframework-oauth">
        <img src="https://pypip.in/version/djangorestframework-oauth/badge.svg">
    </a>
</div>

## Overview

OAuth support for Django REST Framework. Provides two authentication classes: [OAuthAuthentication][oauth-authentication] and [OAuth2Authentication][oauth2-authentication] and a [TokenHasReadWriteScope][token-has-read-write-scope] permission class

## Requirements

* Python (2.6.5+, 2.7, 3.2, 3.3, 3.4)
* Django (1.4.11+, 1.5.5+, 1.6, 1.7)

## Installation

Install using `pip`...

```bash
$ pip install djangorestframework-oauth
```

[oauth-authentication]: authentication.md#oauthauthentication
[oauth2-authentication]: authentication.md#oauth2authentication
[token-has-read-write-scope]: permissions.md#tokenhasreadwritescope
