Django Auth0 Auth
=================

*Django Auth0 Auth* allows you to authenticate through Auth0.

Installation
------------

Run `pip install django-auth0-auth`

Add the `Auth0Backend` to your `AUTHENTICATION_BACKENDS` setting:

```python
AUTHENTICATION_BACKENDS = (
    ...
    'auth0_auth.backends.Auth0Backend',
)
```

Edit your `urls.py` to include:

```python
urlpatterns = [
    url(r'^auth0/', include('auth0_auth.urls')),
    ...
]
```


Settings
--------

###AUTH0_DOMAIN

Auth0 domain.

###AUTH0_CLIENT_ID

Auth0 client id.


###AUTH0_CLIENT_SECRET

Auth0 client secret.


###AUTH0_SCOPE

**default:** `'openid email'`
OAuth scope parameter.


###AUTH0_USER_CREATION

**default:** `True`
Allow creation of new users after successful authentication.


Lock Signin
----------------
To log in using the JavaScript based **Lock** dialog, add the following to your project.


Add the `auth0` context processor to the `TEMPLATES` options.

```python
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'OPTIONS': {
            'context_processors': [
                ...
                'auth0_auth.context_processors.auth0',
            ],
        },
    },
]
```

Add the following JavaScript snippet to your `base.html` below your sites other JavaScript.

    <script src="https://cdn.auth0.com/js/lock-9.min.js"></script>
    <script type="text/javascript">
        var lock = new Auth0Lock('{{ AUTH0_CLIENT_ID }}', '{{ AUTH0_DOMAIN }}');
        function signin() {
            lock.show({
                callbackURL: '{{ AUTH0_CALLBACK_URL }}',
                responseType: 'token',
                authParams: {
                    'scope': '{{ AUTH0_SCOPE }}',
                    'response_mode': 'form_post',
                    'state': '{{ AUTH0_STATE }}'
                }
            });
        }
    </script>

Add a login button to your `base.html`.

    <button onclick="window.signin();">Login</button>
