Django Authentication Backend for Harvard Pin
================================

By plugging the authentication backend into your django settings, the code will:
	
1. authenticate a user via Harvard Pin
--  uses Pin 2 authentication for constructing the PGP-signed message
2. upon authentication, look up the person's info via *HU LDAP
3. create a Django User object based on the HU LDAP information (username, last name, first name, email)

## Requirements / Packages
- Harvard specific

-- [Register a Pin 2 Application](http://reference.pin.harvard.edu/dev-registration)

-- [Request access to HU-LDAP](http://isites.harvard.edu/icb/icb.do?keyword=k236&pageid=icb.page527)

-- [Pin2 public keys](http://reference.pin.harvard.edu/dev-downloads)

- Other

-- [django](http://www.djangoproject.com), assuming you're using this already.

-- [python-ldap](http://www.python-ldap.org/), used by hu_ldap_basic module for accessing HU-LDAP

-- [gnupg](http://www.gnupg.org/), open source version of PGP.  

-- [python-gnupg](http://code.google.com/p/python-gnupg/), python interface to gnupg.  Used by hu_pin_auth module for verifying PGP message.

## How to use
-  Install requirements/packages above.

-- [public key install](http://irtfweb.ifa.hawaii.edu/~lockhart/gpg/gpg-cs.html), see 'gpg --import public.key'

- Include "hu_ldap_basic" and "hu_pin_auth" modules on your PYTHON_PATH
    - hackish: sys.path.append('Django-HU-Pin_Auth/')

- In settings.py add 'hu_pin_auth.auth_hu_pin_backend.HarvardPinSimpleAuthBackend' to the
AUTHENTICATION_BACKENDS 

-- example with standard backend + HU PIN backend:
```
    AUTHENTICATION_BACKENDS = (   'django.contrib.auth.backends.ModelBackend',
        'hu_pin_auth.auth_hu_pin_backend.HarvardPinSimpleAuthBackend',
    )
```

- In settings.py add, at your app name to HU_PIN_LOGIN_APP_NAMES.  This is the name given when you [Register a Pin 2 Application](http://reference.pin.harvard.edu/dev-registration)
    - example: HU_PIN_LOGIN_APP_NAMES = ('FAS_MCB_AUTH_DEV',)

- In urls.py, adjust "view_handle_pin_callback" url to match the url you specified in your [Pin 2 Registration](http://reference.pin.harvard.edu/dev-registration)

- Add a link to use PIN for admin login. 

-- Example of link that was added to the django admin/login.html template. [overriding-admin-templates](https://docs.djangoproject.com/en/dev/ref/contrib/admin/#overriding-admin-templates)

--- Include your app name where it reads 'FAS_MY_DEPT_AUTH_DEV':
```   
<a href="https://www.pin1.harvard.edu/pin/authenticate?__authen_application=FAS_MY_DEPT_AUTH_DEV&next={% url admin:index %}"><u>USE PIN LOGIN</u></a>````

- In the example above, a successful log in redirects back to the admin index page, this can be changed in either:

-- (a) your link to the pin auth 

-- (b) in the hu_pin_auth.views file
    
    
    