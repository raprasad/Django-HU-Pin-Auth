Django Authentication Backend for Harvard Pin
================================

By plugging the authentication backend into your django settings, the code will:
	
1. authenticate a user via Harvard Pin
--  uses Pin 2 authentication for constructing the PGP-signed message
2. upon authentication, look up the person's info via HU LDAP
3. create a Django User object based on the HU LDAP information (username, last name, first name, email)

## Requirements / Packages
- Harvard specific

    - [Register a Pin 2 Application](http://reference.pin.harvard.edu/dev-registration)

    - [Request access to HU-LDAP](http://isites.harvard.edu/icb/icb.do?keyword=k236&pageid=icb.page527)

    - [Pin2 public keys](http://reference.pin.harvard.edu/dev-downloads)

- Other

    - [django](http://www.djangoproject.com), assuming you're using this already.

    - [python-ldap](http://www.python-ldap.org/), used by hu_ldap_basic module for accessing HU-LDAP

    - [gnupg](http://www.gnupg.org/), open source version of PGP.  

    - [python-gnupg](http://code.google.com/p/python-gnupg/), python interface to gnupg.  Used by hu_pin_auth module for verifying PGP message.

## How to use
-  Install requirements/packages above.

    - [public key install](http://irtfweb.ifa.hawaii.edu/~lockhart/gpg/gpg-cs.html), see 'gpg --import public.key'

- Include "hu_ldap_basic" and "hu_pin_auth" modules on your PYTHON_PATH
    - hackish: sys.path.append('Django-HU-Pin_Auth/')

- In settings.py add 'hu_pin_auth.auth_hu_pin_backend_ldap.HarvardPinWithLdapAuthBackend' to the
AUTHENTICATION_BACKENDS 

    - example with standard backend + HU PIN backend:
        - AUTHENTICATION_BACKENDS = (   'django.contrib.auth.backends.ModelBackend',
                                  'hu_pin_auth.auth_hu_pin_backend_ldap.HarvardPinWithLdapAuthBackend',
                                  )


### For the settings.py file

- Add "HU_PIN_LOGIN_APP_NAMES" tuple with your app name.  This is the name given when you [Register a Pin 2 Application](http://reference.pin.harvard.edu/dev-registration)
    - example: HU_PIN_LOGIN_APP_NAMES = ('FAS_MCB_AUTH_DEV',)
    
- Define these variables for LDAP authentication
    - LDAP_CUSTOMER_NAME 
        - e.g. LDAP_CUSTOMER_NAME = 'fas_dept'
    - LDAP_CUSTOMER_PASSWORD
        - e.g. LDAP_CUSTOMER_PASSWORD = 'MR-potato-head-123'
    - LDAP_SERVER 
        - e.g. LDAP_SERVER = 'ldaps://hu-ldap-test.harvard.edu'
       

### Pin callback url (urls.py + view + errors in template)
- Include a "view_handle_pin_callback" url to match the url you specified in your [Pin 2 Registration](http://reference.pin.harvard.edu/dev-registration)
- An example callback url and view may be seen in:

    - hu_pin_auth/urls.py: view_handle_pin_callback
        - ex/ url(r'^hu_auth/callback/$', 'view_handle_pin_callback', name='view_handle_pin_callback' ),

    - hu_pin_auth/views.py: def view_handle_pin_callback(request): 
    
- For potential errors:
    - hu_pin_auth/templates/view_pin_login_failed.html

- Log out
    - hu_pin_auth/templates/registration/logout.html (includes link to the HU Pin logout page)

### Log in

- Add a link to use PIN for admin (or other login.) 
    - Example of link that was added to the django admin/login.html template. [overriding-admin-templates](https://docs.djangoproject.com/en/dev/ref/contrib/admin/#overriding-admin-templates)
    - Include your app name where it reads 'FAS_MY_DEPT_AUTH_DEV':
```<a href="https://www.pin1.harvard.edu/pin/authenticate?__authen_application=FAS_MY_DEPT_AUTH_DEV&next={% url admin:index %}"><u>USE PIN LOGIN</u></a>```
    - Example may be found in file: hu_pin_auth/templates/admin/login.html

- In the example above, a successful log in redirects back to the admin index page, to redirect to another page:
    - (a) Define 'next' in the url query string.  
    - (b) Rewrite your view to go to the appropriate page (see example in hu_pin_auth/views.py)


    