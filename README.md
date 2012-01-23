Django Authentication Backend for Harvard Pin
================================

By plugging the authentication backend into your django settings, the code will:
	
1. authenticate a user via Harvard Pin
	->  uses Pin 1 authentication for constructing the PGP-signed message
2. upon authentication, look up the person's info via *HU LDAP
	->  * [LDAP isite](http://isites.harvard.edu/icb/icb.do?keyword=k236&pageid=icb.page527)
3. create a Django User object based on the HU LDAP information (username, last name, first name, email)

# How to use
- Include "hu_pin_auth" module on your PYTHON_PATH
    - hackish: sys.path.append('Django-HU-Pin_Auth/')

- In settings.py add 'hu_pin_auth.auth_hu_pin_backend.HarvardPinSimpleAuthBackend' to the
AUTHENTICATION_BACKENDS 

    - example with standard backend + HU PIN backend:

    AUTHENTICATION_BACKENDS = (   'django.contrib.auth.backends.ModelBackend',
        'hu_pin_auth.auth_hu_pin_backend.HarvardPinSimpleAuthBackend',
    )

- In settings.py add, at your app name to HU_PIN_LOGIN_APP_NAMES.
    - example: HU_PIN_LOGIN_APP_NAMES = ('FAS_MCB_AUTH_DEV',)

- In urls.py, adjust "view_handle_pin_callback" url to match the url you specified to UIS

- Add a link to use PIN for admin login. Example of link that was added to the admin/login.html file:

    - Include your app name where appropraiate
    
<a href="https://www.pin1.harvard.edu/pin/authenticate?__authen_application=FAS_MCB_AUTH_DEV&next={% url admin:index %}"><u>USE PIN LOGIN</u></a>

    - Successful log in redirects back to the admin