Django AuthZ Backend for Harvard Pin
================================

By plugging the authentication backend into your django settings, the code will:
	
## Needed in settings file

    - AUTHENTICATION_BACKENDS 
        - e.g. AUTHENTICATION_BACKENDS = ('django.contrib.auth.backends.ModelBackend'\
                , 'hu_authzproxy.hu_authz_pin_backend.HarvardAuthZProxyBackend'\
                ,)
    - HU_PIN_LOGIN_APP_NAMES
        - e.g. HU_PIN_LOGIN_APP_NAMES = ('FAS_FCOR_MYDEPT_MYDB_AUTHZ',)
    - GNUPG_HOME
        - e.g. GNUPG_HOME = '/some-directory/some-other-dir/.gnupg'
        - e.g. GNUPG_HOME = None
    - GPG_PASSPHRASE
        - e.g. GPG_PASSPHRASE = 'gpg-passphrase-for-me'
        - e.g. GPG_PASSPHRASE = None

## Add views, urls
    - hu_authz_handler/views.py
    - hu_authz_handler/urls.py
    - urls.py

## Add path to settings file 