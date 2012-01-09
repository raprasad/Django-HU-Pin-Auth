from django.conf import settings
from django.contrib.auth.models import User
from urlparse import urlparse, parse_qs
import time, hashlib
import gnupg
from textwrap import dedent


AUTH_URL_CALLBACK_KEYWORDS = ('__authen_pgp_signature' , '__authen_time', '__authen_application', '__authen_ip', '__authen_pgp_version', '__authen_huid' )


def is_pgp_message_verified(lu):
    """Test the PGP signature according to HU specs. 
    document: PIN2 Developer Resources.pdf
    lu: dict containing values for AUTH_URL_CALLBACK_KEYWORDS """
    print '-'  * 40
    print 'is_pgp_message_verified', lu
    print '-'  * 40
    
    print '1 lu'
    if lu is None:
        return None
        
    # make sure all the keywords are in the dict
    print '2 AUTH_URL_CALLBACK_KEYWORDS'
    for kw in AUTH_URL_CALLBACK_KEYWORDS:
        if kw not in lu.keys():
            return None
        
    # create the token as described in 
    token = '%s|%s||%s|%s' % (lu['__authen_application']\
                , lu['__authen_huid']
                , lu['__authen_ip']
                , lu['__authen_time']
                )
        #msg('__authen_pgp_signature: %s' % lu['__authen_pgp_signature'])

        #msg('token: [%s]' % token)

    print '3 token'
    
    pgp_msg = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

%s
-----BEGIN PGP SIGNATURE-----
Version: 5.0

%s
-----END PGP SIGNATURE-----""" % (token, lu['__authen_pgp_signature'])

    print '4', pgp_msg

    gpg_obj = gnupg.GPG()

    v = gpg_obj.verify(pgp_msg)
    if v is not None and v.valid==True:
        return True
        
    return False
    

class HarvardPinSimpleAuthBackend(object):
    """This authentication backend handles callbacks after people have logged with a Harvard Pin.
    
    The "token" passed to the authenticate message is the callback url returned from the HU authentication system, including the GET arguments.
    
    Note: username is a hash of Harvard Pin--not the pin itself
    """
    supports_inactive_user = False

    def authenticate(self, token=None):
        # Check the token and return a User.
        if token is None:
            return None
            
        # (1) break the url into key/value pairs
        try:
            lu = parse_qs(urlparse(token).query)
        except: 
            return None
        
        for k, v in lu.iteritems():
            lu.update({k: v[0].strip()})

        # (2) Test the PGP message
        if not is_pgp_message_verified(lu):
            return None
        
        #username = hashlib.sha224(lu['__authen_huid']).hexdigest()
        username = lu['__authen_huid'] # for test
        print 'username', username
        
        # (3) Retrieve user's credentials
        try:
            # Check if the user exists in Django's local database
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # Create a user in Django's local database
            user = User.objects.create_user(username, email='anonymous@ok.com')
            user.set_unusable_password()
            user.is_staff = True
            user.save()
            
        user.backend = 'hu_pin_auth.auth_hu_pin_backend.HarvardPinSimpleAuthBackend' 
        return user


    def get_user(self, user_id):
        # Required for your backend to work properly - unchanged in most scenarios
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
            
            
            
            