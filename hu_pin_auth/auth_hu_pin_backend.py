from django.conf import settings
from django.contrib.auth.models import User
from urlparse import urlparse, parse_qs
import time, hashlib

import gnupg
from textwrap import dedent
from datetime import datetime

def msg(m): print m
def dashes(): msg('-'*40)
def msgt(m): dashes(); msg(m); dashes()
def msgx(m): dashes(); msg(m); print 'exiting'; sys.exit(0)

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
    

    
class HarvardPinAbstractAuthBackend(object):
    """This authentication backend handles callbacks after people have logged with a Harvard Pin.
    
    The "token" passed to the authenticate message is the callback url returned from the HU authentication system, including the GET arguments.
    
    Note: username is a hash of Harvard Pin--not the pin itself
    """
    supports_inactive_user = False
    supports_anonymous_user = False
    
    #log = logging.getLogger(__name__)

    def authenticate(self, request=None):
        # Check the token and return a User.
        if request is None:
            msg("request is None")
            return None
            
        url_full_path = request.get_full_path()
            
        # (1) break the url into key/value pairs
        try:
            lu = parse_qs(urlparse(url_full_path).query)
        except: 
            msg('failed to parse path: [%s]' % (url_full_path))
            return None
        
        for k, v in lu.iteritems():
            lu.update({k: v[0].strip()})

        # (2) Test the PGP message
        if not is_pgp_message_verified(lu):
            msg('PGP message failed verification')
            return None
                    
        # (2a) check the app name
        if not lu['__authen_application'] in settings.HU_PIN_LOGIN_APP_NAMES:
            msg('app name failed verification: [%s]' % lu['__authen_application'])
            return None
        
        # (2b) verify the IP
        if not lu['__authen_ip'] == request.META.get('REMOTE_ADDR', None):
            msg('IP failed verification: url[%s] actual[%s]' % (lu['__authen_ip'], request.META.get('REMOTE_ADDR', 'unknown')) )
            return None
        
        # (2c) check that time not longer than 2 minutes old
        # e.g. __authen_time=Wed Jan 11 09:50:16 EST 2012
        dt_pat = '%a %b %d %H:%M:%S EST %Y'
        datetime_obj = datetime.strptime(lu['__authen_time'], dt_pat)
        try:
            time_now = datetime.now()
            time_diff = time_now - datetime_obj
            if time_diff.seconds < 0 or time_diff.seconds > 120:
                msg('120 second rule failed verification: url[%s] system[%s]' % (lu['__authen_time'], time_now))
                return None
        except:
            msg('time diff failed: url[%s]' % (lu['__authen_time']))
            return None

        user = self.get_or_create_user(lu)
        if user is None:
            return None
            
        return user
        
    def get_user(self, user_id):
        # Required for your backend to work properly - unchanged in most scenarios
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
    

class HarvardPinSimpleAuthBackend(HarvardPinAbstractAuthBackend):
    supports_inactive_user = False
    supports_anonymous_user = False

    def get_or_create_user(self, lu):
        if lu is None:
            msg('user is info is None')
            return None
      
        #username = hashlib.sha224(lu['__authen_huid']).hexdigest()
        username = lu.get('__authen_huid', None)
        if username is None:
            msg('__authen_huid is None')            
            return None
    
        # (3) Retrieve user's credentials
        try:
            # Check if the user exists in Django's local database
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # Create a user in Django's local database
            user = User.objects.create_user(username, email='anonymous@ok.com')
            user.set_unusable_password()
            user.is_staff = False
            user.save()
        
        user.backend = 'hu_pin_auth.auth_hu_pin_backend.HarvardPinSimpleAuthBackend' 
        
        return user
            
            