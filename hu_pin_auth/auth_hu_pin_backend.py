from django.conf import settings
from django.contrib.auth.models import User
from urlparse import urlparse, parse_qs
import time
try:
    from hashlib import sha1
except:
    import md5


import gnupg
from datetime import datetime

def msg(m): print m
def dashes(): msg('-'*40)
def msgt(m): dashes(); msg(m); dashes()
def msgx(m): dashes(); msg(m); print 'exiting'; sys.exit(0)

AUTH_URL_CALLBACK_KEYWORDS = ('__authen_pgp_signature' 
                            , '__authen_time'
                            , '__authen_application'
                            , '__authen_ip'
                            , '__authen_pgp_version'
                            , '__authen_huid' )


class PGPVerifyResult:
    def __init__(self, verified, err_msg=None):
        self.is_verified = verified
        self.err_msg = err_msg
        
def is_pgp_message_verified(lu):
    """Test the PGP signature according to HU specs. 
    document: PIN2 Developer Resources.pdf
    lu: dict containing values for AUTH_URL_CALLBACK_KEYWORDS"""
    #msgt('is_pgp_message_verified:\n %s' % lu)
    if lu is None:
        return PGPVerifyResult(False, '1 - No url params to check')
        
    # make sure all the keywords are in the dict
    for kw in AUTH_URL_CALLBACK_KEYWORDS:
        if kw not in lu.keys():
            return PGPVerifyResult(False, '2 - Param missing in url: %s' % kw)
        
    # create the token as described in 
    token = '%s|%s||%s|%s' % (lu['__authen_application']\
                , lu['__authen_huid']
                , lu['__authen_ip']
                , lu['__authen_time']
                )
    
    pgp_msg = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

%s
-----BEGIN PGP SIGNATURE-----
Version: 5.0

%s
-----END PGP SIGNATURE-----""" % (token, lu['__authen_pgp_signature'])
    
    if settings.GNUPG_HOME is not None:
        gpg_obj = gnupg.GPG(gnupghome=settings.GNUPG_HOME)
    else:
        gpg_obj = gnupg.GPG()
        
    v = gpg_obj.verify(pgp_msg)
    if v is not None and v.valid==True:
        return PGPVerifyResult(True)
        
    return PGPVerifyResult(False,\
        """3 - Verify failed. pgp msg:\n%s\n\n%s\nlookup params: %s\n\n%s""" % (pgp_msg,'-' * 30, lu, v.stderr) )
    
    #print '-' * 30
    #print lu
    #print '-' * 30
    #print pgp_msg
    #print '-' * 30
    #print v.stderr
    #return False
    

    
class HarvardPinAuthBackendBase(object):
    """This authentication backend handles callbacks after people have logged with a Harvard Pin.
    
    The "token" passed to the authenticate message is the callback url returned from the HU authentication system, including the GET arguments.
    
    Note: username is a hash of Harvard Pin--not the pin itself
    """
    supports_inactive_user = False
    supports_anonymous_user = False
    supports_object_permissions = True
    
    def __init__(self, **kwargs):
        self.expiration_check_time_seconds = 2 * 60 # 2 minutes until PGP log in message expires 
        
        # Error flags that may be raised in the authentication process
        # These flags may later be used in templates
        self.error_check_attribute_names = ['err_no_request_obj'\
                                , 'err_url_parse'\
                                , 'err_url_lookup_vals_not_in_dict'\
                                , 'err_pgp_msg_check'\
                                , 'err_pgp_msg'\
                                , 'err_huid_not_in_callback_url'\
                                , 'err_app_name_check'\
                                , 'err_ip_check'\
                                , 'err_time_check'
                                , 'err_msg_option'
                                 ]
    
    def get_expiration_check_seconds(self):
        return self.expiration_check_time_seconds   # seconds until PGP log in message expires 
        
        
    def init_err_checks(self):
        # using the attribute name strings, add boolean attributes to the object
        for attr_name in self.error_check_attribute_names:
            self.__dict__.update({attr_name : False})
        
    def get_err_flag_dict(self):
        # using the attribute name strings, return a {} containing the error flags
        lu = {}
        for attr_name in self.error_check_attribute_names:
            lu.update({ attr_name : self.__dict__.get(attr_name, False )})
        return lu
        
    def authenticate(self, request=None):
        
        # initialize error flags
        self.init_err_checks()
        
        if request is None:
            self.err_no_request_obj = True
            msg("request is None")
            return None
            
        url_full_path = request.get_full_path()

        # (1) break the url into key/value pairs
        try:
            lu = parse_qs(urlparse(url_full_path).query)
        except: 
            self.err_url_parse = True
            self.err_msg_option = url_full_path
            msg('failed to parse path: [%s]' % (url_full_path))
            return None
        
        for k, v in lu.iteritems():
            lu.update({k: v[0].strip()})

        # (2) Test the PGP message
        pgp_verify_result =  is_pgp_message_verified(lu)
        #(pgp_msg_verified, err_msg) =  is_pgp_message_verified(lu)
        if not pgp_verify_result.is_verified:
            self.err_pgp_msg_check = True
            self.err_pgp_msg = pgp_verify_result.err_msg
            msg('PGP message failed verification')
            return None
                    
        # (2a) check the app name
        if not lu['__authen_application'] in settings.HU_PIN_LOGIN_APP_NAMES:
            self.err_app_name_check = True
            msg('app name failed verification: [%s]' % lu['__authen_application'])
            return None
        
        # (2b) verify the IP
        remote_addr = request.META.get('REMOTE_ADDR', 'unknown')
        auth_ip = str(lu['__authen_ip'])
        if not auth_ip == remote_addr and (not remote_addr == 'unknown'):
            if settings.DEBUG and remote_addr == '127.0.0.1':
                pass
            elif auth_ip.startswith('10.') and (remote_addr.startswith('140.247.') or remote_addr.startswith('128.103.') ):
                # allow if 10. and other address from harvard
                pass
            else:
                self.err_ip_check = True
                msg('IP failed verification: url[%s] actual[%s]' % (auth_ip, remote_addr) )
                return None
        
        # (2c) check that time not longer than 'x' seconds old
        # e.g. __authen_time=Wed Jan 11 09:50:16 EST 2012
        authen_time = lu['__authen_time'].replace('EDT ', 'EST ')
        dt_pat = '%a %b %d %H:%M:%S EST %Y'
        datetime_obj = datetime.strptime(authen_time, dt_pat)
        try:
            time_now = datetime.now()
            time_diff = time_now - datetime_obj
            if time_diff.seconds < 0 or time_diff.seconds > self.get_expiration_check_seconds():
                msg('%s second rule failed verification: url[%s] system[%s]' % (self.get_expiration_check_seconds(), lu['__authen_time'], time_now))
                self.err_time_check = True
                return None
        except:
            self.err_time_check = True
            msg('time diff failed: url[%s]' % (lu['__authen_time']))
            return None

        user = self.get_or_create_user(lu)
        if user is None:
            return None
            
        return user

    def get_user(self,user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class HarvardPinSimpleAuthBackend(HarvardPinAuthBackendBase):
    """Created to test PIN when HU LDAP not configured.
    
    For a username, this uses a hash of the person's Harvard ID.
    In addition, a dummy email is used."""
    
    def get_or_create_user(self, lu):
        if lu is None:
            self.err_url_lookup_vals_not_in_dict = True
            return None
      
        username = lu.get('__authen_huid', None)
        if username is None:
            self.err_huid_not_in_callback_url = True
            return None
            
        try: 
            hash_username = sha1(username).hexdigest()
        except:
            hash_username = md5.new(username).hexdigest()
    
        # (3) Retrieve user's credentials
        try:
            # Check if the user exists in Django's local database
            user = User.objects.get(username=hash_username)
        except User.DoesNotExist:
            # Create a user in Django's local database
            user = User.objects.create_user(hash_username, email='sham_email@test_simple_auth.com')
            user.set_unusable_password()
            user.save()
        
        user.backend = 'hu_pin_auth.auth_hu_pin_backend.HarvardPinSimpleAuthBackend' 
        
        return user
            
            