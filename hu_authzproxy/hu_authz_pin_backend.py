from django.conf import settings
from django.contrib.auth.models import User
from urlparse import urlparse, parse_qs
from django.template.defaultfilters import slugify

from hu_authzproxy.authz_checker import AuthZChecker


class HarvardAuthZProxyBackend(object):
    """This authentication backend handles callbacks after people have logged with a Harvard Pin.
    
    The "token" passed to the authenticate message is the callback url returned from the HU authentication system, including the GET arguments.
    
    Set up for an AuthZ proxy that returns the following attributes:
        'sn' = user first name
        'givenname' = user last name
        'mail' = user email

    The username will be the user's email.  Although email may not be a unique identifier*, we're assuming that the same email signifies the same user.  (* The same email may be associated with more than one Harvard Pin.)    
    """
    supports_inactive_user = False
    supports_anonymous_user = False
    supports_object_permissions = True
    
    def __init__(self, **kwargs):

        self.authz_validation_info = kwargs.get('authz_validation_info', None)  # instance of AuthZProxyValidationInfo

        self.restrict_to_existing_users = kwargs.get('restrict_to_existing_users', True)
        self.restrict_to_active_users = kwargs.get('restrict_to_active_users', True)
        self.restrict_to_staff = kwargs.get('restrict_to_staff', True)
        self.restrict_to_superusers = kwargs.get('restrict_to_superusers', False)
        
        # Error flags that may be raised in the authentication process
        # These flags may later be used in templates
        self.error_check_attribute_names = [ 'err_url_lookup_vals_in_dict_is_none', 'err_user_not_created_name_email_vals_not_in_dict', 'err_account_not_active', 'err_user_not_staff' ,  'restrict_to_superusers', 'err_user_not_superuser']

        self.err_msgs = []

    def add_authz_error_info(self, authz_obj):
        self.add_authz_error_flags(authz_obj)
        self.add_authz_error_msgs(authz_obj)

    def add_authz_error_msgs(self, authz_obj):
        if authz_obj is None:
            return
        
        self.err_msgs += authz_obj.err_msgs
        
        
    def add_authz_error_flags(self, authz_obj):
        if authz_obj is None:
            return
            
        for err_attr in authz_obj.err_attrs:
            self.__dict__.update({ err_attr : authz_obj.__dict__.get(err_attr, False)  })
            self.error_check_attribute_names.append(err_attr)
            
    def init_err_checks(self):
        # using the attribute name strings, add boolean attributes to the object
        for attr_name in self.error_check_attribute_names:
            self.__dict__.update({attr_name : False})
    
    def get_err_msgs(self):
        return self.err_msgs
        
        
    def get_err_flag_dict(self):
        # using the attribute name strings, return a {} containing the error flags
        lu = {}
        for attr_name in self.error_check_attribute_names:
            lu.update({ attr_name : self.__dict__.get(attr_name, False )})
        return lu
        
    def authenticate(self):
        
        # initialize error flags
        self.init_err_checks()    

        zcheck = AuthZChecker( url_full_path=self.authz_validation_info.get_url_fullpath()\
                        , app_names=self.authz_validation_info.app_names
                        , gnupghome=self.authz_validation_info.gnupghome\
                        , user_request_ip=self.authz_validation_info.get_client_ip()
                        , is_debug=self.authz_validation_info.is_debug
                        )
        
        # auth failed!
        if not zcheck.did_authz_check_pass():
            self.add_authz_error_info(zcheck)
            return None
        
        if not zcheck.has_user_vals():
            self.add_authz_error_info(zcheck)
            return None
                    
        user = self.get_or_create_user(zcheck.get_user_vals())
        if user is None:
            return None
            
        return user
        
    def get_err_flag_dict(self):
        lu = {}
        for attr_name in self.error_check_attribute_names:
            lu.update({ attr_name : self.__dict__.get(attr_name, False )})
        return lu
    
    def get_user(self,user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
            
    def get_or_create_user(self, lu):
        if lu is None:
            self.err_url_lookup_vals_in_dict_is_none = True
            self.err_msgs.append('Pin Login did not supply email, last name, and first name')
            return None

        user_email = lu.get('email', None)
        user_lname = lu.get('lname', None)
        user_fname = lu.get('fname', None)
        if not (user_email and user_lname and user_fname):
            self.err_user_not_created_name_email_vals_not_in_dict = True
            self.err_msgs.append('Pin Login did not supply email, last name, and first name: %s' % lu)
            
            return None
        
        username = user_email[:30]  # Django user names restricted to 30 characters
        
        # (3) Retrieve user's credentials and check against retrictions
        try:
            # Check if the user exists in Django's local database
            user = User.objects.get(username=username)

            if self.restrict_to_active_users and not user.is_active:
                self.err_account_not_active = True
                return None
            elif self.restrict_to_staff and not user.is_staff:
                self.err_user_not_staff = True
                return None
            elif self.restrict_to_superusers and not user.is_superuser:
                self.err_user_not_superuser = True
                return None

        except User.DoesNotExist:
            if self.restrict_to_existing_users:
                self.err_not_an_existing_user = True
                return None

            # Create a user in Django's local database
            user = User.objects.create_user(username, email=user_email)
            user.set_unusable_password()
            user.save()

        # update last name, first name, and email
        user.last_name = user_lname
        user.first_name = user_fname
        user.email = user_email
        user.set_unusable_password()
        user.save()

        user.backend = 'hu_authzproxy.hu_authz_pin_backend.HarvardAuthZProxyBackend' 

        self.user = user
        return user
       