from django.conf import settings
from django.contrib.auth.models import User
from urlparse import urlparse, parse_qs
import time
import hashlib
import gnupg    # http://code.google.com/p/python-gnupg/
from datetime import datetime
from django.template.defaultfilters import slugify

from hu_pin_auth.auth_hu_pin_backend import HarvardPinAuthBackendBase
from hu_ldap_basic.hu_directory_search import HUDirectorySearcher    


class HarvardPinWithLdapAuthBackend(HarvardPinAuthBackendBase):
    """This authentication backend handles callbacks after people have logged with a Harvard Pin.
    
    The "token" passed to the authenticate message is the callback url returned from the HU authentication system, including the GET arguments.
    
    Note: username is a slug of the email in the pin system
    
    """
    def __init__(self, **kwargs):
        HarvardPinAuthBackendBase.__init__(self)    # init superclass
        
        # Access attributes
        # Default, restrict to active, existing users who are staff
        self.restrict_to_existing_users = kwargs.get('restrict_to_existing_users', True)
        self.restrict_to_active_users = kwargs.get('restrict_to_active_users', True)
        self.restrict_to_staff = kwargs.get('restrict_to_staff', True)
        self.restrict_to_superusers = kwargs.get('restrict_to_superusers', False)

        '''
        print '-' * 40
        print 'init'
        print 'restrict_to_existing_users', self.restrict_to_existing_users
        print 'restrict_to_active_users', self.restrict_to_active_users
        print 'restrict_to_staff', self.restrict_to_staff
        print 'restrict_to_superusers', self.restrict_to_superusers
        '''
        
        # error attributes
        self.error_check_attribute_names += ['err_no_email_in_hu_ldap'\
                                        ,'err_huid_not_found_in_hu_ldap'\
                                        ,'err_account_not_active'\
                                        ,'err_not_an_existing_user'\
                                        ,'err_user_not_staff'\
                                        ,'err_user_not_superuser' ]                                
            
    def get_or_create_user(self, lu):
        if lu is None:
            self.err_url_lookup_vals_not_in_dict = True
            return None
            
        #username = hashlib.sha224(lu['__authen_huid']).hexdigest()
        huid = lu.get('__authen_huid', None)
        if huid is None:
            self.err_huid_not_in_callback_url = True
            return None
    
        searcher = HUDirectorySearcher() 
        #kwarg = eval('lname="prasad"')
        members = searcher.find_people(**{'huid':huid})
        searcher.close_connection()
        if members is not None and len(members)==1:
            member = members[0]
            if member.mail is None:
                self.err_no_email_in_hu_ldap = True
                return None
            username = member.mail[:30]
        else:
            self.err_huid_not_found_in_hu_ldap = True
            return None
                
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
            user = User.objects.create_user(username, email=member.mail)
            user.set_unusable_password()
            user.save()
        
        # update last name, first name, and email
        user.last_name = member.get_or_blank('sn')
        user.first_name = member.get_or_blank('givenName')
        user.email = member.mail  # usernames are max 30 chars
        
        user.set_unusable_password()
        user.save()
        
        user.backend = 'hu_pin_auth.auth_hu_pin_backend_ldap.HarvardPinWithLdapAuthBackend' 
        
        return user
