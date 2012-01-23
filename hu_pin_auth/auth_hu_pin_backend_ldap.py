from django.conf import settings
from django.contrib.auth.models import User
from urlparse import urlparse, parse_qs
import time, hashlib
import gnupg    # http://code.google.com/p/python-gnupg/
from textwrap import dedent
from datetime import datetime
from django.template.defaultfilters import slugify

from hu_pin_auth.auth_hu_pin_backend import HarvardPinAbstractAuthBackend
from hu_ldap_basic.hu_directory_search import HUDirectorySearcher    


class HarvardPinWithLdapAuthBackend(HarvardPinAbstractAuthBackend):
    """This authentication backend handles callbacks after people have logged with a Harvard Pin.
    
    The "token" passed to the authenticate message is the callback url returned from the HU authentication system, including the GET arguments.
    
    Note: username is a slug of the email in the pin system
    """
    def get_or_create_user(self, lu):
        if lu is None:
            msg('user is info is None')
            return None
      
        #username = hashlib.sha224(lu['__authen_huid']).hexdigest()
        huid = lu.get('__authen_huid', None)
        if huid is None:
            msg('__authen_huid is None')            
            return None
    
        searcher = HUDirectorySearcher() 
        #kwarg = eval('lname="prasad"')
        members = searcher.find_people(**{'huid':huid})
        searcher.close_connection()
        if members is not None and len(members)==1:
            member = members[0]
            if member.mail is None:
                return None
            username = member.mail
        else:
            msg('huid lookup failed None')            
        
        print username
        
        # (3) Retrieve user's credentials
        try:
            # Check if the user exists in Django's local database
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # Create a user in Django's local database
            user = User.objects.create_user(username, email=member.mail)
            user.set_unusable_password()
            user.save()
        
        # update last name, first name, and email
        user.last_name = member.get_or_blank('sn')
        user.first_name = member.get_or_blank('givenName')
        user.email = member.mail
        user.is_staff = True
        
        user.set_unusable_password()
        user.save()
        
        user.backend = 'hu_pin_auth.auth_hu_pin_backend_ldap.HarvardPinWithLdapAuthBackend' 
        
        return user
