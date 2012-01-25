from django.contrib.auth import authenticate, login
from hu_pin_auth.auth_hu_pin_backend_ldap import HarvardPinWithLdapAuthBackend
import sys

class PinLoginHandler:
    """Handles the attempt to authorize/login the user, may be used in a view
    
    ----------------------------
    sample usage in a view:
    ----------------------------
    pin_login_handler = PinLoginHandler(request)    # request object
    if pin_login_handler.did_login_succeed():
        #the_user = pin_login_handler.user # if needed
        return HttpResponseRedirect('go to login success page')
    else:
        err_dict = pin_login_handler.get_error_dict()   # get error lookup for use in template
        return render_to_response('template_dir/login_failed.html', err_dict, context_instance=RequestContext(request))

    ----------------------------
    sample usage in a template, if error occurred
    ----------------------------    
    {% if pin_auth_has_err %}
        Sorry! Login failed.
        {% if pin_auth_err_no_email_in_hu_ldap %}You do not have an email specified in the Harvard directory.{% endif %}
        {% if pin_auth_err_huid_not_found_in_hu_ldap %}Your information was not found in the Harvard directory.{% endif %}
        {% if pin_auth_err_account_not_active %}Your account is not active.  Please contact the administrator.{% endif %}
        <p>Return to the <a href="">log in page</a>.</p>
    {% endif %}
    
    ---------------------------- 
    example of using access_setting in the init   
    Access settings are Django specific and are checked AFTER a successful HU Pin login
    ----------------------------    
    # restrict to active, staff users in Django
    access_dict = { 'restrict_to_existing_users':True \
                        , 'restrict_to_active_users':True \
                        , 'restrict_to_staff':False \
                        , 'restrict_to_superusers':False}
                        
    pin_login_handler = PinLoginHandler(request, **access_dict)
    """
    def __init__(self, request, **access_settings):
        self.user = None
        
        self.has_err = False
        self.err_lookup = {}
        
        self.access_settings = access_settings
        
        self.handle_authorization(request)
    
    def did_login_succeed(self):
        if self.user is not None and not self.has_err:
            return True
        return False
    
    def get_error_dict(self):
        return self.err_lookup 
     
    def get_user(self):
        return self.user
        
    def handle_authorization(self, request):
        print '-' * 40
        print 'PinLoginHandler.handle_authorization'
        print 'request: ', request
        self.user = None
        
        if request is None:
            self.mark_err_as_true(self.err_no_request_object)
            return 
       
        if self.access_settings is not None:
            authorization_backend  = HarvardPinWithLdapAuthBackend(**self.access_settings)    
        
        self.user = authorization_backend.authenticate(request)
        if self.user:
            self.has_err= False
        else:
            self.has_err = True
            self.err_lookup = authorization_backend.get_err_flag_dict()
            
      
        
