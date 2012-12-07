from django.contrib.auth import authenticate, login
from hu_authzproxy.hu_authz_pin_backend import HarvardAuthZProxyBackend
from hu_authzproxy.authz_proxy_validation_info import  AuthZProxyValidationInfo
import sys

     
        
class AuthZProxyLoginHandler:
    """Handles the attempt to authorize/login the user, may be used in a view
    
    ----------------------------
    sample usage in a view:
    ----------------------------
    pin_login_handler = AuthZProxyLoginHandler(request, validation_settings)    # request object

    validation_settings = { 'app_names' : [']}


    if pin_login_handler.did_login_succeed():
        #the_user = pin_login_handler.user # if needed
        return HttpResponseRedirect('go to login success page')
    else:
        err_dict = pin_login_handler.get_error_dict()   # get error lookup for use in template
        return render_to_response('template_dir/login_failed.html', err_dict, context_instance=RequestContext(request))

    (i) Sample file: see hu_authzpoxy/views.py
    
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
    
    (i) Sample file: see templates/view_pin_login_failed.html
    
    
    ---------------------------- 
    # How Django handles authentication after pin is verfied. 
    # 'access_settings' are specific to how Django handles its User objects
    # (Again, these permissions are checked AFTER a successful HU Pin login)
    #
    # example of using 'access_settings' in the init   
    ----------------------------    
    # restrict to active, staff users in Django
    access_settings = { 'restrict_to_existing_users':True \
                        , 'restrict_to_active_users':True \
                        , 'restrict_to_staff':False \
                        , 'restrict_to_superusers':False}
                        
    pin_login_handler = AuthZProxyLoginHandler(request, app_names, user_request_ip, gnupghome,  **access_settings)
    
    
    """
    def __init__(self, authz_validation_info, **access_settings):
        """
        authz_validation_info is an AuthZProxyValidationInfo object
        """
        self.user = None
        self.authz_validation_info = authz_validation_info
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
        
    def handle_authorization(self):
        self.user = None
        
        if request is None:
            pass    # This error is handled and marked in the authorization_backend below

        if self.access_settings is not None:
            authorization_backend  = HarvardAuthZProxyBackend( self.authz_validation_info, **self.access_settings)    
        else:
            authorization_backend  = HarvardAuthZProxyBackend(self.authz_validation_info)
        
        self.user = authorization_backend.authenticate()
        if self.user:
            self.has_err= False
        else:
            self.has_err = True
            self.err_lookup = authorization_backend.get_err_flag_dict()
            
      
        
