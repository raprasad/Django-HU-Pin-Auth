from django.contrib.auth import authenticate, login
from hu_pin_auth.auth_hu_pin_backend_ldap import HarvardPinWithLdapAuthBackend

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
    """
    def __init__(self, request):
        self.user = None
        # error flags
        self.has_err_login_fail = False
        self.err_no_request_object = False
        self.err_no_email_in_hu_ldap = False
        self.err_huid_not_found_in_hu_ldap = False
        self.err_account_not_active = False

        self.handle_authorization(request)
    
    def did_login_succeed(self):
        if self.user is not None and not self.has_err_login_fail:
            return True
        return False
    
    def mark_err_as_true(self, selected_err=None):
        self.has_err_login_fail = True
        if selected_err is not None:
            selected_err = True
        
    def handle_authorization(self, request):
        if request is None:
            self.mark_err_as_true(self.err_no_request_object)
            return 
        
        auth = HarvardPinWithLdapAuthBackend()    
        
        user = auth.authenticate(request)
        if user is not None:
            if user.is_active:      # login success!
                login(request, user)
                self.user = user
                return 
            else:
                self.mark_err_as_true(self.err_account_not_active)      
        elif auth.err_no_email_in_hu_ldap:
            self.mark_err_as_true(self.err_no_email_in_hu_ldap)
        elif auth.err_huid_not_found_in_hu_ldap:
            self.mark_err_as_true(self.err_huid_not_found_in_hu_ldap)
        else:
            self.mark_err_as_true()

            
    def get_error_dict(self):
        return { 'pin_auth_has_err': self.has_err_login_fail \
            , 'pin_auth_err_no_email_in_hu_ldap': self.err_no_email_in_hu_ldap \
            , 'pin_auth_err_huid_not_found_in_hu_ldap': self.err_huid_not_found_in_hu_ldap \
            , 'pin_auth_err_account_not_active': self.err_account_not_active \
        }
        
