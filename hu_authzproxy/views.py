from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.core.urlresolvers import reverse
from django.contrib.auth import authenticate, login
from django.conf import settings
from hu_authzproxy.authzproxy_login_handler import AuthZProxyLoginHandler
from hu_authzproxy.authz_proxy_validation_info import AuthZProxyValidationInfo


def view_handle_pin_callback(request):
    """View to handle pin callback
    If authentication is succesful:
        - go to a specified 'next' link 
        - or default to the django admin index page
    """
    #
    if request.GET and request.GET.get('next', None) is not None:
        next = request.GET.get('next')
    else:
        next =  reverse('admin:index', {})

    # How Django handles authentication after pin is verfied. 
    # See "authz_pin_login_handler.PinLoginHandler" class handler for more info
    # This allows anyone with a harvard pin to log in
    access_settings = { 'restrict_to_existing_users':True \
                         , 'restrict_to_active_users':True \
                         , 'restrict_to_staff':True \
                         , 'restrict_to_superusers':False}

    authz_validation_info = AuthZProxyValidationInfo(request=request\
                                 ,app_names=settings.HU_PIN_LOGIN_APP_NAMES\
                                 , gnupghome=settings.GNUPG_HOME)


    authz_pin_login_handler = AuthZProxyLoginHandler(authz_validation_info=authz_validation_info\
                                     , **access_settings)    
                                     
    if authz_pin_login_handler.did_login_succeed():
        login(request, authz_pin_login_handler.get_user())
        return HttpResponseRedirect(next)
    else:
        print 'login failed'
        err_dict = authz_pin_login_handler.get_error_dict()   # get error lookup for use in template
        print '-' * 20
        for k,v in err_dict.iteritems():
            print ' %s -> [%s]' % (k,v)
        return render_to_response('view_authz_login_failed.html', err_dict, context_instance=RequestContext(request))
    
