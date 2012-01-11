from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.core.urlresolvers import reverse
from django.contrib.auth import authenticate, login
#from hu_pin_auth.auth_hu_pin_backend import HarvardPinSimpleAuthBackend
from hu_pin_auth.auth_hu_pin_backend_ldap import HarvardPinWithLdapAuthBackend

'''

'''
def view_handle_pin_callback(request):
    
    auth = HarvardPinWithLdapAuthBackend()
    
    if request.GET:
        next = request.GET.get('next', '/mcb-grants/grant-admin/')
    else:
        next = 'no next'
        
    print 'request.path: %s' % request.get_full_path()
    #user = auth.authenticate(request.get_full_path())
    user = auth.authenticate(request)
    print 'user: %s' % user
    if user is not None:
        if user.is_active:
            login(request, user)
            return HttpResponseRedirect(next)
        else:
            return 'account not active!'
    return HttpResponse('auth fail')
    
    