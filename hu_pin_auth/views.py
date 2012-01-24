from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.core.urlresolvers import reverse
from django.contrib.auth import authenticate, login
#from hu_pin_auth.auth_hu_pin_backend import HarvardPinSimpleAuthBackend
from hu_pin_auth.pin_login_handler import PinLoginHandler

'''

'''
def view_handle_pin_callback(request):
    
    # if authentication is succesful, go to a specified 'next' link or deftaul to the admin
    #
    if request.GET and request.GET.get('next', None) is not None:
        next = request.GET.get('next')
    else:
        next =  reverse('admin:index', {})

    pin_login_handler = PinLoginHandler(request)    # request object
    if pin_login_handler.did_login_succeed():
        return HttpResponseRedirect(next)
    else:
        err_dict = pin_login_handler.get_error_dict()   # get error lookup for use in template
        return render_to_response('view_pin_login_failed.html', err_dict, context_instance=RequestContext(request))
    
    '''
    print 'request.path: %s' % request.get_full_path()
    #user = auth.authenticate(request.get_full_path())
    user = auth.authenticate(request)
    print 'user: %s' % user
    if user is not None:
        if user.is_active:
            login(request, user)
            return HttpResponseRedirect(next)
        else:
            return 'account not active err!'
    return HttpResponse('auth fail')
    '''
    