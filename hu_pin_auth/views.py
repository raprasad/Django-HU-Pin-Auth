from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.core.urlresolvers import reverse
from django.contrib.auth import authenticate, login
from hu_pin_auth.pin_login_handler import PinLoginHandler


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
    # See "pin_login_handler.PinLoginHandler" class handler for more info
    # This allows anyone with a harvard pin to log in
    access_settings = { 'restrict_to_existing_users':False \
                         , 'restrict_to_active_users':False \
                         , 'restrict_to_staff':False \
                         , 'restrict_to_superusers':False}

    pin_login_handler = PinLoginHandler(request, **access_settings)    # request object
    if pin_login_handler.did_login_succeed():
        login(request, pin_login_handler.get_user())
        return HttpResponseRedirect(next)
    else:
        print 'login failed'
        err_dict = pin_login_handler.get_error_dict()   # get error lookup for use in template
        print '-' * 20
        for k,v in err_dict.iteritems():
            print ' %s -> [%s]' % (k,v)
        return render_to_response('view_pin_login_failed.html', err_dict, context_instance=RequestContext(request))
    
   