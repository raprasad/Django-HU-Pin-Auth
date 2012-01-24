from django.conf.urls.defaults import *

urlpatterns = patterns(
    'hu_pin_auth.views',

    url(r'^hu_auth/callback/$', 'view_handle_pin_callback', name='view_handle_pin_callback' ),

    #url(r'^hu_auth/pin-auth-fail/$', 'view_handle_pin_auth_fail', name='view_handle_pin_auth_fail' ),

)