from django.conf.urls.defaults import *

urlpatterns = patterns(
    'hu_pin_auth.views',

    url(r'^hu_auth/callback/$', 'view_handle_pin_callback', name='view_handle_pin_callback' ),

)