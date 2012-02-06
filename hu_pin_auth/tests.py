import unittest
from django.test import TestCase
from django.contrib.auth.models import User

from hu_pin_auth.pin_login_handler import PinLoginHandler

        
class PinHandlerTest(TestCase):
    """Test if PinLoginHandler access permissions work properly.
    This assumes the user has successfully logged in via PIN"""
    def setUp(self):
        pass
        
    def runTest(self):
        access_dict = { 'restrict_to_existing_users':True \
                            , 'restrict_to_active_users':True \
                            , 'restrict_to_staff':False \
                            , 'restrict_to_superusers':False}

        pin_login_handler = PinLoginHandler(request, **access_dict)
        
        #-------------------------------------------------------
        msgt('check number of breadcrumb items, should be 3')
        menu_builder.show_breadcrumb_items()
        self.assertEqual(menu_builder.get_num_breadcrumbs(), 3)
        msg('actual: [%s]' % menu_builder.get_num_breadcrumbs())

        #-------------------------------------------------------
       

def suite():
    suite = unittest.TestSuite()
    suite.addTest(MenuBuilderTest('runTest'))
    return suite        
