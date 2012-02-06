"""
To work with HU PIN or other apps that may use LDAP lookups

I. DEFAULT: To run this script STANDALONE (w/o a Django settings file):
    (A) Set 'USE_SETTINGS_IN_DJANGO_PROJECT' to False
    (B) Under "Manually set LDAP credentials" below: manually set:
        (1) LDAP_CUSTOMER_NAME 
        (2) LDAP_CUSTOMER_PASSWORD 
        (3) LDAP_SERVER 

II. To use this with a Django Project
    (A) Below, set 'USE_SETTINGS_FROM_DJANGO_PROJECT' to True
    (B) Define these three variables in your settings file:
        (a) LDAP_CUSTOMER_NAME 
        (b) LDAP_CUSTOMER_PASSWORD
        (c) LDAP_SERVER 
            test: ldaps://hu-ldap-test.harvard.edu
            prod: ldaps://hu-ldap.harvard.edu

"""
import sys

# True - Assumes LDAP Credentials are in an accessible Django 'settings' file
# False - Run script standalone
USE_SETTINGS_FROM_DJANGO_PROJECT = False

if USE_SETTINGS_FROM_DJANGO_PROJECT:
    if __name__=='__main__':
        sys.path.append('path to your project')
        from django.core.management import setup_environ
        import settings
        setup_environ(settings)
    else:
        from django.conf import settings


import ldap
from member_info import MemberInfo  # convenience class for accessing ldap values

#------------------------
# Set LDAP options
#------------------------
ldap.set_option(ldap.OPT_REFERRALS, 0)  # turn off referrals
ldap.set_option (ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)  # version 3
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)  # allow self-signed cert

#------------------------
# LDAP test/prod servers
#------------------------
LDAP_TEST_SERVER = 'ldaps://hu-ldap-test.harvard.edu'
LDAP_PROD_SERVER =  'ldaps://hu-ldap.harvard.edu'

#------------------------
# LDAP credentials 
#------------------------
if USE_SETTINGS_FROM_DJANGO_PROJECT:
    LDAP_CUSTOMER_NAME = settings.LDAP_CUSTOMER_NAME       # username/id for binding to ldap server   
    LDAP_CUSTOMER_PASSWORD = settings.LDAP_CUSTOMER_PASSWORD    # password for binding to ldap server   
    LDAP_SERVER = LDAP_TEST_SERVER = settings.LDAP_SERVER
else:
    #---------------------------------
    # Manually set LDAP credentials 
    #---------------------------------
    LDAP_CUSTOMER_NAME = '' 
    LDAP_CUSTOMER_PASSWORD = '' 
    LDAP_SERVER = LDAP_TEST_SERVER  
    

class HUDirectorySearcher:
    """
    Performs and LDAP query and places the results, if any, in MemberInfo objects

    Searches by lname, fname, fname + lname, email, huid, etc, etc
    
    example:
        >kwargs = { 'lname':'smith', 'fname':'mich*' }
        >searcher = HUDirectorySearcher(show_debug=True)    # starts ldap connection
        >searcher.find_people(**kwargs)

        returns: None or [MemberInfo object #1, MemberInfo object #2, etc]
    """
    def __init__(self, show_debug=True):
        
        self.AD_SEARCH_DN = "ou=people, o=Harvard University Core, dc=huid, dc=harvard, dc=edu";
        
        self.show_debug = show_debug
        
        self.ldap_url = LDAP_SERVER
        
        self.ad_bind_usr = 'uid=%s, ou=applications,o=Harvard University Core,dc=huid,dc=harvard,dc=edu' % LDAP_CUSTOMER_NAME
        self.ad_bind_pw = LDAP_CUSTOMER_PASSWORD
    
        self.ldap_conn = self.get_ldap_connection()
    
    def msg(self, m):
        if self.show_debug:
            print m
    
    def msgt(self, m):
        self.msg('-' * 40)
        self.msg(m)
                
    def close_connection(self):
        if self.ldap_conn is None:
            self.msg('ldap connection not found')
            return 
            
        self.ldap_conn.unbind_s()
        self.msg('connection closed.')

    def get_ldap_connection(self):
        
        self.msgt('(1) attempt to initialize url: %s' % self.ldap_url)        
        conn = ldap.initialize(self.ldap_url) 
        self.msg('url initialized')
        
        self.msgt('(2) attempt to bind to server with LDAP_CUSTOMER_NAME = "%s"' % LDAP_CUSTOMER_NAME )
        try:
            conn.simple_bind_s(self.ad_bind_usr, self.ad_bind_pw)
        except ldap.NO_SUCH_OBJECT, e:
            raise ValueError('\nLdap error NO_SUCH_OBJECT\nCould be bad username: "%s"):\n%s\n' % (self.ad_bind_usr, e))
        except ldap.INVALID_CREDENTIALS, e:
            raise ValueError('\nLdap error INVALID_CREDENTIALS\nMay be bad password.\n%s\n' % (e))
        except ldap.SERVER_DOWN, e:
            raise ValueError('\nLdap error SERVER_DOWN\nCheck server url: %s:\n%s\n' % (self.ldap_url, e))
        except:
            print "Unexpected error:", sys.exc_info()[0]
            raise

        self.msg('bind successful')
        
        return conn
        
        
    def find_people(self, **kwargs):

        # process **kwargs
        kw_ad_attrs_dict = { 'lname' : 'sn'
                            , 'fname' : 'givenName'
                            , 'email' : 'mail'
                            , 'huid' : 'harvardEduIDNumber'
                            , 'uid' : 'uid'
                            , 'role': 'eduPersonAffiliation'
                            }
        
        filter_pairs = []
        for kw, ad_kw in kw_ad_attrs_dict.iteritems():
            kwarg_val = kwargs.get(kw, None)
            if kwarg_val is not None:
                filter_pairs.append('(%s=%s)' % (ad_kw, kwarg_val))
        
        if len(filter_pairs) == 0:
            self.msg('None of these keywords found in search filter: %s'  %  '\n - '.join(kw_ad_attrs_dict.keys()))
            return
        elif len(filter_pairs) == 1:
            search_filter = filter_pairs[0]
        else:
            search_filter = '(&%s)' % ''.join(filter_pairs)
        

        # Set the fields to return
        FIELDS_TO_RETURN = ['*']    # fields to return, '*': return everything
        #FIELDS_TO_RETURN = ['sn', 'givenName', 'title', 'mail']   # return last name, first name, title, and email

        # search the people section of HU Core
        AD_SEARCH_DN = "ou=people, o=Harvard University Core, dc=huid, dc=harvard, dc=edu";
        self.msg('using filter: %s' % search_filter)
        
        try:
            results = self.ldap_conn.search_ext_s(self.AD_SEARCH_DN,ldap.SCOPE_SUBTREE, search_filter, FIELDS_TO_RETURN)  
        except UnicodeEncodeError:
            self.msg('ERROR: filter had UnicodeEncodeError')
            return None
        
        
        self.msg('search complete - raw results:')
        self.msgt(results)
        self.msgt('formatted results')
        
        members = []
        for idx, r in enumerate(results):
            cn, lu = r      
            self.msgt('(%s) %s' % (idx+1, cn))
            self.msg(lu)
            mi = MemberInfo(lu)     # convenience class from 'helper_classes.py'
            members.append(mi)
            if self.show_debug:
                mi.show()
       
        if members == []:
            self.msg('>> no results from search')
            return None
        
        return members


def show_usage():
    print '-' * 40
    print """Below are some command line examples.  

Valid keywords: lname, fname, email, huid, uid

>python hu_directory_search.py lname=smith fname=r*    
>python hu_directory_search.py huid=12345678
>python hu_directory_search.py uid=Smithaadfjldfjdfabcdefghijk123

The keywords may be used alone or in combination. Feel free to add your own to the dict called "kw_ad_attrs_dict."
"""
    print '-' * 40
    
if __name__=='__main__':
    if len(sys.argv) > 1:
        lu = {}
        for arg in sys.argv[1:]:
            if arg.find('=') > -1:
                kw, val = arg.split('=')
                lu.update({ kw:val})
        searcher = HUDirectorySearcher(show_debug=True) 
        members = searcher.find_people(**lu)
        searcher.close_connection()
    else:
        show_usage()
        