"""
When given an AuthZ Token, validate layers 1 through 4
"""
import os
from urlparse import urlparse, parse_qs
from hashlib import sha1
import urllib
import gnupg
from datetime import datetime

def msg(m): print m
def dashes(): msg('-'*40)
def msgt(m): dashes(); msg(m); dashes()
def msgx(m): dashes(); msg(m); print 'exiting'; sys.exit(0)

"""
https://www.pin1.harvard.edu/pin/authenticate?__authen_application=FAS_FCOR_MCB_GRDB_AUTHZ
_DEV

https://www.pin1.harvard.edu/pin/authenticate?__authen_application=FAS_FCOR_MCB_GRDB_AUTHZ_DEV

#http://140.247.108.24/mcb-grad/hu_azp/no-access?authorizationError=SYSTEM_CURRENTLY_UNAVAILABLE


"""

URL_KEY_AZP_TOKEN = '_azp_token'



"""
zcheck = AuthZChecker( url_full_path=self.authz_validation_info.get_url_fullpath()\
                , app_names=self.authz_validation_info.app_names
                , gnupghome=self.authz_validation_info.gnupghome\
                , gpg_passphrase=self.authz_validation_info.gpg_passphrase
                , user_request_ip=self.authz_validation_info.get_client_ip()
                , is_debug=self.authz_validation_info.is_debug
                )
"""
class AuthZChecker:
    def __init__(self, authz_validation_info):
        """
        authz_validation_info is an AuthZProxyValidationInfo object
        """
        self.expiration_time_seconds = 2 * 60 # 2 minutes until PGP log in message expires 
        self.url_full_path = authz_validation_info.get_url_fullpath()
        self.app_names = authz_validation_info.app_names
        self.user_request_ip = authz_validation_info.get_client_ip()
        self.gnupghome = authz_validation_info.gnupghome
        self.is_debug = authz_validation_info.is_debug
        self.gpg_passphrase = authz_validation_info.gpg_passphrase
        
        self.custom_attributes = None
        self.user_fname = None
        self.user_lname = None
        self.user_email = None
        
        self.is_verified = False
        self.url_dict = None
        
        self.err_msgs = []
        self.err_attrs = ['err_url_parse', 'err_no_azp_token', 'err_layer1_gnupg_home_directory_not_found', 'err_layer1_decrypt_failed', 'err_layer2_decrypt_failed', 'err_layer2_signature_fail', 'err_layer3_not_two_parts', 'err_layer3_attribute_data_part_fail',   'err_layer3_authen_data_part_fail', 'err_layer4_app_name_not_matched', 'err_layer4_ip_check_failed', 'err_layer4_token_time_elapsed', 'err_layer4_time_check_exception', 'err_missing_user_vals' ]
        self.reset_flags()
    
        self.decoded_data_string_for_potential_err_msg = None # for passing back in error messages
    
        self.check_authz_return_url()
        self.set_user_vals()

    def set_user_vals(self):
        if self.custom_attributes is None:
            return
        
        self.user_fname = self.custom_attributes.get('givenname', None)
        self.user_lname = self.custom_attributes.get('sn', None)
        self.user_email = self.custom_attributes.get('mail', None)
    
    def get_user_vals(self):
        return { 'fname': self.user_fname\
                ,'lname': self.user_lname\
                ,'email': self.user_email\
                }
    
    def has_user_vals(self):
        if not (self.user_fname and self.user_lname and self.user_email):
            self.err_missing_user_vals = True
            self.add_err('Missing user values.  Need mail, sn, givenname.  Have: %s' % self.custom_attributes)
            return False
        
        return True
    
    
    def show_user_vals(self):
        if self.custom_attributes is None:
            return

        for k, v in self.custom_attributes.iteritems():
            print '%s: [%s]' % (k, v)
        #print 'user_email: %s' % self.user_email
        #print 'user_lname: %s' % self.user_lname
        #print 'user_fname: %s' % self.user_fname
    
    
    def did_authz_check_pass(self):
        for err_attr in self.err_attrs:
            if self.__dict__.get(err_attr, False) is True:
                return False
        return True
    
    
    def show_errs(self):
        #print 'AuthZChecker: errors'
        err_found = False
        for err_attr in self.err_attrs:
            #print '%s -> [%s]'% (err_attr, self.__dict__.get(err_attr))
            if self.__dict__.get(err_attr, False) is True:
                print 'Error: %s' % err_attr
                err_found = True
        
        for idx, err_msg in enumerate(self.err_msgs):
            if idx == 0: 
                print '\n-- Errors --'
            print err_msg        

        if not err_found:
            print 'No errors'
        
    def reset_flags(self):
        self.is_verified = False
        
        for err_attr in self.err_attrs:
            self.__dict__.update({err_attr: False})

    def get_pgp_msg(self, decoded_data_string, decoded_signature_string):
        if decoded_data_string is None or decoded_signature_string is None:
            return
            
        return """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

%s
-----BEGIN PGP SIGNATURE-----
Version: 5.0

%s
-----END PGP SIGNATURE-----""" % (decoded_data_string, decoded_signature_string)

    def get_decoded_data_string_for_err_msg(self):
        return self.decoded_data_string_for_potential_err_msg
        
    def add_err(self, msg):
        self.err_msgs.append(msg)
        #print msg
        
    def check_authz_return_url(self):
        """
        One big ugly function that does the following:
            - Layer 1:
                - Parses the url and pulls out the _azp_token
                - Decrypts the data from the _azp_token.  Use the private key, matching the public key sent for AuthZ registration
            - Layer 2:
                - Splits the token decrypted data into 2 parts: (a) authentication/custom data and (b) signature strings
                - Verifies the data using the AuthZ public key
            - Layer 3:
                - Splits the authentication data and attribute data
                - Saves the attribute data to the 
            - Layer 4:
                - Checks the application name against the expected app name
                - Checks the client IP address
                - Looks for an expired timestamp (more than 2 minutes)
        """
        
        # break the url into key/value pairs
        try:
            self.url_dict = parse_qs(urlparse(self.url_full_path).query)
        except:
            self.err_url_parse = True
            return

        for k, v in self.url_dict.iteritems():
            self.url_dict.update({k: v[0].strip()})
        
        #---------------------------------------------------
        # Layer 1: Check the "_azp_token" encrypted_data_string 
        #---------------------------------------------------
        encrypted_data_string = self.url_dict.get(URL_KEY_AZP_TOKEN, None)
        if encrypted_data_string is None:
            self.err_no_azp_token = True
            return
                
        if not os.path.isdir(self.gnupghome):
            self.add_err('directory not found: %s' % self.gnupghome)
            self.err_layer1_gnupg_home_directory_not_found = True
            return
            
        gpg_obj = gnupg.GPG(gnupghome=self.gnupghome, verbose=self.is_debug)
        
        if self.gpg_passphrase:
            decrypted_data = gpg_obj.decrypt(encrypted_data_string\
                                            , passphrase=self.gpg_passphrase)
        else:
            decrypted_data = gpg_obj.decrypt(encrypted_data_string)
            
        #print '\n\ndecrypted_data: %s' % decrypted_data

        if decrypted_data is None:
            self.err_layer1_decrypt_failed = True
            return
        
        #---------------------------------------------------
        # Layer 2: Unencrypted Data and Signature Strings
        #   - split by '&' and decode each part
        #   - check that the first parameter has been encoded the AuthZProxy's PGP private key
        #---------------------------------------------------
        decrypt_parts = decrypted_data.data.split('&')
        if not len(decrypt_parts) == 2:
            self.err_layer2_decrypt_failed = True
            return
            
        url_encoded_data_string,  url_encoded_signature_string = decrypt_parts

        decoded_data_string = urllib.unquote(url_encoded_data_string) 
        self.decoded_data_string_for_potential_err_msg = decoded_data_string
        decoded_signature_string = urllib.unquote(url_encoded_signature_string)

        #print 'url_encoded_data_string: [%s]' % decoded_data_string
        #print ''
        #print 'url_encoded_signature_string: [%s]' % decoded_signature_string
        
        pgp_msg = self.get_pgp_msg(decoded_data_string, decoded_signature_string)

        v = gpg_obj.verify(pgp_msg)
        if v is not None and v.valid==True:
            pass
            #print 'yes'
        else:
            self.add_err('Signature fail.\npgp message: [%s]\ndecoded_data_string: [%s]\ndecoded_signature_string: [%s]' % (pgp_msg, decoded_data_string, decoded_signature_string))
            self.err_layer2_signature_fail = True
            return

        #---------------------------------------------------
        # Layer 3: Authentication Data and Attribute List Strings
        #---------------------------------------------------
        # 12345678|2012-12-06T17:18:44Z|140.247.10.93|FAS_FCOR_MCB_GRDB_AUTHZ|P&mail=raman_prasad%40harvard.edu|sn=Prasad|givenname=Raman
        
        layer3_data_parts = decoded_data_string.split('&')
        if not len(layer3_data_parts) == 2:
            self.err_layer3_not_two_parts = True
            return
        authentication_data, attribute_data = layer3_data_parts

        # split apart attribute data
        # e.g. mail=raman_prasad%40harvard.edu|sn=Prasad|givenname=Raman
        try:
            self.custom_attributes = {}
            for pair in attribute_data.split('|'):
                if len(pair.split('=')) == 2:
                    k, v = pair.split('=')
                    self.custom_attributes[k] = urllib.unquote(v)            
        except:
            self.err_layer3_attribute_data_part_fail = True
            self.add_err('original attribute_data string: [%s]' % attribute_data)
            return
                        
        
        # split apart Authentication Data 
        authen_data_parts = authentication_data.split('|')
        if not len(authen_data_parts) == 5:
            self.err_layer3_authen_data_part_fail = True
            self.add_err('original authentication_data string: [%s]' % authentication_data)
            return        
            
        #---------------------------------------------------
        # Layer 4: Authentication Data
        #---------------------------------------------------
        # 12345678|2012-12-06T17:18:44Z|140.247.10.93|FAS_FCOR_MCB_GRDB_AUTHZ|P
        user_id, login_timestamp, client_ip, app_id, id_type = authen_data_parts

        # (4a) check application name
        if not app_id in self.app_names:
            self.err_layer4_app_name_not_matched = True
            self.add_err('authz app id: [%s] actual app id: [%s]' % (app_id, self.app_names))
            self.add_err('\nAdditional info: \ndecoded_data_string: [%s]\ndecoded_signature_string: [%s]' % ( decoded_data_string, decoded_signature_string))
            
            return
        
        #return # skip IP and timestamp verifiation settings
        
        # (4b) verify the IP
        if self.is_debug and self.user_request_ip == '127.0.0.1':
            # allow client address of 127.0.0.1 for testing
            pass
        elif not client_ip == self.user_request_ip:
            self.err_layer4_ip_check_failed = True            
            self.add_err('authz client_ip: [%s] user ip: [%s]' % (client_ip, self.user_request_ip))
            self.add_err('\nAdditional info: \ndecoded_data_string: [%s]\ndecoded_signature_string: [%s]' % (decoded_data_string, decoded_signature_string))
            
            return
                
        # (4c) Check the timestamp
        dt_pat = '%Y-%m-%dT%H:%M:%SZ'
        try:
            login_datetime_obj = datetime.strptime(login_timestamp, dt_pat)
            time_now = datetime.utcnow()
            time_diff = time_now - login_datetime_obj
            if time_diff.seconds < 0 or time_diff.seconds > self.expiration_time_seconds:
                self.err_layer4_token_time_elapsed = True
                msg('%s second rule failed verification: \nauthz msg: [%s] \nsystem: [%s]' % (self.expiration_time_seconds, login_timestamp, time_now))
                self.add_err('\nAdditional info: \ndecoded_data_string: [%s]\ndecoded_signature_string: [%s]' % ( decoded_data_string, decoded_signature_string))
                
                return
        except:
            self.err_layer4_time_check_exception = True
            
            msg('time diff failed: auth z timestamp str [%s]' % (login_timestamp))
            self.add_err('\nAdditional info:\ndecoded_data_string: [%s]\ndecoded_signature_string: [%s]' % ( decoded_data_string, decoded_signature_string))
            
            return None
            
        
        
TEST_AZP_MSG = """https://adminapps.mcb.harvard.edu/mcb-grad/hu_azp/callback?_azp_token=-----BEGIN+PGP+MESSAGE-----%0D%0AVersion%3A+Cryptix+OpenPGP+0.20050418%0D%0A%0D%0AhQEMA%2FVD%2FGQNXDZ2AQgArrnoVaz2SsDBvIcIdi%2BtRbOwlXZf0S0jNA3OCpL%2F5D5b%0D%0ADQIXT5D9urAGJPyjN0kB%2BG2%2BL0e22fJy3S3QjDhbYPm97GKywHUJDW3K9BagYEaD%0D%0A1Mry8XRGDY5bf%2F6xfMq%2Bq3tT%2FGs1WpfDQLT7zzzRa0T6dOusP9RjWm6%2F%2FfLrPtSw%0D%0AIko8vmgL7vdvU4QjqmUb0dMsUw0VEfsagRDcSTAglfhryOFWf7%2B%2BDerJqagHQSdH%0D%0A%2BGYkxCCcdwvWe9Ta7qJcVIM%2BfFaqYTDSSjE1h%2Fz3XDeilUgJAyCVRl%2FRCcoWwhrn%0D%0A47lSV2DxIjVo1D%2BWQeFR%2BbPS9S3uU9af%2BdLM2Zh4sqUBKdYB12oj1GVnVaHxTSA2%0D%0Ac5kKetfDdS5mAv3prmQdkYrPoF1gBwNfM1NGjjDC38Uhz%2BhDavCVVsx6FaVP2Tvu%0D%0AncCgA2Zrj46lTObQsbNcIYUgi5XNA2c3ArrbKGc2LmgFqaNjUP6LrcysurpojK74%0D%0ArAVJiXcGaeD8meCGZGZyMlm%2FcYpAPY5ikknTq88c70Eq2EVHFvV2HKB7FACrTkSH%0D%0AsKs5ZaSAvm2h7%2BxtvXIjhixkzRRxDiq5qZJq6VIK9bYkbzsJ%2FCVxJ0htkHq8yuYG%0D%0AtMAe3iE54kaGZpaCm4ozjqXPQa47%2FASgcUBOd6qMX%2FFLnOdWzxENCSwtXX1qEZvT%0D%0ALqOsDULeZtwtrNXWB11zO4As4etNbd%2FQbAjET%2FkhjJgBNuOw5vUQZ28g8Q%3D%3D%0D%0A%3DgFeY%0D%0A-----END+PGP+MESSAGE-----%0D%0A"""



if __name__ == '__main__':
    """
    Run test
    """
    from authz_proxy_validation_info import AuthZProxyValidationInfo

    authz_validation_info = AuthZProxyValidationInfo(request=None\
                                 ,app_names=['FAS_FCOR_MCB_GRDB_AUTHZ']\
                                 , gnupghome='gpg-test'
                                 , gpg_passphrase=None
                                 , is_debug=True)
                                            
    authz_validation_info.set_url_fullpath_manually(TEST_AZP_MSG)                             
    authz_validation_info.set_client_ip_manually('140.247.108.24')
    
    zcheck = AuthZChecker(authz_validation_info)
    
    zcheck.show_errs()
    zcheck.show_user_vals()

