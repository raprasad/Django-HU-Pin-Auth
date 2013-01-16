

class AuthZProxyValidationInfo:
    """
    Container for information needed to check an AuthZProxy url
    
    request = Django request object containing the url as well as the client IP address

    app_names = Registered app name or names to check.  Use a list in case more than one legit app.  e.g. ['FAS_DEPT_DB_APP', 'FAS_DEPT_DB_APP2'] 

    gnupghome = # fullpath to .gnupg. directory, e.g. "/home/some-dir/.gnupg"
    """
    def __init__(self, request, app_names, gnupghome, gpg_passphrase=None, is_debug=False):
        self.request = request
        self.app_names = app_names 
        self.gnupghome = gnupghome  
        self.gpg_passphrase = gpg_passphrase 
        self.is_debug = is_debug    # allows client IPs of 127.0.0.1
    
        self.url_fullpath = None
        self.client_ip = None
        
        
    def set_url_fullpath_manually(self, url_fullpath):
        if url_fullpath is None:
            return
            
        self.url_fullpath = url_fullpath
    
    
    def set_client_ip_manually(self, client_ip):
        if client_ip is None:
            return
            
        self.client_ip = client_ip
    
    def get_url_fullpath(self):
        # check for manually entered url
        if self.url_fullpath is not None:
            return self.url_fullpath
        
        # get url from request object
        if self.request is None:
            return None
            
        try:
            return self.request.get_full_path()
        except:
            return None
            
            
    def get_client_ip(self):
        # check for manually entered client IP
        if self.client_ip is not None:
            return self.client_ip
        
        if self.request is None:
            return None

        try:
            return self.request.META.get('REMOTE_ADDR', None)
        except:
            return None