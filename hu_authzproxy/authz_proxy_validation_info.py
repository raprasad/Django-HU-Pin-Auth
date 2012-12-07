

class AuthZProxyValidationInfo:
    """
    Container for information needed to check an AuthZProxy url
    
    request = Django request object containing the url as well as the client IP address

    app_names = Registered app name or names to check.  Use a list in case more than one legit app.  e.g. ['FAS_DEPT_DB_APP', 'FAS_DEPT_DB_APP2'] 

    gnupghome = # fullpath to .gnupg. directory, e.g. "/home/some-dir/.gnupg"
    """
    def __init__(self, request, app_names, gnupghome, is_debug=False):
        self.request = request
        self.app_names = app_names 
        self.gnupghome = gnupghome  
        self.is_debug = is_debug    # allows client IPs of 127.0.0.1
    
    def get_url_fullpath(self):
        if self.request is None:
            return None
            
        try:
            return self.request.get_full_path()
        except:
            return None
            
            
    def get_client_ip(self):
        if self.request is None:
            return None

        try:
            return self.request.META.get('REMOTE_ADDR', None)
        except:
            return None