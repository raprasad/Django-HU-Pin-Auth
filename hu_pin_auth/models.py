from django.db import models
import datetime
        

"""
add a query string to the HU Callback depending on the app
(1) ?lt=mcb_admin 
(2) ?lt=poster_printer
etc.?

"""

'''
class HarvardLoginTypeHandler(models.Model):
    app_name = models.CharField(max_length=255)
    
    def __unicode__(self):
         return app_name
         #return '%s - %s' % (self.service, self.embryo_donor_strain)
    
    class Meta:
        pass
        #ordering = ('service', 'embryo_donor_strain', )
        #verbose_name = 'Embryo Information Record'
'''
