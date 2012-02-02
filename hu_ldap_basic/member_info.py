"""Allows the results of an LDAP query to be placed into a python object

- Distinguishes between single attribute objects (e.g. userID) and lists (e.g. 'memberOf')

sample use:

raw_ldap_result = [('cn=RobNoName M Smith+uid=Smithaadfjldfjdfabcdefghijk123, ou=people, o=Harvard University Core, dc=huid, dc=harvard, dc=edu', {'co': ['United States'], 'uid': ['Smithaadfjldfjdfabcdefghijk123'], 'harvardEduPostalAddressInternal': [''], 'harvardeduschool': ['ECS', 'EXT'], 'generationQualifier': [''], 'harvardeduofficeaddressprivacy': ['5'], 'st': ['MA'], 'departmentNumber': ['1234567'], 'cn': ['RobNoName M Smith'], 'title': ['Some Title'], 'facsimileTelephoneNumber': [''], 'harvardeduidnumber': ['12345678'], 'harvardedufaxprivacy': ['5'], 'harvardEduFerpaPastStudentIndicator': ['FALSE'], 'harvardeduemployeeprivacy': ['5'], 'postalCode': ['02138'], 'mail': ['RobNoName_Smith@harvard.edu'], 'postalAddress': ['RobNoName M Smith$Harvard, Some Address$Cambridge MA 02138'], 'harvardeduimageprivacy': ['1'], 'harvardeduprimejobdn': ['cn=Smithaadfjldfjdfabcdefghijk123 JOB 0, ou=jobs, o=Harvard University Core, dc=huid, dc=harvard, dc=edu'], 'harvardedumailprivacy': ['5'], 'c': ['USA'], 'harvardedusuffixqualifier': [''], 'edupersonaffiliation': ['employee'], 'employeeNumber': ['12345678'], 'harvardeduregisteredsortname': ['Smith RobNoName M'], 'harvardEduDirectoryListing': ['1$+1 617 123 4567$V$O$D$Northwest Building 190.02$$5$E$O'], 'harvardedumiddlename': ['M'], 'harvardedustudentyear': [''], 'telephoneNumber': ['+1 617 495 5722'], 'harvardedudisplayaddress': ['Some Building 1123'], 'givenName': ['RobNoName'], 'displayName': [''], 'harvardEduHRDepartmentShortDescription': ['FAS'], 'harvardEduFerpaStatus': ['FALSE'], 'harvardeduphoneprivacy': ['5'], 'harvardedujobdn': ['cn=Smithaadfjldfjdfabcdefghijk123 JOB 0, ou=jobs, o=Harvard University Core, dc=huid, dc=harvard, dc=edu'], 'l': ['Cambridge'], 'personalTitle': [''], 'harvardeduregisteredname': ['RobNoName M Smith'], 'sn': ['Smith'], 'harvardEduOfficeInternalPostalCode': ['HIJKL09']})]

> single_listing = raw_ldap_result[0]
> distinguished_name, ldap_dict = single_listing 
> mi = MemberInfo(ldap_dict)
> mi.givenName
RobNoName
> mi.employeeNumber
12345678
>for school in mi.harvardeduschool
... print school
ECS
EXT

"""

""" Attributes retrieved for a user.  
Quick copy/paste from Excel - this may need some help:) """

MEMBER_ATTRIBUTE_LIST = [ 'memberOf', 'employeeNumber', 'harvardEduIDNumber', 'harvardEduIDCardNumber', 'harvardEduGender', 'harvardEduBirthDate', 'distinguishedName', 'dn', 'userID', 'uid', 'personalTitle', 'givenName', 'harvardEduMiddleName', 'surname', 'sn', 'generationQualifier', 'harvardEduSuffixQualifier', 'commonName', 'cn', 'harvardEduRegisteredName', 'harvardEduRegisteredSortName', 'displayName', 'harvardEduDisplaySortName', 'eduPersonAffiliation', 'harvardEduPersonaNonGrata', 'harvardEduImagePrivacy', 'harvardEduCardDisabled', 'harvardEduCurrentIDCard', 'harvardEduSpecialRoleStatus', 'harvardEduOtherSpecialStatus', 'organizationName', 'o', 'objectClass', 'harvardEduSpecialPrivacy', 'harvardEduBorrowerCode', 'harvardEduEmployeePrivacy', 'departmentNumber', 'title', 'harvardEduPrimeJobDN', 'harvardEduJobDN', 'harvardEduLongerServiceEmployee', 'harvardEduRetireeSpecialStatus', 'harvardEduHRPersonStatus', 'harvardEduLastJobTerminatedOn', 'harvardEduHRDepartmentShortDescription', 'harvardEduStudentPrivacy', 'harvardEduSchool', 'harvardEduStudentStatus', 'harvardEduStudentSpecialStatus', 'harvardEduGraduationDate', 'harvardEduStudentYear', 'harvardEduResidenceHouse', 'harvardEduHouseOfRecord', 'harvardEduBoardHouse', 'harvardEduOnBoardPlan', 'harvardEduSISStatus', 'harvardEduFerpaStatus', 'harvardEduFerpaPastStudentIndicator', 'harvardEduLastDateOfAttendance', 'mail', 'harvardEduMailPrivacy', 'harvardEduDisplayAddress', 'telephoneNumber', 'harvardEduPhonePrivacy', 'facsimileTelephoneNumber', 'fax', 'harvardEduFaxPrivacy', 'harvardEduDirectoryListing', 'homeTelephoneNumber', 'homePhone', 'harvardEduHomePhonePrivacy', 'mobileTelephoneNumber', 'mobile', 'harvardEduMobilePrivacy', 'harvardEduPostalAddressInternal', 'postalAddress', 'localityName', 'l', 'stateOrProvinceName', 'st', 'harvardEduOfficeInternalPostalCode', 'postalCode', 'c', 'countryName', 'co', 'friendlyCountryName', 'harvardEduOfficeAddressPrivacy', 'harvardEduOfficeAddressType', 'harvardEduOfficeAddrSource', 'harvardEduOfficeAddrUpdatedBy', 'harvardEduOfficeAddrUpdatedOn', 'harvardEduHomePostalAddressInternal', 'homePostalAddress', 'harvardEduHomeLocality', 'harvardEduHomeState', 'harvardEduHomeInternalPostalCode', 'harvardEduHomePostalCode', 'harvardEduHomeFriendlyCountryName', 'harvardEduHomeAddressPrivacy', 'harvardEduHomeAddressType', 'harvardEduHomeAddrSource', 'harvardEduHomeAddrUpdatedBy', 'harvardEduHomeAddrUpdatedOn', 'harvardEduStudentOriginalPhone', 'harvardEduStudentDormRoom', 'harvardEduStudentMailingAddress', 'harvardEduDormAddressPrivacy', 'harvardEduMailingAddress', 'harvardEduIDExpirationDate', 'harvardEduIDLogin', 'harvardEduIDOwner', 'roleOccupant',  'harvardEduIsPrimaryJob', 'departmentNumber', 'harvardEduJobStartDate', 'harvardEduJobEndDate', 'harvardEduJobStatus', 'harvardEduJobNumber', 'distinguishedName', 'dn', 'commonName', 'cn', 'objectClass', 'harvardEduJobCode', 'manager', 'harvardEduEmploymentStatus', 'harvardEduPayGroup', 'harvardEduEmployeeClass', 'harvardEduJobLocationCode', 'harvardEduJobIsUnpaid']

NON_LIST_MEMBER_ATTRIBUTES = MEMBER_ATTRIBUTE_LIST[0:]
# needs adjustment
LIST_ATTRS = ['title', 'memberOf', 'eduPersonAffiliation', 'harvardEduSchool']
for attr in LIST_ATTRS:
    NON_LIST_MEMBER_ATTRIBUTES.remove(attr) 


class MemberInfo:
    """ Used to hold AD User information from LDAP"""
    
    def __init__(self, lookup):
        """ Uses an LDAP dictionary for the constructor """
        for attr in MEMBER_ATTRIBUTE_LIST:
            # look up every value in the MEMBER_ATTRIBUTE_LIST
            try:
                val = lookup.get(attr, None) 
                if val is None:
                    val = lookup.get(attr.lower(), None)      # some attributes are all lowercase in ldap, but mixed case in docs               
            except AttributeError:
                val = None
                
            # if attribute is not a list, take the 1st value
            # e.g, if harvardeduphoneprivacy = ['5'], use harvardeduphoneprivacy[0] -> '5'
            if attr in NON_LIST_MEMBER_ATTRIBUTES and not val==None:
                val = val[0]
                
            self.__dict__.update({ attr :val })            
    
    
    def get_or_blank(self, attr_name):
        """Return the value or an empty string ("") if it is None"""
        if attr_name is None:
            return ''

        val = self.__dict__.get(attr_name, None)
        if val == None or val =='':
            return ''
        return val
        
    def get_or_neg1(self, attr_name):
        """Return the value or -1 if it is None"""
        if attr_name is None:
            return -1
            
        val = self.__dict__.get(attr_name, None)
        if val == None or val =='':
            return -1
        return val
        
    def show(self):
        """Print all the values in the dictionary, with keys sorted"""
        keys = self.__dict__.keys()
        keys.sort()
        for k in keys:
            val = self.__dict__.get(k)
            if val:
                print '%s: [%s]' % (k, val)
         
    def __unicode__(self):
        """ Return the display name """
        if self.displayName is not None and not self.displayName == '':
            return self.displayName
        return '%s %s' % (self.givenName, self.cn)
