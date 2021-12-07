# Helpers for accessing Coverity Web Services API v8
#
# To use:
# from wscoverity import WebServiceClient, ConfigServiceClient, DefectServiceClient
# defectServiceClient = DefectServiceClient(args.host, args.port, args.ssl, args.username, args.password)
# configServiceClient = ConfigServiceClient(args.host, args.port, args.ssl, args.username, args.password)

from suds import *
from suds.client import Client
from suds.wsse import *
import ssl

# Uncomment to debug SOAP XML
#import logging
#logging.basicConfig()
#logging.getLogger('suds.client').setLevel(logging.DEBUG)
#logging.getLogger('suds.transport').setLevel(logging.DEBUG)


# -----------------------------------------------------------------------------
class WebServiceClient:
    def __init__(self, webservice_type, host, port, do_ssl, username, password):
        """Base class for clients querying the Coverity web services API.
        
        Keyword arguments:
        webservice_type -- either 'configuration' or 'defect'
        host -- host of Coverity Connect
        port -- port of Coverity Connect
        ssl -- True if to use SSL
        username -- Coverity Connect account
        password -- Coverity Connect password
        """

        url = ''
        if (do_ssl):
          url = 'https://' + host + ':' + port
        else:
          url = 'http://' + host + ':' + port
        if webservice_type == 'configuration':
            self.wsdlFile = url + '/ws/v9/configurationservice?wsdl'
        elif webservice_type == 'defect':
            self.wsdlFile = url + '/ws/v9/defectservice?wsdl'
        else:
            raise "unknown web service type: " + webservice_type

        self.client = Client(self.wsdlFile, cache=None)

        self.security = Security()
        self.token = UsernameToken(username, password)
        self.security.tokens.append(self.token)
        self.client.set_options(wsse=self.security)

    def getwsdl(self):
        """Retrieve the SOAP Client."""
        print(self.client)


# -----------------------------------------------------------------------------
class ConfigServiceClient(WebServiceClient):
    def __init__(self, host, port, ssl, username, password):
        """Instantiate the Configuration client querying the Coverity web services API.
        
        Keyword arguments:
        host -- host of Coverity Connect
        port -- port of Coverity Connect
        ssl -- True if to use SSL
        username -- Coverity Connect account
        password -- Coverity Connect password
        """
        WebServiceClient.__init__(self, 'configuration', host, port, ssl, username, password)

    def get_projects(self):
        """Get information describing all Coverity projects.
        
        Returns list of elements describing projects having the structure defined by the Coverity web services API
        """
        return self.client.service.getProjects()

    def get_project(self, projectName):
        """Get information describing a specific Coverity project.

        Keyword arguments:
        projectName -- name of Coverity project
        
        Returns list of elements having the structure defined by the Coverity web services API
        """
        pfsDO = self.client.factory.create('projectFilterSpecDataObj')
        pfsDO.namePattern = projectName

        return self.client.service.getProjects(pfsDO)

    def get_stream(self, streamName):
        """Get information describing a specific Coverity stream.

        Keyword arguments:
        streamName -- name of Coverity stream
        
        Returns list of elements having the structure defined by the Coverity web services API
        """
        sfsDO = self.client.factory.create('streamFilterSpecDataObj')
        sfsDO.namePattern = streamName

        return self.client.service.getStreams(sfsDO)

    def get_user(self, connectUser):
        """Get info about a Coverity user.

        Keyword arguments:
        connectUser -- account name within Coverity Connect
        
        Returns userDO
        """
        userDO = self.client.service.getUser(connectUser)
        return userDO

    def get_assignable_users(self):
        """Get users who can be assigned defects.
        
        Returns Set of assignable users
        """
        userDOs = []

        filterSpecDO = self.client.factory.create('userFilterSpecDataObj')
        # fill out the filterSpecDO fields to constrain the search

        PAGE_SIZE = 100  # this cannot exceed 100!

        pageSpecDO = self.client.factory.create('pageSpecDataObj')
        pageSpecDO.pageSize = PAGE_SIZE
        pageSpecDO.sortAscending = True
        pageSpecDO.startIndex = 0

        i = 0
        usersPage = None

        while True:
            pageSpecDO.startIndex = i
            usersPage = self.client.service.getUsers(filterSpecDO, pageSpecDO)
            i += pageSpecDO.pageSize

            if (usersPage.totalNumberOfRecords > 0):
                userDOs.extend(usersPage.users)

            if (i >= usersPage.totalNumberOfRecords):
                break

        assignable_users = set([])
        for userDO in userDOs:
            assignable_users.add(userDO.username)
        return assignable_users

    def get_checker_properties(self, projectName):
        """Get checker properties of a given Coverity project.  These include
        Impact categorization.

        Keyword arguments:
        projectName -- name of Coverity project (these properties are not
                       available on a stream basis)
        
        Returns dict of checkerName#subcategory#domain to checker properties
        having the structure defined by the Coverity web services API
        """
        sys.stdout.write("Fetching checker properties for project " + projectName + "...")

        projectIdDO = self.client.factory.create('projectIdDataObj')
        projectIdDO.name = projectName

        checkerPropertyDOs = self.client.service.getCheckerProperties(projectIdDO)

        checkerPropertyDict = {}
        for checkerPropertyDO in checkerPropertyDOs:
            checkerName = checkerPropertyDO.checkerSubcategoryId.checkerName
            subcategory = checkerPropertyDO.checkerSubcategoryId.subcategory
            domain = checkerPropertyDO.checkerSubcategoryId.domain
            key = "{0}#{1}#{2}".format(checkerName, subcategory, domain)
            checkerPropertyDict[key] = checkerPropertyDO

        return checkerPropertyDict
        

    def get_snapshots_info_for_stream(self, streamName):
        """Get information describing snapshots of a given Coverity stream.

        Keyword arguments:
        streamName -- name of Coverity stream
        
        Returns list of elements describing snapshot info having the structure defined by the Coverity web services API
        """
        streamIdDO = self.client.factory.create('streamIdDataObj')
        streamIdDO.name = streamName

        snapshotIds = self.client.service.getSnapshotsForStream(streamIdDO)
        snapshotsInfo = self.client.service.getSnapshotInformation(snapshotIds)
        return snapshotsInfo
        

# -----------------------------------------------------------------------------
class DefectServiceClient(WebServiceClient):
    def __init__(self, host, port, ssl, username, password):
        """Instantiate the Defect client querying the Coverity web services API.
        
        Keyword arguments:
        host -- host of Coverity Connect
        port -- port of Coverity Connect
        ssl -- True if to use SSL
        username -- Coverity Connect account
        password -- Coverity Connect password
        """
        WebServiceClient.__init__(self, 'defect', host, port, ssl, username, password)

    def create_defect_state_attribute_value(self, key, value):
        """Create data-structure representing a key-value pair to be consumed by the web services API

        Keyword arguments:
        key -- string
        value -- tring

        Return data-structure suitable for defectStateAttributeValueDataObj
        """
        attributeDefinitionIdDO = self.client.factory.create('attributeDefinitionIdDataObj')
        attributeDefinitionIdDO.name = key

        attributeValueIdDO = self.client.factory.create('attributeValueIdDataObj')
        attributeValueIdDO.name = value

        defectStateAttributeValueDO = self.client.factory.create('defectStateAttributeValueDataObj')
        defectStateAttributeValueDO.attributeDefinitionId = attributeDefinitionIdDO
        defectStateAttributeValueDO.attributeValueId = attributeValueIdDO

        return defectStateAttributeValueDO

    def assign_owner(self, triageStoreName, cid, owner, comment):
        """Programatically triage a defect.

        Keyword arguments:
        triageStoreName -- name of Coverity triage store
        cid -- defect CID
        owner -- Coverity Connect username performing the triage
        comment -- message
        """
        triageStoreIdDO = self.client.factory.create('triageStoreIdDataObj')
        triageStoreIdDO.name = triageStoreName

        mergedDefectIdDO = self.client.factory.create('mergedDefectIdDataObj')
        mergedDefectIdDO.cid = cid

        defectStateSpecDO = self.client.factory.create('defectStateSpecDataObj')
        defectStateSpecDO.defectStateAttributeValues = [
            self.create_defect_state_attribute_value('owner', owner),
            self.create_defect_state_attribute_value('comment', comment)]

        self.client.service.updateTriageForCIDsInTriageStore(triageStoreIdDO, mergedDefectIdDO, defectStateSpecDO)

    def update_ext_ref(self, triageStoreName, cid, externalRef, comment):
        """Programatically triage a defect.

        Keyword arguments:
        triageStoreName -- name of Coverity triage store
        cid -- defect CID
        externalRef -- Ext. Reference
        comment -- message
        """
        triageStoreIdDO = self.client.factory.create('triageStoreIdDataObj')
        triageStoreIdDO.name = triageStoreName

        mergedDefectIdDO = self.client.factory.create('mergedDefectIdDataObj')
        mergedDefectIdDO.cid = cid

        defectStateSpecDO = self.client.factory.create('defectStateSpecDataObj')
        defectStateSpecDO.defectStateAttributeValues = [
            self.create_defect_state_attribute_value('Ext. Reference', externalRef),
            self.create_defect_state_attribute_value('comment', comment)]

        self.client.service.updateTriageForCIDsInTriageStore(triageStoreIdDO, mergedDefectIdDO, defectStateSpecDO)

    def get_file_contents(self, streamName, fileId):

        streamIdDO = self.client.factory.create('streamIdDataObj')
        streamIdDO.name = streamName

        fileIdDO = self.client.factory.create('fileIdDataObj')
        fileIdDO.contentsMD5 = fileId['contentsMD5']
        fileIdDO.filePathname = fileId['filePathname']

        fileContentsDO = self.client.service.getFileContents(streamIdDO, fileIdDO)

        return fileContentsDO

    def get_stream_defects(self, cid, streamNames):
        """Get stream defects for a particular CID.

        Keyword arguments:
        cid -- defect CID
        streamNames -- list of Coverity stream names
        
        Returns list of elements describing stream defects having the structure defined by the Coverity web services API
        """
        mergedDefectIdDO = self.client.factory.create('mergedDefectIdDataObj')
        mergedDefectIdDO.cid = cid

        streamIdDOs = []
        for streamName in streamNames:
            streamIdDO = self.client.factory.create('streamIdDataObj')
            streamIdDO.name = streamName
            streamIdDOs.append(streamIdDO)

        streamDefectFilterSpecDO = self.client.factory.create('streamDefectFilterSpecDataObj')
        streamDefectFilterSpecDO.includeDefectInstances = True
        streamDefectFilterSpecDO.includeHistory = True
        streamDefectFilterSpecDO.streamIdList = streamIdDOs

        streamDefectDOs = self.client.service.getStreamDefects(mergedDefectIdDO, streamDefectFilterSpecDO)
        return streamDefectDOs

    def get_merged_defects_for_stream(self, streamName):
        """Get merged defects in a specific Coverity stream.

        Keyword arguments:
        streamName -- name of Coverity stream
        
        Returns list of elements describing defects having the structure defined by the Coverity web services API
        """
        # output: an array of dictionaries, one for each defect
        mergedDefects = []

        streamIdDO = self.client.factory.create('streamIdDataObj')
        streamIdDO.name = streamName

        filterSpecDO = self.client.factory.create('mergedDefectFilterSpecDataObj')
        filterSpecDO.legacyNameList = 'False'
        filterSpecDO.ownerNameList = 'Unassigned'

        sys.stdout.write("Fetching Unassigned non-Legacy merged defects in last snapshot from stream " + streamName)

        PAGE_SIZE = 1000  # this cannot exceed 2500!

        pageSpecDO = self.client.factory.create('pageSpecDataObj')
        pageSpecDO.pageSize = PAGE_SIZE
        pageSpecDO.sortAscending = True
        pageSpecDO.startIndex = 0

        snapshotScopeSpecDO = self.client.factory.create('snapshotScopeSpecDataObj')
        snapshotScopeSpecDO.showSelector = 'last()'

        i = 0
        defectsPage = None

        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            pageSpecDO.startIndex = i
            defectsPage = self.client.service.getMergedDefectsForStreams(streamIdDO, filterSpecDO, pageSpecDO, snapshotScopeSpecDO)
            i += pageSpecDO.pageSize

            if (defectsPage.totalNumberOfRecords > 0):
                mergedDefects.extend(defectsPage.mergedDefects)

            if (i >= defectsPage.totalNumberOfRecords):
                break

        # "\nFetched " + str(len(mergedDefects)) + " records."
        return mergedDefects

    def get_merged_defects_for_snapshot(self, streamName, snapshotId):
        """Get merged defects in a specific snapshot of a Coverity stream.

        Keyword arguments:
        streamName -- name of Coverity stream
        snapshotId -- snapshot ID
        
        Returns list of elements describing defects having the structure defined by the Coverity web services API
        """
        # output: an array of dictionaries, one for each defect
        mergedDefects = []

        streamIdDO = self.client.factory.create('streamIdDataObj')
        streamIdDO.name = streamName

        filterSpecDO = self.client.factory.create('mergedDefectFilterSpecDataObj')
        # filterSpecDO.legacyNameList = 'False'

        sys.stdout.write("Fetching merged defects in snapshot " + snapshotId + " from stream " + streamName)

        PAGE_SIZE = 1000  # this cannot exceed 2500!

        pageSpecDO = self.client.factory.create('pageSpecDataObj')
        pageSpecDO.pageSize = PAGE_SIZE
        pageSpecDO.sortAscending = True
        pageSpecDO.startIndex = 0

        snapshotScopeSpecDO = self.client.factory.create('snapshotScopeSpecDataObj')
        snapshotScopeSpecDO.showSelector = snapshotId

        i = 0
        defectsPage = None

        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            pageSpecDO.startIndex = i
            defectsPage = self.client.service.getMergedDefectsForStreams(streamIdDO, filterSpecDO, pageSpecDO, snapshotScopeSpecDO)
            i += pageSpecDO.pageSize

            if (defectsPage.totalNumberOfRecords > 0):
                mergedDefects.extend(defectsPage.mergedDefects)

            if (i >= defectsPage.totalNumberOfRecords):
                break

        #print "\nFetched " + str(len(mergedDefects)) + " records."
        return mergedDefects

    def get_merged_defects_for_project(self, projectName):
        """Get defects in a specific Coverity project.

        Keyword arguments:
        projectName -- name of Coverity project
        
        Returns list of elements describing defects having the structure defined by the Coverity web services API
        """
        projectIdDO = self.client.factory.create('projectIdDataObj')
        projectIdDO.name = projectName

        # output: an array of dictionaries, one for each defect
        mergedDefects = []

        filterSpecDO = self.client.factory.create('mergedDefectFilterSpecDataObj')
        # fill out the filterSpecDO fields to constrain the search

        PAGE_SIZE = 1000  # this cannot exceed 2500!

        pageSpecDO = self.client.factory.create('pageSpecDataObj')
        pageSpecDO.pageSize = PAGE_SIZE
        pageSpecDO.sortAscending = True
        pageSpecDO.startIndex = 0

        i = 0
        defectsPage = None

        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            pageSpecDO.startIndex = i
            defectsPage = self.client.service.getMergedDefectsForProject(projectIdDO, filterSpecDO, pageSpecDO)
            i += pageSpecDO.pageSize

            if (defectsPage.totalNumberOfRecords > 0):
                mergedDefects.extend(defectsPage.mergedDefects)

            if (i >= defectsPage.totalNumberOfRecords):
                break

        #print "\nFetched " + str(len(mergedDefects)) + " records."
        return mergedDefects
