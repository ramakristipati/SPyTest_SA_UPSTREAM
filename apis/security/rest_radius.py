from spytest.rest import Rest
from spytest import st
import utilities.common as utils
import requests


def _convert_kwargs_list(**kwargs):
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    return kwargs


def validate_rest_status(output):
    result = True
    if not isinstance(output, dict):
        st.error('The given output is not a dict')
        return False
    if not output:
        st.error('The output is empty')
        return False
    for entry in output.values():
        if entry.get('status') not in [200, 201, 204]:
            result = False
    return result


class CiscoIse():
    def __init__(self, server_type=None, ser_ip=None, ser_port='443', username=None, password=None):
        self.server_ip = ser_ip
        self.server_port = ser_port
        self.username = username
        self.password = password
        # ip = '{}:{}'.format(self.server_ip, '9060')
        # self.session = Rest().reinit(ip, self.username, self.password, self.password)
        self.ip_port = '{}:{}'.format(self.server_ip, self.server_port)
        self.session = Rest().reinit(self.ip_port, self.username, self.password, self.password)

    def rest_op(self, method, path, **kwargs):
        req = dict()
        output = dict()
        exception = ''
        headers = kwargs.pop('headers', {"Accept": "application/json", "Content-type": "application/json"})
        params = kwargs.pop('params', None)
        username = kwargs.pop('rest_username', 'ersadmin')
        password = kwargs.pop('rest_password', 'Broadcom#123')
        rest_timeout = int(kwargs.pop('rest_timeout', 20))
        validate_status = kwargs.get('validate_status', False)
        req['data'] = kwargs.pop('data', None)
        req['operation'] = method
        req['path'] = path
        req['instance'] = dict()
        req['instance']['rest_username'] = username
        req['instance']['rest_password'] = password
        req['instance']['headers'] = headers
        req['instance']['rest_timeout'] = rest_timeout
        if params: req['instance']['params'] = params
        st.log("HTTP METHOD : {}".format(method.upper()))
        st.log("URL : https://{}{}".format(self.ip_port, path))
        iteration = 3
        for iter in range(1, iteration + 1):
            try:
                output = self.session.apply(req)
                break
            except (requests.ReadTimeout, requests.ConnectTimeout, requests.ConnectionError) as exp:
                st.error("REST OPERATION : {} - iteration {}".format(exp, iter))
                exception = str(exp)
                self.session = Rest().reinit(self.ip_port, self.username, self.password, self.password)
            except Exception as e:
                st.error("REST OPERATION : {} - iteration {}".format(e, iter))
                exception = str(e)
        st.log('REST OUTPUT: {}'.format(output))
        if not output:
            expt = 'with exception: {}'.format(exception) if exception else ''
            msg = 'RADIUS_SERVER_FAIL: Rest request to radius server is failed {}'.format(expt)
            st.report_env_fail('msg', msg)
        if validate_status:
            return validate_rest_status(output)
        return output

    def get_adminuser(self, **kwargs):
        path = '/ers/config/adminuser'
        st.banner("Get the admin Users")
        name = kwargs.get('name')
        ret_id_map = kwargs.get('ret_id_map')
        params = {}
        if name:
            params = {'filter': 'name.CONTAINS.{}'.format(name)}
        output = self.rest_op('get', path, params=params, **kwargs)
        if ret_id_map:
            ret_val = dict()
            if output and output.get('0') and output['0'].get('output') and output['0']['output'].get(
                    'SearchResult') and output['0']['output']['SearchResult'].get('resources'):
                for item in output['0']['output']['SearchResult'].get('resources'):
                    id = item.get('id')
                    name = item.get('name')
                    if id is not None and name is not None:
                        ret_val.update({name: id})
            return ret_val
        return output

    def get_adminuser_by_id(self, id, **kwargs):
        path = '/ers/config/adminuser/{}'.format(id)
        st.banner("Get the admin Users by id {}".format(id))
        output = self.rest_op('get', path, **kwargs)
        return output

    def create_internal_user(self, username, password, **kwargs):
        '''
        data={
              "InternalUser" : {
                "name" : "sonic_test_name_1",
                "description" : "description",
                "enabled" : 'true',
                "email" : "email@domain.com",
                "password" : "password",
                "firstName" : "lakshmi",
                "lastName" : "narayana",
                "changePassword" : 'true',
                "identityGroups" : "a176c430-8c01-11e6-996c-525400b48521",
                "passwordIDStore" : "Internal Users"
              }
            }

        create_internal_user(['user_test_1', 'user_test_2'], ['test_pwd','test_pwd'])
        create_internal_user('user_test_1', password='password')

        :param username:
        :param password:
        :param kwargs:
        :return:
        '''
        ret_val = []
        kwargs = _convert_kwargs_list(**kwargs)
        path = '/ers/config/internaluser'
        username = utils.make_list(username)
        password = utils.make_list(password)
        for index, user in enumerate(username):
            data = dict()
            data['InternalUser'] = {}
            data['InternalUser']['name'] = user
            data['InternalUser']['password'] = password[index]
            data['InternalUser']['description'] = kwargs['description'][index] if kwargs.get(
                'description') is not None else ''
            data['InternalUser']['enabled'] = kwargs['enabled'][index] if kwargs.get('enabled') is not None else 'true'
            data['InternalUser']['identityGroups'] = kwargs['identityGroups'][index] if kwargs.get(
                'identityGroups') is not None else 'a176c430-8c01-11e6-996c-525400b48521'
            data['InternalUser']['passwordIDStore'] = kwargs['passwordIDStore'][index] if kwargs.get(
                'passwordIDStore') is not None else 'Internal Users'
            data['InternalUser']['changePassword'] = kwargs['changePassword'][index] if kwargs.get(
                'changePassword') is not None else 'false'

            st.banner("Create the User Identity for user '{}'".format(user))
            output = self.rest_op('post', path, data=data, **kwargs)
            if output: ret_val.append(output)
        return ret_val

    def update_internal_user(self, username, **kwargs):
        '''
        update_internal_user('user_test_1', password='change')
        update_internal_user('user_test_1', password='change', description='modified')

        :param username:
        :param kwargs:
        :return:
        '''
        ret_val = []
        keys = ['password', 'description', 'enabled', 'identityGroups', 'passwordIDStore']
        username = utils.make_list(username)
        kwargs = _convert_kwargs_list(**kwargs)
        for index, user in enumerate(username):
            path = '/ers/config/internaluser/name/{}'
            data = dict()
            data['InternalUser'] = {}
            for param in keys:
                if kwargs.get(param) is not None:
                    data['InternalUser'][param] = kwargs[param][index]
            st.banner("Update the User Identity for user '{}'".format(user))
            output = self.rest_op('put', path.format(user), data=data)
            if output: ret_val.append(output)
        return ret_val

    def get_all_internal_user(self, **kwargs):
        '''
        get_all_internal_user()

        :return:
        '''
        path = '/ers/config/internaluser'
        st.banner("Get the all internal Users")
        output = self.rest_op('get', path, **kwargs)
        return output

    def get_internal_user_by_name(self, name):
        '''
        get_internal_user_by_name('user_test_2')

        :param name:
        :return:
        '''
        path = '/ers/config/internaluser/name/{}'
        st.banner("Get the all internal Users")
        output = self.rest_op('get', path.format(name))
        return output

    def delete_internal_user(self, username):
        '''
        delete_internal_user_by_name('user_test_2')
        delete_internal_user_by_name(['user_test_1','user_test_2'])

        :param username:
        :return:
        '''
        ret_val = []
        path = '/ers/config/internaluser/name/{}'
        username = utils.make_list(username)
        for user in username:
            st.banner("Deleet the User Identity for user '{}'".format(user))
            output = self.rest_op('delete', path.format(user))
            if output: ret_val.append(ret_val)
        return ret_val

    def create_network_device(self, ipaddress, **kwargs):
        '''
        create_network_device('22.3.4.5', mask='20', radius_secreat_key='hello123', description='testuser')
        create_network_device('22.3.4.5', mask='20', radius_secreat_key='hello123', description='testuser', name='test_user')

        :param ipaddress:
        :param kwargs:
        :return:
        '''
        path = '/ers/config/networkdevice'
        mask = kwargs.get('mask', '32')
        radius_secreat_key = kwargs.get('radius_secreat_key', None)
        tacacs_secreat_key = kwargs.get('tacacs_secreat_key', None)
        params = ['radius_secreat_key', 'tacacs_secreat_key', 'profileName', 'coaPort', 'description']
        data = dict()
        data['NetworkDevice'] = dict()
        data['NetworkDevice']['name'] = kwargs.get('name', ipaddress)
        data['NetworkDevice']['NetworkDeviceIPList'] = [{'ipaddress': ipaddress, 'mask': mask}]
        for param in params:
            if param == 'radius_secreat_key' and kwargs.get(param) is not None:
                data['NetworkDevice']['authenticationSettings'] = {'radiusSharedSecret': radius_secreat_key}
            elif param == 'tacacs_secreat_key' and kwargs.get(param) is not None:
                data['NetworkDevice']['tacacsSettings'] = {'sharedSecret': tacacs_secreat_key}
            elif kwargs.get(param) is not None:
                data['NetworkDevice'][param] = kwargs[param]

        st.banner("Create the network device for client {}".format(ipaddress))
        output = self.rest_op('post', path, data=data, **kwargs)
        return output

    def update_network_device(self, client_name, **kwargs):
        '''
        update_network_device('test_user', mask='24', ipaddress='1.2.3.4', description='changed_ip', radius_secreat_key='secret123')

        :param client_name:
        :param kwargs:
        :return:
        '''
        path = '/ers/config/networkdevice/name/{}'
        radius_secreat_key = kwargs.get('radius_secreat_key', None)
        tacacs_secreat_key = kwargs.get('tacacs_secreat_key', None)
        params = ['radius_secreat_key', 'tacacs_secreat_key', 'profileName', 'coaPort', 'description', 'ipaddress',
                  'mask']
        data = dict()
        data['NetworkDevice'] = dict()
        data['NetworkDevice']['name'] = client_name
        device_ip = {}
        for param in params:
            if param == 'radius_secreat_key' and kwargs.get(param) is not None:
                data['NetworkDevice']['authenticationSettings'] = {'radiusSharedSecret': radius_secreat_key}
            elif param == 'tacacs_secreat_key' and kwargs.get(param) is not None:
                data['NetworkDevice']['tacacsSettings'] = {'sharedSecret': tacacs_secreat_key}
            elif param in ['ipaddress', 'mask'] and kwargs.get(param) is not None:
                device_ip.update({param: kwargs[param]})
            elif kwargs.get(param) is not None:
                data['NetworkDevice'][param] = kwargs[param]
        if device_ip: data['NetworkDevice']['NetworkDeviceIPList'] = [device_ip]

        st.banner("Update the network device '{}'".format(client_name))
        output = self.rest_op('put', path.format(client_name), data=data)
        return output

    def delete_network_device(self, client_name):
        '''
        delete_network_device('test_user')

        :param client_name:
        :return:
        '''
        path = '/ers/config/networkdevice/name/{}'
        st.banner("Delete the network device '{}'".format(client_name))
        output = self.rest_op('delete', path.format(client_name))
        return output

    def get_network_device(self, client_name, **kwargs):
        '''
        delete_network_device('test_user')

        :param client_name:
        :param kwargs:
        :return:
        '''
        path = '/ers/config/networkdevice/name/{}'
        st.banner("Delete the network device '{}'".format(client_name))
        output = self.rest_op('get', path.format(client_name), **kwargs)
        return output

    def get_all_downloadable_acl(self, **kwargs):
        '''
        get_all_downloadable_acl(dacl='DENY_ALL_IPV6_TRAFFIC')
        get_all_downloadable_acl(ret_id_map=True)
        get_all_downloadable_acl()

        :param ret_id_map: Return dict of dacl name and respective id
        :param dacl: Reurn dict of name and its id
        :param kwargs:
        :return:
        '''
        path = '/ers/config/downloadableacl'
        ret_id_map = True if 'ret_id_map' in kwargs else False
        dacl = utils.make_list(kwargs.get('dacl', []))
        st.banner("Get the dowloadable acls")
        output = self.rest_op('get', path, **kwargs)
        if ret_id_map or dacl:
            ret_val = dict()
            if output and output.get('0') and output['0'].get('output') and output['0']['output'].get(
                    'SearchResult') and output['0']['output']['SearchResult'].get('resources'):
                for item in output['0']['output']['SearchResult'].get('resources'):
                    id = item.get('id')
                    name = item.get('name')
                    if id is not None and name is not None and not dacl:
                        ret_val.update({name: id})
                    elif dacl and name in dacl:
                        ret_val.update({name: id})
            return ret_val
        return output

    def get_downloadable_acl_by_id(self, id):
        '''
        get_downloadable_acl_by_id('03d8c390-3e1b-11ed-b235-8e7d2046fbdf')

        :param id:
        :return:
        '''
        path = '/ers/config/downloadableacl/{}'
        st.banner("Get the dowloadable acl for id '{}".format(id))
        output = self.rest_op('get', path.format(id))
        return output

    def create_downloadable_acl(self, **kwargs):
        '''
        {
          "DownloadableAcl": {
            "name": "name",
            "description": "description",
            "dacl": "permit ip any any",
            "daclType": "IPV4"
          }
        }
        create_downloadable_acl(name='test_dacl', dacl="permit ip any 11.1.1.1/32\npermit ip any 11.1.1.2/32", daclType='IP_AGNOSTIC', description='test dacl')
        create_downloadable_acl(name='test_dacl', dacl="permit ip any 11.1.1.1/32", description='test dacl')

        :param kwargs:
        :return:
        '''

        path = '/ers/config/downloadableacl'
        if kwargs.get('name') is None:
            st.error('Mandatory argument "acl_name" is not provided')
            return False
        kwargs = _convert_kwargs_list(**kwargs)
        for index, acl in enumerate(kwargs['name']):
            data = dict()
            data['DownloadableAcl'] = {}
            data['DownloadableAcl']['name'] = acl
            data['DownloadableAcl']['description'] = kwargs['description'][index] if kwargs.get(
                'description') is not None else ''
            data['DownloadableAcl']['dacl'] = kwargs['dacl'][index] if kwargs.get(
                'dacl') is not None else "permit ip any any"
            data['DownloadableAcl']['daclType'] = 'IP_AGNOSTIC'

            st.banner("Create the downloadable acl '{}'".format(acl))
            output = self.rest_op('post', path, data=data, **kwargs)
        return output

    def update_downloadable_acl(self, id, name, dacl, description=None, daclType='IP_AGNOSTIC'):
        '''
        update_downloadable_acl(id='0eee9b60-4262-11ed-b235-8e7d2046fbdf', dacl="permit ip any 14.1.1.1/32",name='test_dacl')

        :param id:
        :param name:
        :param dacl:
        :param description:
        :param daclType:
        :return:
        '''
        path = '/ers/config/downloadableacl/{}'
        data = dict()
        data['DownloadableAcl'] = {}
        data['DownloadableAcl']['id'] = id
        data['DownloadableAcl']['name'] = name
        data['DownloadableAcl']['dacl'] = dacl
        data['DownloadableAcl']['daclType'] = daclType
        if description: data['DownloadableAcl']['description'] = description

        st.banner("Update the downloadable acl '{}'".format(id))
        output = self.rest_op('put', path.format(id), data=data)
        return output

    def delete_downloadable_acl(self, id):
        '''
        delete_downloadable_acl(['faaa67b0-40ea-11ed-b235-8e7d2046fbdf', '1090a300-40eb-11ed-b235-8e7d2046fbdf'])
        delete_downloadable_acl('1090a300-40eb-11ed-b235-8e7d2046fbdf')

        :param id:
        :return:
        '''
        id = utils.make_list(id)
        for acl_id in id:
            path = '/ers/config/downloadableacl/{}'
            st.banner("Delete the downloadable acl '{}'".format(acl_id))
            self.rest_op('delete', path.format(acl_id))

    def get_autherization_profile(self, **kwargs):
        '''
        get_autherization_profile(name='test_auth_profile')
        get_autherization_profile()

        :param kwargs:
        :return:
        '''
        path = '/ers/config/authorizationprofile'
        name = kwargs.get('name')
        if name:
            path = path + '/name/' + name

        st.banner("Get the autherization profile")
        output = self.rest_op('get', path, **kwargs)
        return output

    def delete_autherization_profile(self, id):
        '''
        delete_autherization_profile(['faaa67b0-40ea-11ed-b235-8e7d2046fbdf', '1090a300-40eb-11ed-b235-8e7d2046fbdf'])
        delete_autherization_profile('1090a300-40eb-11ed-b235-8e7d2046fbdf')

        :param id:
        :return:
        '''
        id = utils.make_list(id)
        for profile in id:
            path = '/ers/config/authorizationprofile/{}'
            st.banner("Delete the autherization profile '{}'".format(profile))
            self.rest_op('delete', path.format(profile))

    def create_autherization_profile(self, **kwargs):
        '''
        create_autherization_profile(name='auth_profile', description='sonic ft test profile', advancedAttributes=[('Cisco','cisco-av-pair','test'), ('Radius','Session-Timeout','80')], accessType='ACCESS_ACCEPT', vlan='20',daclName='dummy', webRedirection={'acl':'rdacl','staticIPHostNameFQDN':'1.1.1.1'})

        :param kwargs:
        :return:
        '''

        path = '/ers/config/authorizationprofile'
        name = kwargs.get('name')
        advancedAttributes = utils.make_list(kwargs.get('advancedAttributes', []))
        webRedirection = kwargs.get('webRedirection')
        vlan = kwargs.get('vlan')
        reauth = kwargs.get('reauth')

        if kwargs.get('name') is None:
            st.error('Mandatory argument "auth_profile" is not provided')
            return False

        data = dict()
        data['AuthorizationProfile'] = {}

        cmdList = ['name', 'description', 'advancedAttributes', 'accessType', 'authzProfileType', 'vlan', 'reauth',
                   'webRedirection', 'acl', 'trackMovement', 'agentlessPosture', 'serviceTemplate',
                   'easywiredSessionCandidate', 'daclName', 'ipv6ACLFilter', 'profileName', 'ipv6DaclName', 'webAuth']

        for param in cmdList:
            if param == 'advancedAttributes' and advancedAttributes:
                data['AuthorizationProfile']['advancedAttributes'] = []
                for val in advancedAttributes:
                    if len(val) != 3:
                        st.error('Expecting dir name, attr name and attr value')
                        continue
                    attr = {
                        "leftHandSideDictionaryAttribue": {
                            "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                            "dictionaryName": val[0],
                            "attributeName": val[1]
                        },
                        "rightHandSideAttribueValue": {
                            "AdvancedAttributeValueType": "AttributeValue",
                            "value": val[2]
                        }
                    }
                    data['AuthorizationProfile']['advancedAttributes'].append(attr)
            elif param == 'vlan' and vlan is not None:
                data['AuthorizationProfile']['vlan'] = {"nameID": vlan, "tagID": 1}
            elif param == 'reauth' and reauth is not None:
                data['AuthorizationProfile']['reauth'] = {"timer": reauth, "connectivity": "RADIUS_REQUEST"}
            elif param == 'webRedirection' and webRedirection:
                WebRedirectionType = webRedirection.get('WebRedirectionType', 'ClientProvisioning')
                acl = webRedirection.get('acl', '')
                portalName = webRedirection.get('portalName', 'Client Provisioning Portal (default)')
                staticIPHostNameFQDN = webRedirection.get('staticIPHostNameFQDN', '')
                attr = {
                    "WebRedirectionType": WebRedirectionType,
                    "acl": acl,
                    "portalName": portalName,
                    "staticIPHostNameFQDN": staticIPHostNameFQDN,
                }
                data['AuthorizationProfile']['webRedirection'] = attr
            elif kwargs.get(param) is not None:
                data['AuthorizationProfile'][param] = kwargs[param]

        st.banner("Create the autherization profile '{}'".format(name))
        output = self.rest_op('post', path, data=data, **kwargs)
        return output

    def update_autherization_profile(self, id, **kwargs):
        '''
        update_autherization_profile('6713b510-42fc-11ed-b235-8e7d2046fbdf',name='auth_profile', description='sonic ft test profile', advancedAttributes=[('Cisco','cisco-av-pair','test'), ('Radius','Session-Timeout','80')], vlan='20',daclName='dummy', webRedirection={'acl':'rdacl','staticIPHostNameFQDN':'1.1.1.1'})

        :param kwargs:
        :return:
        '''

        path = '/ers/config/authorizationprofile/{}'
        advancedAttributes = utils.make_list(kwargs.get('advancedAttributes', []))
        webRedirection = kwargs.get('webRedirection')
        vlan = kwargs.get('vlan')
        reauth = kwargs.get('reauth')

        if kwargs.get('name') is None:
            st.error('Mandatory argument "auth_profile" is not provided')
            return False

        data = dict()
        data['AuthorizationProfile'] = {}
        data['AuthorizationProfile']['id'] = id

        cmdList = ['name', 'description', 'advancedAttributes', 'accessType', 'authzProfileType', 'vlan', 'reauth',
                   'webRedirection', 'acl', 'trackMovement', 'agentlessPosture', 'serviceTemplate',
                   'easywiredSessionCandidate', 'daclName', 'ipv6ACLFilter', 'profileName', 'ipv6DaclName', 'webAuth']

        for param in cmdList:
            if param == 'advancedAttributes' and advancedAttributes:
                data['AuthorizationProfile']['advancedAttributes'] = []
                for val in advancedAttributes:
                    if len(val) != 3:
                        st.error('Expecting dir name, attr name and attr value')
                        continue
                    attr = {
                        "leftHandSideDictionaryAttribue": {
                            "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                            "dictionaryName": val[0],
                            "attributeName": val[1]
                        },
                        "rightHandSideAttribueValue": {
                            "AdvancedAttributeValueType": "AttributeValue",
                            "value": val[2]
                        }
                    }
                    data['AuthorizationProfile']['advancedAttributes'].append(attr)
            elif param == 'vlan' and vlan is not None:
                data['AuthorizationProfile']['vlan'] = {"nameID": vlan, "tagID": 1}
            elif param == 'reauth' and reauth is not None:
                data['AuthorizationProfile']['reauth'] = {"timer": reauth, "connectivity": "RADIUS_REQUEST"}
            elif param == 'webRedirection' and webRedirection:
                WebRedirectionType = webRedirection.get('WebRedirectionType', 'ClientProvisioning')
                acl = webRedirection.get('acl', '')
                portalName = webRedirection.get('portalName', 'Client Provisioning Portal (default)')
                staticIPHostNameFQDN = webRedirection.get('staticIPHostNameFQDN', '')
                attr = {
                    "WebRedirectionType": WebRedirectionType,
                    "acl": acl,
                    "portalName": portalName,
                    "staticIPHostNameFQDN": staticIPHostNameFQDN,
                }
                data['AuthorizationProfile']['webRedirection'] = attr
            elif kwargs.get(param) is not None:
                data['AuthorizationProfile'][param] = kwargs[param]

        st.banner("Update the autherization profile")
        output = self.rest_op('put', path.format(id), data=data)
        return output

    def create_device_admin_policy_set(self, **kwargs):
        '''
        {
          "default": false,
          "name": "test-policy",
          "description": null,
          "hitCounts": 1439,
          "rank": 1,
          "state": "enabled",
          "condition": {
            "link": null,
            "conditionType": "ConditionOrBlock",
            "isNegate": false,
            "children": [
              {
                "link": null,
                "conditionType": "ConditionAttributes",
                "isNegate": false,
                "dictionaryName": "Radius",
                "attributeName": "User-Name",
                "operator": "equals",
                "dictionaryValue": null,
                "attributeValue": "00:00:00:00:09:78"
              },
              {
                "link": null,
                "conditionType": "ConditionAttributes",
                "isNegate": false,
                "dictionaryName": "Radius",
                "attributeName": "User-Name",
                "operator": "equals",
                "dictionaryValue": null,
                "attributeValue": "00:00:00:00:09:79"
              }
            ]
          },
          "serviceName": "Default Network Access",
          "isProxy": false,
        }
        cisco.create_device_admin_policy_set(name='test_policy', description='sonic test policy', condition={'conditionType': 'ConditionAttributes', 'dictionaryName': 'Radius', 'attributeName': 'User-Name', 'operator': 'equals', 'attributeValue': 'testname1234567890'}, serviceName='Default Network Access')
        cisco.create_device_admin_policy_set(name='test_policy', description='sonic test policy', condition={'conditionType': 'ConditionOrBlock', 'children': [{'conditionType': 'ConditionAttributes', 'dictionaryName': 'Radius', 'attributeName': 'User-Name', 'operator': 'equals', 'attributeValue': 'testname1234567890'},{'conditionType': 'ConditionAttributes', 'dictionaryName': 'Radius', 'attributeName': 'User-Name', 'operator': 'equals', 'attributeValue': 'testname123456'}]})

        :param kwargs:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set'
        name = kwargs.get('name')
        serviceName = kwargs.get('serviceName', 'Default Network Access')
        if not name:
            st.error('Mandatory argument "policy_set" is not provided')
            return False
        cmdList = ['name', 'description', 'rank', 'condition', 'state', 'isProxy', 'default']
        data = dict()

        for param in cmdList:
            if kwargs.get(param) is not None:
                data[param] = kwargs[param]
        data['serviceName'] = serviceName

        st.banner("Create the device admin policy set")
        output = self.rest_op('post', path, data=data, **kwargs)
        return output

    def update_device_admin_policy_set(self, policy_id, **kwargs):
        '''
        cisco.update_device_admin_policy_set(name='test_policy', description='sonic test policy', condition={{'conditionType': 'ConditionAttributes', 'dictionaryName': 'Radius', 'attributeName': 'User-Name', 'operator': 'equals', 'attributeValue': 'testname1234567890'}}, serviceName='Default Network Access')
        cisco.update_device_admin_policy_set(name='test_policy', description='sonic test policy', condition={'conditionType': 'ConditionOrBlock', 'children': [{'conditionType': 'ConditionAttributes', 'dictionaryName': 'Radius', 'attributeName': 'User-Name', 'operator': 'equals', 'attributeValue': 'testname1234567890'},{'conditionType': 'ConditionAttributes', 'dictionaryName': 'Radius', 'attributeName': 'User-Name', 'operator': 'equals', 'attributeValue': 'testname123456'}]})

        :param policy_id:
        :param kwargs:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set/{}'.format(policy_id)
        name = kwargs.get('name')
        serviceName = kwargs.get('serviceName', 'Default Network Access')
        if not name:
            st.error('Mandatory argument "policy_set" is not provided')
            return False
        cmdList = ['name', 'description', 'rank', 'condition', 'state', 'isProxy', 'default']
        data = dict()

        for param in cmdList:
            if kwargs.get(param) is not None:
                data[param] = kwargs[param]
        data['serviceName'] = serviceName

        st.banner("Create the device admin policy set")
        output = self.rest_op('put', path, data=data)
        return output

    def get_device_admin_policy_set(self, **kwargs):
        '''
        get_device_admin_policy_set(id='d46653a7-3439-4393-9c02-906a2da84627')
        get_device_admin_policy_set(policy_name='SONiC_PAC_Spytest_MAB_IPv6')

        :param kwargs:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set'
        ret_id_map = kwargs.get('ret_id_map', False)
        policy_name = utils.make_list(kwargs.get('policy_name', []))
        id = kwargs.get('id')
        if id:
            path = path + '/' + id

        st.banner("Get the device admin policy set")
        output = self.rest_op('get', path)
        if ret_id_map or policy_name:
            ret_val = dict()
            if output and output.get('0') and output['0'].get('output') and output['0']['output'].get('response'):
                for item in output['0']['output']['response']:
                    id = item.get('id')
                    name = item.get('name')
                    if id is not None and name is not None and not policy_name:
                        ret_val.update({name: id})
                    elif policy_name and name in policy_name:
                        ret_val.update({name: id})
            return ret_val
        return output

    def delete_device_admin_policy_set(self, id):
        '''
        delete_device_admin_policy_set(['faaa67b0-40ea-11ed-b235-8e7d2046fbdf', '1090a300-40eb-11ed-b235-8e7d2046fbdf'])
        delete_device_admin_policy_set('1090a300-40eb-11ed-b235-8e7d2046fbdf')

        :param id:
        :return:
        '''
        id = utils.make_list(id)
        for profile in id:
            path = '/api/v1/policy/network-access/policy-set/{}'
            st.banner("Delete the device admin policy set '{}'".format(profile))
            self.rest_op('delete', path.format(profile))

    def create_device_admin_authentication_rule(self, policy_id, **kwargs):
        '''
        {
            "rule": {
                "default": false,
                "name": "Authentication Rule 2",
                "rank": 0,
                "state": "enabled",
                "condition": {
                  "conditionType": "ConditionReference",
                  "isNegate": false,
                  "name": "Wired_MAB",
                  "id": "9a74ebd6-9855-49d8-9a68-ac66f17bd53a",
                  "description": "A condition to match MAC Authentication Bypass service based authentication requests from switches, according to the corresponding MAB attributes defined in the device profile."
                }
            },
          "identitySourceName": "Internal Users",
          "ifAuthFail": "REJECT",
          "ifUserNotFound": "REJECT",
          "ifProcessFail": "DROP",
        }
        create_device_admin_authentication_rule('e177defb-e97e-4369-8400-97894619eff7', rule={'name': 'Authentication Rule 1', 'condition': {'conditionType': 'ConditionReference', 'name': 'Wired_MAB','id': '9a74ebd6-9855-49d8-9a68-ac66f17bd53a'}})
        create_device_admin_authentication_rule('e177defb-e97e-4369-8400-97894619eff7', rule={'name': 'Authentication Rule 2', 'condition': {'conditionType': 'ConditionReference', 'name': 'Wired_802.1X','id': '9e7f92dd-179f-4ed4-aafa-d8768ba26988'}})
        create_device_admin_authentication_rule('dbe1f1a4-044b-40d0-ad33-9e4ef8bd2897', rule={'name': 'Authentication Rule 3', 'condition': "conditionType": "ConditionAndBlock", "children": [{'conditionType': 'ConditionReference', 'name': 'Wired_MAB','id': '9a74ebd6-9855-49d8-9a68-ac66f17bd53a'}, {'conditionType': 'ConditionReference', 'name': 'Wired_802.1X','id': '9e7f92dd-179f-4ed4-aafa-d8768ba26988'}]})

        :param policy_id:
        :param kwargs:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set/{}/authentication'.format(policy_id)
        if kwargs.get('rule') is None:
            st.error('Mandatory argument "rule" is not provided')
            return False
        cmdList = ['ifAuthFail', 'ifProcessFail', 'ifUserNotFound']
        data = dict()
        data['rule'] = kwargs.get('rule')
        data['identitySourceName'] = kwargs.get('identitySourceName', 'Internal Users')
        for param in cmdList:
            if kwargs.get(param) is not None:
                data[param] = kwargs[param]

        st.banner("Create the device admin authentication rule")
        output = self.rest_op('post', path, data=data, **kwargs)
        return output

    def update_device_admin_authentication_rule(self, policy_id, rule_id, **kwargs):
        '''
        update_device_admin_authentication_rule('e177defb-e97e-4369-8400-97894619eff7', rule={'name': 'Authentication Rule 1', 'condition': {'conditionType': 'ConditionReference', 'name': 'Wired_MAB','id': '9a74ebd6-9855-49d8-9a68-ac66f17bd53a'}})

        :param policy_id:
        :param rule_id:
        :param kwargs:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set/{}/authentication/{}'.format(policy_id, rule_id)
        if kwargs.get('rule') is None:
            st.error('Mandatory argument "rule" is not provided')
            return False
        cmdList = ['rule', 'identitySourceName', 'ifAuthFail', 'ifProcessFail', 'ifUserNotFound']
        data = dict()
        for param in cmdList:
            if kwargs.get(param) is not None:
                data[param] = kwargs[param]

        st.banner("Update the device admin authentication rule")
        output = self.rest_op('put', path, data=data)
        return output

    def delete_device_admin_authentication_rule(self, policy_id, rule_id):
        '''
        delete_device_admin_authentication_rule('dbe1f1a4-044b-40d0-ad33-9e4ef8bd2897', '519d4863-0536-40a3-8e9c-ee7adbf10ef4')

        :param policy_id:
        :param rule_id:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set/{}/authentication/{}'.format(policy_id, rule_id)
        st.banner("Delete the device admin authentication rule")
        output = self.rest_op('delete', path)
        return output

    def get_device_admin_authentication_rule(self, policy_id, rule_id=None):
        '''
        get_device_admin_authentication_rule('dbe1f1a4-044b-40d0-ad33-9e4ef8bd2897', '519d4863-0536-40a3-8e9c-ee7adbf10ef4')

        :param policy_id:
        :param rule_id:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set/{}/authentication'.format(policy_id)
        if rule_id:
            path = '/api/v1/policy/network-access/policy-set/{}/authentication/{}'.format(policy_id, rule_id)
        st.banner("Get the device admin authentication rule")
        output = self.rest_op('get', path)
        return output

    def create_device_admin_authorization_rule(self, policy_id, **kwargs):
        '''
        {
        "rule": {
            "default": false,
            "name": "Authorization Rule 2",
            "rank": 0,
            "state": "enabled",
            "condition": {
              "conditionType": "ConditionReference",
              "name": "Network_Access_Authentication_Passed",
              "id": "7eb022ea-db35-4d28-abc1-3798516ca720",
              "description": "Default condition used for basic Network Access requiring that authentication was successful."
            }
        },
          "profile": [
            "SonicPACUTProfilemabipv4acl2"
          ],
          "securityGroup": "Employees"
        },
        create_device_admin_authorization_rule('dbe1f1a4-044b-40d0-ad33-9e4ef8bd2897', profile=['username'], rule={rule: {'name': 'Authorization Rule 2', 'condition': {'conditionType': 'ConditionReference', 'name': 'Network_Access_Authentication_Passed', "id": "7eb022ea-db35-4d28-abc1-3798516ca720"}}})

        :param policy_id:
        :param kwargs:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set/{}/authorization'.format(policy_id)
        if kwargs.get('rule') is None:
            st.error('Mandatory argument "rule" is not provided')
            return False
        cmdList = ['rule', 'securityGroup', 'profile']
        data = dict()
        for param in cmdList:
            if kwargs.get(param) is not None:
                data[param] = kwargs[param]

        st.banner("Create the device admin authorization rule")
        output = self.rest_op('post', path, data=data, **kwargs)
        return output

    def update_device_admin_authorization_rule(self, policy_id, rule_id, **kwargs):
        '''
        create_device_admin_authorization_rule('dbe1f1a4-044b-40d0-ad33-9e4ef8bd2897', 'f8562f2d-d19f-41fe-bfc7-4e07e6fab728', profile=['username'], rule={rule: {'name': 'Authorization Rule 2', 'condition': {'conditionType': 'ConditionReference', 'name': 'Network_Access_Authentication_Passed', "id": "7eb022ea-db35-4d28-abc1-3798516ca720"}}})

        :param policy_id:
        :param rule_id:
        :param kwargs:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set/{}/authorization/{}'.format(policy_id, rule_id)
        if kwargs.get('rule') is None:
            st.error('Mandatory argument "rule" is not provided')
            return False
        cmdList = ['rule', 'securityGroup', 'profile']
        data = dict()
        for param in cmdList:
            if kwargs.get(param) is not None:
                data[param] = kwargs[param]

        st.banner("Update the device admin authorization rule")
        output = self.rest_op('put', path, data=data)
        return output

    def delete_device_admin_authorization_rule(self, policy_id, rule_id):
        '''
        delete_device_admin_authorization_rule('dbe1f1a4-044b-40d0-ad33-9e4ef8bd2897', '519d4863-0536-40a3-8e9c-ee7adbf10ef4')

        :param policy_id:
        :param rule_id:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set/{}/authorization/{}'.format(policy_id, rule_id)
        st.banner("Delete the device admin authorization rule")
        output = self.rest_op('delete', path)
        return output

    def get_device_admin_authorization_rule(self, policy_id, rule_id=None):
        '''
        get_device_admin_authorization_rule('dbe1f1a4-044b-40d0-ad33-9e4ef8bd2897', '519d4863-0536-40a3-8e9c-ee7adbf10ef4')

        :param policy_id:
        :param rule_id:
        :return:
        '''
        path = '/api/v1/policy/network-access/policy-set/{}/authorization'.format(policy_id)
        if rule_id:
            path = '/api/v1/policy/network-access/policy-set/{}/authorization/{}'.format(policy_id, rule_id)
        st.banner("Get the device admin authorization rule")
        output = self.rest_op('get', path)
        return output

    def session_reauthentication(self, endpoint_mac, psn_name, reauth_type='0', **kwargs):
        '''
        REAUTH_TYPE_DEFAULT - 0
        REAUTH_TYPE_LAST - 1
        REAUTH_TYPE_RERUN - 2
        session_reauthentication('00:00:00:81:00:13', 'Cisco-ISE-Sonic', reauth_type=0)

        :param endpoint_mac:
        :param psn_name:
        :param reauth_type:
        :param kwargs:
        :return:
        '''

        endpoint_mac = endpoint_mac.replace(':', '-')
        headers = kwargs.get('headers', {"Accept": "application/xml", "Content-type": "application/xml"})
        path = '/admin/API/mnt/CoA/Reauth/{}/{}/{}'.format(psn_name, endpoint_mac, reauth_type)
        st.banner("perform reauthentication for client {}".format(endpoint_mac))
        output = self.rest_op('get', path, headers=headers)
        return output

    def session_disconnect(self, disconnect_type, endpoint_ip, endpoint_mac, nas_ip, psn_name, **kwargs):
        '''
        DYNAMIC_AUTHZ_PORT_DEFAULT = 0
        DYNAMIC_AUTHZ_PORT_BOUNCE = 1
        DYNAMIC_AUTHZ_PORT_SHUTDOWN = 2
        session_disconnect('0', '1.2.3.4', '00:00:00:81:00:13', '10.192.2.3', 'Cisco-ISE-Sonic')

        :param disconnect_type:
        :param endpoint_ip:
        :param mac:
        :param nas_ip:
        :param psn_name:
        :param kwargs:
        :return:
        '''

        type = {'0': 'disconnect', '1': 'bounce host port', '2': 'disable host port'}
        disconnect_type = str(disconnect_type)
        headers = kwargs.get('headers', {"Accept": "application/xml", "Content-type": "application/xml"})
        endpoint_mac = endpoint_mac.replace(':', '-')
        path = '/admin/API/mnt/CoA/Disconnect/{}/{}/{}/{}/{}'.format(psn_name, endpoint_mac, disconnect_type, nas_ip,
                                                                     endpoint_ip)
        st.banner("perform disconnect for client {} with {}".format(endpoint_mac, type[disconnect_type]))
        output = self.rest_op('get', path, headers=headers, rest_timeout=60)
        return output
