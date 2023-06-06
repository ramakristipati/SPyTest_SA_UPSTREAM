# This file contains the list of API's which performs FBS operations.
#Author: prudviraj k (prudviraj.kristipati.@broadcom.com)

from spytest import st
from utilities.common import filter_and_select
import re
from utilities.utils import get_interface_number_from_name, get_supported_ui_type_list
from apis.system.rest import config_rest, delete_rest,get_rest
from utilities.common import make_list
import apis.qos.copp as copp_api

try:
    import apis.yang.codegen.messages.fbs_ext.FbsExt as umf_fbs
except ImportError:
    pass


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def config_policy_table(dut, **kwargs):
    """
    Creating policies
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to build policy table
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    policy_data = kwargs
    if 'policy_name' not in policy_data:
        st.error("policy name not provided ...")
        return False
    if cli_type in get_supported_ui_type_list():
        fbs_obj = umf_fbs.Root()
        if policy_data['enable'] == "create":
            pol_obj = umf_fbs.PolicyMap(Name=policy_data['policy_name'],
                                        Type=policy_data['policy_type'], Root=fbs_obj)
            result = pol_obj.configure(dut, cli_type=cli_type)
        elif policy_data['enable'] == "del":
            pol_obj = umf_fbs.PolicyMap(Name=policy_data['policy_name'], Root=fbs_obj)
            result = pol_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Creation or deletion of Policy {} {}'.format(policy_data['policy_name'],result.data))
            return False
    elif cli_type == "click":
        if policy_data['enable'] == "create":
            command = "config policy add {} -t {}".format(policy_data['policy_name'], policy_data['policy_type'])
        elif policy_data['enable'] == "del":
            command = "config policy del {}".format(policy_data['policy_name'])
        st.config(dut, command, type=cli_type)
    elif cli_type == 'klish':
        command = list()
        if policy_data['enable'] == "create":
            command.append("policy-map {} type {}".format(policy_data['policy_name'], policy_data['policy_type']))
            command.append('exit')
        elif policy_data['enable'] == "del":
            command.append("no policy-map {}".format(policy_data['policy_name']))
        st.config(dut, command, type=cli_type)
        st.config(dut, "exit", type=cli_type)
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        http_method = kwargs.pop('http_method',cli_type)
        if policy_data['enable'] == "create":
            rest_url = rest_urls['policy_table_config']
            ocdata = {"openconfig-fbs-ext:policy": [{"policy-name":policy_data['policy_name'],
                                                     "config": {"type": "POLICY_"+policy_data['policy_type'].upper(),
                                                                "name": policy_data['policy_name']}}]}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            if not response:
                st.log(response)
                return False
        elif policy_data['enable'] == "del":
            rest_url = rest_urls['policy_table_delete'].format(policy_data['policy_name'])
            response = delete_rest(dut, rest_url=rest_url)
            if not response:
                st.log(response)
                return False
        return True
    else:
        st.error("Invalid config command selection")
        return False
    return True


def config_classifier_table(dut, **kwargs):
    """
    Creating classifiers
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to build classifier table
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    class_data = kwargs
    skip_error = kwargs.get("skip_error", False)
    if 'class_name' not in class_data:
        st.error("classifier name not provided ...")
        return False

    class_criteria_list = list()
    criteria_val_list = list()
    if 'class_criteria' in class_data.keys() and 'criteria_value' in class_data.keys():
        class_criteria = class_data['class_criteria']
        criteria_val = class_data['criteria_value']
        class_criteria_list = list(class_criteria) if type(class_criteria) is list else [class_criteria]
        criteria_val_list = list(criteria_val) if type(criteria_val) is list else [criteria_val]

    command = ''
    if cli_type in get_supported_ui_type_list():
        fbs_obj = umf_fbs.Root()
        config = kwargs.get('config', 'yes')
        class_data.update({"match_type": kwargs.get("match_type", "acl")})
        if 'match_type' in class_data.keys() and class_data['match_type'] != 'acl':
            class_data['match_type'] = 'fields'
        class_data['match_type'] = 'MATCH_' + class_data['match_type'].upper()
        if class_data['enable'] != 'del':
            class_obj = umf_fbs.ClassMap(Name=class_data['class_name'],
                                         MatchType=class_data['match_type'], Root=fbs_obj)
            class_obj.configure(dut, cli_type=cli_type)
            if 'description' in class_data:
                class_obj.Description = class_data['description']
                if config == "yes":
                    class_obj.configure(dut, cli_type=cli_type, target_attr=class_obj.Description)
                else:
                    class_obj.unConfigure(dut, cli_type=cli_type, target_attr=class_obj.Description)
            for criteria, value in zip(class_criteria_list, criteria_val_list):
                prefix = 'no match' if '--no-' in criteria else 'match'
                criteria_val = '' if '--no-' in criteria else value
                criteria = criteria.replace("--", "")
                if 'acl' in criteria:
                    acl_type = kwargs.get('acl_type','ip') if criteria_val != '' else ''
                    if acl_type == 'ip' : acl_type = "ACL_IPV4"
                    if acl_type == 'ipv6': acl_type = "ACL_IPV6"
                    if acl_type == 'mac': acl_type = "ACL_L2"
                    class_obj.AclName = criteria_val
                    class_obj.AclType = acl_type
                elif 'src-mac' in criteria:
                    class_obj.SrcMac = criteria_val
                    del_attr = class_obj.SrcMac 
                elif 'src-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/128'
                    class_obj.Sipv6 = criteria_val
                    del_attr = class_obj.Sipv6
                elif 'src-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/32'
                    class_obj.Sip = criteria_val
                    del_attr = class_obj.Sip
                elif 'dst-mac' in criteria:
                    class_obj.DstMac = criteria_val
                    del_attr = class_obj.DstMac 
                elif 'dst-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/128'
                    class_obj.Dipv6 = criteria_val
                    del_attr = class_obj.Dipv6
                elif 'dst-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/32'
                    class_obj.Dip = criteria_val
                    del_attr = class_obj.Dip
                elif 'ether' in criteria:
                    ether_type = 'ETHERTYPE_IPV6' if 'ipv6' in criteria_val else 'ETHERTYPE_IPV4'
                    class_obj.Ethertype = ether_type
                    del_attr = class_obj.Ethertype
                elif 'pcp' in criteria:
                    class_obj.Pcp = criteria_val
                    del_attr = class_obj.Pcp      
                elif 'ip-proto' in criteria:
                    ip_proto = 'IP_TCP' if criteria_val =='tcp' or criteria_val =='6' else 'IP_UDP'
                    class_obj.IpProto = ip_proto
                    del_attr = class_obj.IpProto
                elif 'src-port' in criteria:
                    if prefix == "match":
                        if '-' in str(criteria_val): criteria_val = criteria_val.replace('-', '..')
                        if ".." not in str(criteria_val): criteria_val = int(criteria_val)
                        class_obj.SrcPort = criteria_val
                    del_attr = class_obj.SrcPort
                elif 'dst-port' in criteria:
                    if prefix == "match":
                        if '-' in str(criteria_val): criteria_val = criteria_val.replace('-', '..')
                        if ".." not in str(criteria_val): criteria_val = int(criteria_val)
                        class_obj.DstPort = criteria_val
                    del_attr = class_obj.DstPort
                elif 'dscp' in criteria:
                    class_obj.Dscp = criteria_val
                    del_attr = class_obj.Dscp
                elif 'tcp-flags' in criteria:
                    if prefix == "match":
                        criteria_val = criteria_val.split(' ')
                        flag_list = []
                        for item in criteria_val:
                           flag_list.append(item)
                        class_obj.TcpFlags = flag_list
                    del_attr = class_obj.TcpFlags
                else:
                    criteria_field = 'vlanid' if 'vlan' in criteria else criteria
                    class_obj.Vlanid = int(criteria_val)
                    del_attr = class_obj.Vlanid
                if prefix == "match":
                    result = class_obj.configure(dut, cli_type=cli_type)
                else:
                    result = class_obj.unConfigure(dut, cli_type=cli_type, target_attr=del_attr)
                if not result.ok():
                    st.log('test_step_failed: config fails for {}'.format(result.data))
                    return False
        elif class_data['enable'] == 'del':
            class_obj = umf_fbs.ClassMap(Name=class_data['class_name'], Root=fbs_obj) 
            result = class_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: config fails for {}'.format(result.data))
                return False 
    elif cli_type == "click":
        if class_data['enable'] == "create":
            command = "config classifier add {} -m  {}".format(class_data['class_name'], class_data['match_type'])
        elif class_data['enable'] == "yes":
            command = "config classifier update {} ".format(class_data['class_name'])
            for class_criteria, criteria_val in zip(class_criteria_list, criteria_val_list):
                if '--no-' in class_criteria:
                    if criteria_val != '':
                        command += '{} {} '.format(class_criteria, criteria_val)
                    else:
                        command += '{} '.format(class_criteria)
                else:
                    command += '{} {} '.format(class_criteria, criteria_val)
        elif class_data['enable'] == "no":
            command = "config classifier update {} ".format(class_data['class_name'])
            for class_criteria in class_criteria_list:
                if '--no-' in class_criteria: command += '{} '.format(class_criteria)
        elif class_data['enable'] == "del":
            command = "config classifier del {}".format(class_data['class_name'])
    elif cli_type == 'klish':
        command = list()
        config = kwargs.get('config', 'yes')
        config_cmd = '' if config == 'yes' else 'no'
        class_data.update({"match_type": kwargs.get("match_type", "acl")})
        if 'match_type' in class_data.keys() and class_data['match_type'] != 'acl':
            class_data['match_type'] = 'fields match-all'
        if class_data['enable'] != 'del':
            command.append('class-map {} match-type {}'.format(class_data['class_name'], class_data['match_type']))
            if 'description' in class_data:
                if config_cmd == 'no': class_data['description'] = ''
                command.append('{} description {}'.format(config_cmd, class_data['description']))
            for criteria, value in zip(class_criteria_list, criteria_val_list):
                prefix = 'no match' if '--no-' in criteria else 'match'
                criteria_val = '' if '--no-' in criteria else value
                criteria = criteria.replace("--", "")
                if 'acl' in criteria:
                    infer_acl_type = None
                    if 'acl_table_l2' in criteria_val: infer_acl_type = 'mac'
                    if 'acl_table_v4' in criteria_val: infer_acl_type = 'ip'
                    if 'acl_table_v6' in criteria_val: infer_acl_type = 'ipv6'
                    if not kwargs.get("acl_type") and not infer_acl_type:
                        st.error("ACL Type is Mandatory")
                        return False
                    acl_type = kwargs.get("acl_type", infer_acl_type)
                    cmd = '{} access-group {} {}'.format(prefix, acl_type, criteria_val)
                elif 'src-mac' in criteria:
                    mac_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} source-address mac {}'.format(prefix, mac_cmd)
                elif 'src-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} source-address ipv6 {}'.format(prefix, ip_cmd)
                elif 'src-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} source-address ip {}'.format(prefix, ip_cmd)
                elif 'dst-mac' in criteria:
                    mac_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} destination-address mac {}'.format(prefix, mac_cmd)
                elif 'dst-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} destination-address ipv6 {}'.format(prefix, ip_cmd)
                elif 'dst-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} destination-address ip {}'.format(prefix, ip_cmd)
                elif 'ether' in criteria:
                    if criteria_val == '0x800' or criteria_val == '0x0800' : criteria_val = 'ip'
                    if criteria_val.lower() == '0x86dd':criteria_val = 'ipv6'
                    if criteria_val == '0x806' or criteria_val == '0x0806': criteria_val = 'arp'
                    cmd = '{} ethertype {}'.format(prefix, criteria_val)
                elif 'pcp' in criteria:
                    cmd = '{} pcp {}'.format(prefix, criteria_val)
                elif 'ip-proto' in criteria:
                    cmd = '{} ip protocol {}'.format(prefix, criteria_val)
                elif 'src-port' in criteria:
                    string = 'eq' if criteria_val != '' else ''
                    if criteria_val != '' and '-' in str(criteria_val):
                        string = 'range';
                        criteria_val = criteria_val.split('-')
                    if type(criteria_val) is list:
                        cmd = '{} l4-port source {} {} {}'.format(prefix, string, criteria_val[0],criteria_val[1])
                    else:
                        cmd = '{} l4-port source {} {}'.format(prefix, string, criteria_val)
                elif 'dst-port' in criteria:
                    string = 'eq' if criteria_val != '' else ''
                    if criteria_val != '' and '-' in str(criteria_val):
                        string = 'range';
                        criteria_val = criteria_val.split('-')
                    if type(criteria_val) is list:
                        cmd = '{} l4-port destination {} {} {}'.format(prefix, string, criteria_val[0], criteria_val[1])
                    else:
                        cmd = '{} l4-port destination {} {}'.format(prefix, string, criteria_val)
                elif 'dscp' in criteria:
                    cmd = '{} dscp {}'.format(prefix, criteria_val)
                elif 'tcp-flags' in criteria:
                    if value != '':
                        cmd = '{} tcp-flags {}'.format(prefix, value)
                    else:
                        cmd = '{} tcp-flags'.format(prefix)
                else:
                    cmd = '{} {} {}'.format(prefix, criteria, criteria_val)
                command.append(cmd)
        elif class_data['enable'] == 'del':
            command.append('no class-map {}'.format(class_data['class_name']))
    elif cli_type in ['rest-patch','rest-put']:
        config = kwargs.get('config','yes')
        http_method = kwargs.pop('http_method',cli_type)
        config_cmd = '' if config == 'yes' else 'no'
        rest_urls = st.get_datastore(dut,'rest_urls')
        delete_base_url = rest_urls['classifier_update_delete'].format(class_data['class_name'])
        ocdata = {}
        ocdata["openconfig-fbs-ext:classifiers"] ={}
        ocdata["openconfig-fbs-ext:classifiers"]['classifier'] =[]
        temp_dict = {}
        temp_dict['class-name'] = class_data['class_name']
        temp_dict['config'] = {}
        temp_dict['match-acl'] = {}
        temp_dict['match-acl']['config'] = {}
        temp_dict['match-hdr-fields'] = {}
        temp_dict['match-hdr-fields']['config'] = {}
        temp_dict['match-hdr-fields']['l2'] = {}
        temp_dict['match-hdr-fields']['l2']['config'] = {}
        temp_dict['match-hdr-fields']['ip'] = {}
        temp_dict['match-hdr-fields']['ip']['config'] = {}
        temp_dict['match-hdr-fields']['ipv4'] = {}
        temp_dict['match-hdr-fields']['ipv4']['config'] = {}
        temp_dict['match-hdr-fields']['ipv6'] = {}
        temp_dict['match-hdr-fields']['ipv6']['config'] = {}
        temp_dict['match-hdr-fields']['transport'] = {}
        temp_dict['match-hdr-fields']['transport']['config'] = {}
        temp_dict['config']['name'] = class_data['class_name']
        if class_data['enable'] != 'del':
            temp_dict['config']['match-type'] = 'MATCH_' + class_data['match_type'].upper()
            rest_url=rest_urls['classifier_table_config']
            if 'description' in class_data:
                if config_cmd != 'no':
                    temp_dict['config']['description'] = class_data['description']
                else:
                    response = delete_rest(dut, rest_url=delete_base_url + '/config/description')
                    if not response:
                        return False
            for criteria,value in zip(class_criteria_list,criteria_val_list):
                prefix = 'no match' if '--no-' in criteria else 'match'
                criteria_val = '' if '--no-' in criteria else value
                if 'acl' in criteria:
                    acl_type = kwargs.get('acl_type','ip') if criteria_val != '' else ''
                    if acl_type == 'ip' : acl_type = "ACL_IPV4"
                    if acl_type == 'ipv6': acl_type = "ACL_IPV6"
                    if acl_type == 'mac': acl_type = "ACL_L2"
                    if prefix == 'match':
                        temp_dict['match-acl']['config']['acl-name'] = criteria_val
                        temp_dict['match-acl']['config']['acl-type'] = acl_type
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url +'/match-acl/config')
                        if not response:
                            return False
                elif 'src-mac' in criteria:
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['l2']['config']['source-mac'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/l2/config/source-mac')
                        if not response:
                            return False
                elif 'src-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/128'
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ipv6']['config']['source-address'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ipv6/config/source-address')
                        if not response:
                            return False
                elif 'src-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/32'
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ipv4']['config']['source-address'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ip/config/source-address')
                        if not response:
                            return False
                elif 'dst-mac' in criteria:
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['l2']['config']['destination-mac'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/l2/config/destination-mac')
                        if not response:
                            return False
                elif 'dst-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/128'
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ipv6']['config']['destination-address'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ipv6/config/destination-address')
                        if not response:
                            return False
                elif 'dst-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/32'
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ipv4']['config']['destination-address'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ip/config/destination-address')
                        if not response:
                            return False
                elif 'ether' in criteria:
                    if prefix == 'match':
                        ether_type = 'ETHERTYPE_IPV6' if 'ipv6' in criteria else 'ETHERTYPE_IPV4'
                        temp_dict['match-hdr-fields']['l2']['config']['ethertype'] = ether_type
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/l2/config/ethertype')
                        if not response:
                            return False
                elif 'pcp' in criteria:
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['l2']['config']['pcp'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/l2/config/pcp')
                        if not response:
                            return False
                elif 'ip-proto' in criteria:
                    if prefix == 'match':
                        ip_proto = 'IP_TCP' if criteria_val =='tcp' or criteria_val =='6' else 'IP_UDP'
                        temp_dict['match-hdr-fields']['ip']['config']['protocol'] = ip_proto
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ip/config/protocol')
                        if not response:
                            return False
                elif 'src-port' in criteria:
                    if prefix == 'match':
                        if '-' in str(criteria_val): criteria_val = criteria_val.replace('-', '..')
                        if ".." not in str(criteria_val): criteria_val = int(criteria_val)
                        temp_dict['match-hdr-fields']['transport']['config']['source-port'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/transport/config/source-port')
                        if not response:
                            return False
                elif 'dst-port' in criteria:
                    if prefix == 'match':
                        if '-' in str(criteria_val): criteria_val = criteria_val.replace('-', '..')
                        if ".." not in str(criteria_val): criteria_val = int(criteria_val)
                        temp_dict['match-hdr-fields']['transport']['config']['destination-port'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/transport/config/destination-port')
                        if not response:
                            return False
                elif 'dscp' in criteria:
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ip']['config']['dscp'] = int(criteria_val)
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ip/config/dscp')
                        if not response:
                            return False
                elif 'tcp-flags' in criteria:
                    if prefix == 'match':
                        criteria_val = criteria_val.split(' ')
                        flag_list = []
                        for item in criteria_val:
                            if 'no' in item:
                                item = item.split('-')
                                flag_list.append('TCP_NOT_{}'.format(item[1].upper()))
                            else:
                                flag_list.append('TCP_{}'.format(item.upper()))
                        temp_dict['match-hdr-fields']['transport']['config']['tcp-flags'] = flag_list
                    else:
                        response = delete_rest(dut, rest_url=delete_base_url+'/match-hdr-fields/transport/config/tcp-flags')
                        if not response:
                            return False
                else:
                    criteria_field = 'vlanid' if 'vlan' in criteria else criteria
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['l2']['config'][criteria_field] = int(criteria_val)
                    else:
                        rest_url = delete_base_url + '/' + '/match-hdr-fields/l2/config/' + criteria_field
                        response = delete_rest(dut, rest_url=rest_url)
                        if not response:
                           return False
            if temp_dict['config'] == {}:del temp_dict['config']
            if temp_dict['match-acl']['config'] == {}: del temp_dict['match-acl']['config']
            if temp_dict['match-acl'] == {}:del temp_dict['match-acl']
            if temp_dict['match-hdr-fields']['config'] == {}: del temp_dict['match-hdr-fields']['config']
            if temp_dict['match-hdr-fields']['l2']['config'] == {}: del temp_dict['match-hdr-fields']['l2']['config']
            if temp_dict['match-hdr-fields']['l2'] == {}: del temp_dict['match-hdr-fields']['l2']
            if temp_dict['match-hdr-fields']['ip']['config'] == {}: del temp_dict['match-hdr-fields']['ip']['config']
            if temp_dict['match-hdr-fields']['ip'] == {}: del temp_dict['match-hdr-fields']['ip']
            if temp_dict['match-hdr-fields']['ipv4']['config'] == {}: del temp_dict['match-hdr-fields']['ipv4']['config']
            if temp_dict['match-hdr-fields']['ipv4'] == {}: del temp_dict['match-hdr-fields']['ipv4']
            if temp_dict['match-hdr-fields']['ipv6']['config'] == {}: del temp_dict['match-hdr-fields']['ipv6']['config']
            if temp_dict['match-hdr-fields']['ipv6'] == {}: del temp_dict['match-hdr-fields']['ipv6']
            if temp_dict['match-hdr-fields']['transport']['config'] == {}: del temp_dict['match-hdr-fields']['transport']['config']
            if temp_dict['match-hdr-fields']['transport'] == {}: del temp_dict['match-hdr-fields']['transport']
            if temp_dict['match-hdr-fields'] == {}: del temp_dict['match-hdr-fields']

            ocdata["openconfig-fbs-ext:classifiers"]['classifier'].append(temp_dict)
            if len(ocdata["openconfig-fbs-ext:classifiers"]['classifier']) > 0:
                response = config_rest(dut,http_method=http_method,rest_url= rest_url,json_data=ocdata)
                if not response:
                    return False
        elif class_data['enable'] =='del':
            rest_url = rest_urls['classifier_update_delete'].format(class_data['class_name'])
            response = delete_rest(dut,rest_url=rest_url)
            if not response:
                st.log(response)
                return False
        return True
    else:
        st.error("Invalid config command selection")
        return False
    out = st.config(dut, command,type=cli_type,skip_error_check=skip_error)
    if re.search(r'Error',out):
        if cli_type == "klish":
            st.config(dut, "exit", type=cli_type)
        return False
    if cli_type == "klish":
        st.config(dut, "exit", type=cli_type)
    return True


def convert_tcp_flags_to_hex(tcp_flags=''):
    hex_dict ={}
    hex_dict['fin'] = hex_dict['not-fin'] = 1
    hex_dict['syn'] = hex_dict['not-syn'] = 2
    hex_dict['rst'] = hex_dict['not-rst'] = 4
    hex_dict['psh'] = hex_dict['not-psh'] = 8
    hex_dict['ack'] = hex_dict['not-ack'] = 16
    hex_dict['urg'] = hex_dict['not-urg'] = 32

    tcp_flags = tcp_flags.rstrip().split(' ')
    total = 0;total_no_not = 0
    for flag in tcp_flags:
        total += hex_dict[flag]
        if 'not' not in flag:
            total_no_not += hex_dict[flag]
    total_hex = hex(total)
    total_no_not_hex = hex(total_no_not) if total_no_not else total_hex
    return ('{}/{}'.format(total_no_not_hex,total_hex))


def config_flow_update_table(dut, skip_error=False, **kwargs):
    """
    Creating to update the classifier table
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to update the flow table
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    flow_data = kwargs
    policy_type = kwargs.get('policy_type', 'qos')
    if not flow_data:
        st.error("flow update table failed because of invalid data ..")
    if cli_type in get_supported_ui_type_list():
        root_obj = umf_fbs.Root()
        config = kwargs.get('config','yes')
        config_cmd = '' if config == 'yes' else 'no'
        set_action = flow_data.get('priority_option',None)
        version = flow_data.get('version','ip').upper()
        next_hop = flow_data.get('next_hop',None)
        nhgroup_name = flow_data.get('nhgroup_name', None)
        repgroup_name = flow_data.get('repgroup_name', None)
        vrf_name = flow_data.get('vrf_name',None)
        next_hop_priority = flow_data.get('next_hop_priority',None)
        set_interface = flow_data.get('set_interface',None)
        set_interface_priority = flow_data.get('set_interface_priority',None)
        traffic_class = flow_data.get('traffic_class','')
        pol_obj = umf_fbs.PolicyMap(Name=flow_data['policy_name'], Type=policy_type, Root=root_obj)
        result = pol_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            return False
        if flow_data['flow'] != 'del':
            if flow_data['flow'] == 'add' and 'priority_value' in flow_data:
                flow_data['flow_priority'] = int(flow_data['priority_value'])
                class_obj = umf_fbs.PolicyMapSection(Name=flow_data['class_name'], 
                                                     Priority=flow_data['flow_priority'], PolicyMap=pol_obj)
                result = class_obj.configure(dut, cli_type=cli_type)
            elif 'flow_priority' in flow_data:
                class_obj = umf_fbs.PolicyMapSection(Name=flow_data['class_name'],
                                                     Priority=flow_data['flow_priority'], PolicyMap=pol_obj)
                result = class_obj.configure(dut, cli_type=cli_type)
            else:
                class_obj = umf_fbs.PolicyMapSection(Name=flow_data['class_name'],PolicyMap=pol_obj)
                result = class_obj.configure(dut, cli_type=cli_type)
            if 'description' in flow_data:
                class_obj.Description = flow_data['description']
                result = class_obj.configure(dut, cli_type=cli_type)
            if nhgroup_name:
                nhgroup_name = list(nhgroup_name) if type(nhgroup_name) is list else [nhgroup_name]
                set_version = 'NEXT_HOP_GROUP_TYPE_IPV4' if version == 'IP' else 'NEXT_HOP_GROUP_TYPE_IPV6'
                if next_hop_priority:
                    next_hop_priority = list(next_hop_priority) if type(next_hop_priority) is list else [next_hop_priority]
                    if config_cmd != 'no':
                        for nhg, prio in zip(nhgroup_name, next_hop_priority):
                            group_obj = umf_fbs.NextHopGroup(Name=nhg, Type=set_version, Root=root_obj)
                            nhg_obj = umf_fbs.SetNextHopGroup(Name=group_obj, Type=set_version, 
                                                                     Priority=prio, PolicyMapSection=class_obj)
                            result = nhg_obj.configure(dut, cli_type=cli_type)
                    else:
                        for nhg in (nhgroup_name):
                            nhg_obj = umf_fbs.SetNextHopGroup(Name=nhg, PolicyMapSection=class_obj)
                            result = nhg_obj.unConfigure(dut, cli_type=cli_type)
                else:
                    for nhg in (nhgroup_name):
                        group_obj = umf_fbs.NextHopGroup(Name=nhg, Type=set_version, Root=root_obj)
                        nhg_obj = umf_fbs.SetNextHopGroup(Name=group_obj, Type=set_version,
                                                                 PolicyMapSection=class_obj)
                        if config_cmd != 'no':
                            result = nhg_obj.configure(dut, cli_type=cli_type)
                        else: 
                            result = nhg_obj.unConfigure(dut, cli_type=cli_type)
            if repgroup_name:
                repgroup_name = make_list(repgroup_name)
                set_version = 'REPLICATION_GROUP_TYPE_IPV4' if version == 'IP' else 'REPLICATION_GROUP_TYPE_IPV6'
                if next_hop_priority:
                    next_hop_priority = make_list(next_hop_priority)
                if not next_hop_priority:
                    for rep_g in repgroup_name: 
                        group_obj = umf_fbs.ReplicationGroup(Name=rep_g, Type=set_version,
                                                                Root=root_obj)           
                        rep_obj = umf_fbs.SetReplicationGroup(Name=group_obj, Type=set_version,
                                                                     PolicyMapSection=class_obj)
                        if config_cmd != 'no':
                            result = rep_obj.configure(dut, cli_type=cli_type)
                        else:
                            result = rep_obj.unConfigure(dut, cli_type=cli_type)
                elif next_hop_priority:
                    for rep_g,prio in zip(repgroup_name, next_hop_priority):
                        group_obj = umf_fbs.ReplicationGroup(Name=rep_g, Type=set_version,
                                                                Root=root_obj)
                        rep_obj = umf_fbs.SetReplicationGroup(Name=group_obj, Type=set_version,
                                                                     Priority=prio, PolicyMapSection=class_obj)
                        if config_cmd != 'no':
                            result = rep_obj.configure(dut, cli_type=cli_type)
                        else:
                            result = rep_obj.unConfigure(dut, cli_type=cli_type)
            if set_action and set_action == 'next-hop': 
                set_version = 'SET_IP_NEXTHOP' if version == 'IP' else 'SET_IPV6_NEXTHOP'
                next_hop = list(next_hop) if type(next_hop) is list else [next_hop]
                if vrf_name:
                    vrf_name = list(vrf_name) if type(vrf_name) is list else [vrf_name]
                if next_hop_priority:
                    next_hop_priority = list(next_hop_priority) if type(next_hop_priority) is list else [next_hop_priority]
                if not vrf_name and not next_hop_priority:
                    for nh in next_hop:
                        nh_obj = umf_fbs.SetNextHop(Ip=nh, Vrf='INTERFACE_NETWORK_INSTANCE',
                                                           PolicyMapSection=class_obj)
                        if config_cmd != 'no':
                            result = nh_obj.configure(dut, cli_type=cli_type)
                        else:
                            result = nh_obj.unConfigure(dut, cli_type=cli_type)
                elif not vrf_name and next_hop_priority:
                    for nh, prio in zip(next_hop, next_hop_priority):
                        nh_obj = umf_fbs.SetNextHop(Ip=nh, Vrf='INTERFACE_NETWORK_INSTANCE',
                                                           Priority=prio, PolicyMapSection=class_obj)
                        if config_cmd != 'no':
                            result = nh_obj.configure(dut, cli_type=cli_type)
                        else:
                            result = nh_obj.unConfigure(dut, cli_type=cli_type)
                elif vrf_name and not next_hop_priority:
                    for nh, vrf in zip(next_hop, vrf_name):
                        if vrf == '':
                            vrf='INTERFACE_NETWORK_INSTANCE'
                        nh_obj = umf_fbs.SetNextHop(Ip=nh, Vrf=vrf,
                                                           PolicyMapSection=class_obj)
                        if config_cmd != 'no':
                            result = nh_obj.configure(dut, cli_type=cli_type)
                        else:
                            result = nh_obj.unConfigure(dut, cli_type=cli_type)
                elif vrf_name and next_hop_priority:
                    for nh, vrf, prio in zip(next_hop, vrf_name, next_hop_priority):
                        if vrf == '':
                            vrf='INTERFACE_NETWORK_INSTANCE'
                        nh_obj = umf_fbs.SetNextHop(Ip=nh, Vrf=vrf,
                                                           Priority=prio, PolicyMapSection=class_obj)
                        if config_cmd != 'no':
                            result = nh_obj.configure(dut, cli_type=cli_type)
                        else:
                            result = nh_obj.unConfigure(dut, cli_type=cli_type)
            elif set_action and set_action == 'interface':
                    set_interface = list(set_interface) if type(set_interface) is list else [set_interface]
                    if set_interface_priority:
                        set_interface_priority = list(set_interface_priority) if type(set_interface_priority) is list else [
                                                 set_interface_priority]
                    if not set_interface_priority:
                        for intf in set_interface:
                            if 'null' not in intf:
                                interface = get_interface_number_from_name(intf)
                                if isinstance(interface, dict):
                                    intf_obj = umf_fbs.SetInterface(IntfName=interface['type']+interface['number'],
                                                                   PolicyMapSection=class_obj)
                                else:
                                    intf_obj = umf_fbs.SetInterface(IntfName=intf, PolicyMapSection=class_obj)
                                if config_cmd != 'no':
                                    result = intf_obj.configure(dut, cli_type=cli_type)
                                else:
                                    result = intf_obj.unConfigure(dut, cli_type=cli_type)
                            else:
                                class_obj.Discard = True
                                if config_cmd != 'no':
                                    class_obj.configure(dut, cli_type=cli_type)
                                else:
                                    class_obj.unConfigure(dut, cli_type=cli_type, target_attr=class_obj.Discard)
                    else:
                        for intf,priority in zip(set_interface,set_interface_priority):
                            if 'null' not in intf:
                                interface = get_interface_number_from_name(intf)
                                if isinstance(interface, dict):
                                    intf_obj = umf_fbs.SetInterface(IntfName=interface['type']+interface['number'],
                                                                    Priority=priority, PolicyMapSection=class_obj)
                                else:
                                    intf_obj = umf_fbs.SetInterface(IntfName=intf,
                                                                     Priority=priority, PolicyMapSection=class_obj)
                                if config_cmd != 'no':
                                    result = intf_obj.configure(dut, cli_type=cli_type)
                                else:
                                    result = intf_obj.unConfigure(dut, cli_type=cli_type)
                            else:
                                class_obj.Discard = True
                                if config_cmd != 'no':
                                    class_obj.configure(dut, cli_type=cli_type)
                                else:
                                    class_obj.unConfigure(dut, cli_type=cli_type, target_attr=class_obj.Discard)
            elif set_action and 'police' in set_action:   
                    if 'priority_value_1' in flow_data:
                        class_obj.CoppPolCir = str(flow_data['priority_value_1'])
                        class_obj.CoppPolCbs = str(flow_data['priority_value_2'])
                        class_obj.CoppPolPir = str(flow_data['priority_value_3'])
                        class_obj.CoppPolPbs = str(flow_data['priority_value_4'])
                    if config_cmd == '':
                        result = class_obj.configure(dut, cli_type=cli_type) 
                    else:
                        result = class_obj.unConfigure(dut, cli_type=cli_type,
                                                       target_attr=[class_obj.CoppPolPbs, class_obj.CoppPolPir, 
                                                                    class_obj.CoppPolCbs, class_obj.CoppPolCir])
            elif set_action and 'dscp' in set_action:
                    if '--no' in set_action:
                        result = class_obj.unConfigure(dut, cli_type=cli_type, target_attr=class_obj.SetDscp)                   
                    else:
                        class_obj.SetDscp = int(flow_data['priority_value'])
                        result = class_obj.configure(dut, cli_type=cli_type)
            elif set_action and 'pcp' in set_action: 
                    if '--no' in set_action:
                        result = class_obj.unConfigure(dut, cli_type=cli_type, target_attr=class_obj.SetPcp)
                    else:
                        class_obj.SetPcp = int(flow_data['priority_value'])
                        result = class_obj.configure(dut, cli_type=cli_type)
            elif set_action and 'traffic_class' in set_action:
                    if config_cmd != 'no':
                        result = class_obj.unConfigure(dut, cli_type=cli_type, target_attr=class_obj.SetTc)
                    else:
                        class_obj.SetTc = traffic_class
                        result = class_obj.configure(dut, cli_type=cli_type)
            elif set_action and "mirror-session" in set_action:
                    mirr_obj = umf_fbs.SetMirrorSession(Name=flow_data['priority_value'], PolicyMapSection=class_obj)
                    if '--no' in set_action:
                        result = mirr_obj.unConfigure(dut, cli_type=cli_type)
                    else:
                        result = mirr_obj.configure(dut, cli_type=cli_type)
        else:
            class_obj = umf_fbs.PolicyMapSection(Name=flow_data['class_name'], PolicyMap=pol_obj)
            result = class_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: flow creation for {}'.format(result.data))
            return False
    elif cli_type == "click":
        if flow_data['flow'] == "update":
            if flow_data['priority_option'] == "--police":
                command = "config flow update {} {} --police --cir {} --cbs {} --pir {} --pbs {}".format(
                    flow_data['policy_name'], flow_data['class_name'], flow_data['priority_value_1'],
                    flow_data['priority_value_2'], flow_data['priority_value_3'], flow_data['priority_value_4'])
                st.config(dut, command, type='click')
            else:
                command = "config flow update {} {} {} {}".format(flow_data['policy_name'], flow_data['class_name'],
                                                                  flow_data['priority_option'],
                                                                  flow_data['priority_value'])
                out = st.config(dut, command, type='click', skip_error_check=skip_error)
                if re.search(r'Error: Invalid value for.*', out):
                    return False
        elif flow_data['flow'] == "update_del":
            command = "config flow update {} {} {}".format(flow_data['policy_name'], flow_data['class_name'],
                                                           flow_data['priority_option'])
            st.config(dut, command)
        elif flow_data['flow'] == "add":
            command = "config flow add {} {} -p {} -d {}".format(flow_data['policy_name'], flow_data['class_name'],
                                                                 flow_data['priority_value'], flow_data['description'])
            out = st.config(dut, command, type='click', skip_error_check=skip_error)
            if "Failed" not in out or "Error" not in out:
                return False
        elif flow_data['flow'] == "del":
            command = "config flow del {} {}".format(flow_data['policy_name'], flow_data['class_name'])
            st.config(dut, command, type='click')
    elif cli_type == 'klish':
        config = kwargs.get('config', 'yes')
        config_cmd = '' if config == 'yes' else 'no'
        set_action = flow_data.get('priority_option', None)
        version = flow_data.get('version', 'ip')
        next_hop = flow_data.get('next_hop', None)
        nhgroup_name = flow_data.get('nhgroup_name', None)
        repgroup_name = flow_data.get('repgroup_name', None)
        vrf_name = flow_data.get('vrf_name', None)
        next_hop_priority = flow_data.get('next_hop_priority', None)
        set_interface = flow_data.get('set_interface', None)
        set_interface_priority = flow_data.get('set_interface_priority', None)

        action_cmd = list()
        if nhgroup_name:
            nhgroup_name = list(nhgroup_name) if type(nhgroup_name) is list else [nhgroup_name]
            if next_hop_priority:
                next_hop_priority = list(next_hop_priority) if type(next_hop_priority) is list else [next_hop_priority]
            if vrf_name:
                vrf_name = list(vrf_name) if type(vrf_name) is list else [vrf_name]
            if not vrf_name and not next_hop_priority:
                for nhg in nhgroup_name:
                    action_cmd.append('{} set {} next-hop-group {}'.format(config_cmd, version, nhg))
            elif not vrf_name and next_hop_priority:
                for nhg,prio in zip(nhgroup_name, next_hop_priority):
                    prio_cmd = '' if prio == '' else ' priority {}'.format(prio)
                    action_cmd.append('{} set {} next-hop-group {}{}'.format(config_cmd,version,nhg,prio_cmd))
            elif vrf_name and not next_hop_priority:
                for nhg, vrf in zip(nhgroup_name, vrf_name):
                    vrf_cmd = '' if vrf == '' else ' vrf {}'.format(vrf)
                    action_cmd.append('{} set {} next-hop-group {}{}'.format(config_cmd, version,nhg,vrf_cmd))
            elif vrf_name and next_hop_priority:
                for nhg,vrf,prio in zip(nhgroup_name,vrf_name,next_hop_priority):
                    prio_cmd = '' if prio == '' else ' priority {}'.format(prio)
                    vrf_cmd = '' if vrf == '' else ' vrf {}'.format(vrf)
                    action_cmd.append('{} set {} next-hop-group {}{}{}'.format(config_cmd,version,nhg,vrf_cmd,prio_cmd))


        if repgroup_name:
            repgroup_name =make_list(repgroup_name)
            if next_hop_priority:
                next_hop_priority = make_list(next_hop_priority)
            if vrf_name:
                vrf_name = make_list(vrf_name)
            if not vrf_name and not next_hop_priority:
                for rep_g in repgroup_name:
                    action_cmd.append('{} set {} replication-group {}'.format(config_cmd, version, rep_g))
            elif not vrf_name and next_hop_priority:
                for rep_g,prio in zip(repgroup_name, next_hop_priority):
                    prio_cmd = '' if prio == '' else ' priority {}'.format(prio)
                    action_cmd.append('{} set {} replication-group {} {}'.format(config_cmd,version,rep_g,prio_cmd))
            elif vrf_name and not next_hop_priority:
                for rep_g, vrf in zip(repgroup_name, vrf_name):
                    vrf_cmd = '' if vrf == '' else ' vrf {}'.format(vrf)
                    action_cmd.append('{} set {} replication-group {} {}'.format(config_cmd, version,rep_g,vrf_cmd))
            elif vrf_name and next_hop_priority:
                for rep_g,vrf,prio in zip(repgroup_name,vrf_name,next_hop_priority):
                    prio_cmd = '' if prio == '' else ' priority {}'.format(prio)
                    vrf_cmd = '' if vrf == '' else ' vrf {}'.format(vrf)
                    action_cmd.append('{} set {} replication-group {} {} {}'.format(config_cmd,version,rep_g,vrf_cmd,prio_cmd))


        if set_action and set_action == 'next-hop':
            next_hop = list(next_hop) if type(next_hop) is list else [next_hop]
            if vrf_name:
                vrf_name = list(vrf_name) if type(vrf_name) is list else [vrf_name]
            if next_hop_priority:
                next_hop_priority = list(next_hop_priority) if type(next_hop_priority) is list else [next_hop_priority]
            if not vrf_name and not next_hop_priority:
                for nh in next_hop:
                    action_cmd.append('{} set {} next-hop {}'.format(config_cmd, version, nh))
            elif not vrf_name and next_hop_priority:
                for nh, prio in zip(next_hop, next_hop_priority):
                    prio_cmd = '' if prio == '' else ' priority {}'.format(prio)
                    action_cmd.append('{} set {} next-hop {}{}'.format(config_cmd, version, nh, prio_cmd))
            elif vrf_name and not next_hop_priority:
                for nh, vrf in zip(next_hop, vrf_name):
                    vrf_cmd = '' if vrf == '' else ' vrf {}'.format(vrf)
                    action_cmd.append('{} set {} next-hop {}{}'.format(config_cmd, version, nh, vrf_cmd))
            elif vrf_name and next_hop_priority:
                for nh, vrf, prio in zip(next_hop, vrf_name, next_hop_priority):
                    vrf_cmd = '' if vrf == '' else ' vrf {}'.format(vrf)
                    prio_cmd = '' if prio == '' else ' priority {}'.format(prio)
                    action_cmd.append('{} set {} next-hop {}{}{}'.format(config_cmd, version, nh, vrf_cmd, prio_cmd))
        elif set_action and set_action == 'interface':
            set_interface = list(set_interface) if type(set_interface) is list else [set_interface]
            if set_interface_priority:
                set_interface_priority = list(set_interface_priority) if type(set_interface_priority) is list else [
                    set_interface_priority]
            if not set_interface_priority:
                for intf in set_interface:
                    interface = get_interface_number_from_name(intf)
                    if isinstance(interface, dict):
                        action_cmd.append('{} set interface {} {}'.format(config_cmd,interface['type'],interface['number']))
                    else:
                        action_cmd.append('{} set interface {}'.format(config_cmd,intf))
            else:
                for intf,priority in zip(set_interface,set_interface_priority):
                    interface = get_interface_number_from_name(intf)
                    if isinstance(interface, dict):
                        action_cmd.append('{} set interface {} {} priority {}'.format(config_cmd,interface['type'],interface['number'],priority))
                    else:
                        action_cmd.append('{} set interface {} priority {}'.format(config_cmd,intf,priority))
        elif set_action and 'police' in set_action:

            if 'priority_value_1' in flow_data:
                flow_data['cir'] = flow_data['priority_value_1']
                flow_data['cbs'] = flow_data['priority_value_2']
                flow_data['pir'] = flow_data['priority_value_3']
                flow_data['pbs'] = flow_data['priority_value_4']
            if config_cmd == '':
                action_cmd.append('{} police cir {} cbs {} pir {} pbs {}\n'.format(config_cmd, flow_data['cir'],
                                                                               flow_data['cbs'], flow_data['pir'],
                                                                               flow_data['pbs']))
            else:
                action_cmd.append('no police cir cbs pir pbs')
        elif set_action and 'dscp' in set_action:
            action_cmd.append('no set dscp' if '--no' in set_action else 'set dscp {}'.format(
                flow_data['priority_value']))
        elif set_action and 'pcp' in set_action:
            action_cmd.append('no set pcp' if '--no' in set_action else 'set pcp {}'.format(flow_data['priority_value']))
        elif set_action and 'mirror-session' in set_action:
            action_cmd.append('no set mirror-session' if '--no' in set_action else 'set mirror-session {}'.format(flow_data['priority_value']))
        command = ['policy-map {} type {}'.format(flow_data['policy_name'], policy_type)]
        check = False
        if flow_data['flow'] != 'del':
            if flow_data['flow'] == 'add' and 'priority_value' in flow_data:
                flow_data['flow_priority'] = flow_data['priority_value']
                check = True
            if 'flow_priority' in flow_data:
                command.append('class {} priority {}'.format(flow_data['class_name'], flow_data['flow_priority']))
                check = True
            else:
                command.append('class {}'.format(flow_data['class_name']))
                check = True
            if 'description' in flow_data:
                if config_cmd == 'no': flow_data['description'] = ''
                command.append('{} description {}'.format(config_cmd, flow_data['description']))
                check = True

            if flow_data['class_name']=="test_non_exist":
                check = False

            if check:
                action_cmd.append("exit")
                #check = False
            command = command + action_cmd
            command.append("exit")
        else:
            command.append('no class {}'.format(flow_data['class_name']))
            command.append("exit")
        st.log(command)
        out = st.config(dut, command, type='klish',skip_error_check=skip_error)
        if "Error" in out:
            return False
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        config = kwargs.get('config','yes')
        config_cmd = '' if config == 'yes' else 'no'
        set_action = flow_data.get('priority_option',None)
        version = flow_data.get('version','ip').upper()
        next_hop = flow_data.get('next_hop',None)
        nhgroup_name = flow_data.get('nhgroup_name', None)
        vrf_name = flow_data.get('vrf_name',None)
        next_hop_priority = flow_data.get('next_hop_priority',None)
        set_interface = flow_data.get('set_interface',None)
        set_interface_priority = flow_data.get('set_interface_priority',None)
        traffic_class = flow_data.get('traffic_class','')
        rest_urls = st.get_datastore(dut,'rest_urls')
        ocdata = {}
        ocdata["openconfig-fbs-ext:sections"] = {}
        ocdata["openconfig-fbs-ext:sections"]['section'] = []
        section_dict = {}
        section_dict['config'] = {}
        section_dict['qos'] = {}
        section_dict['qos']['remark'] = {}
        section_dict['qos']['remark']['config'] = {}
        section_dict['qos']['policer'] = {}
        section_dict['qos']['policer']['config'] = {}
        section_dict['qos']['queuing'] = {}
        section_dict['qos']['queuing']['config'] = {}
        section_dict['monitoring'] = {}
        section_dict['monitoring']['mirror-sessions'] = {}
        section_dict['monitoring']['mirror-sessions']['mirror-session'] = []
        monitoring_dict = {}
        monitoring_dict['config'] = {}
        section_dict['forwarding'] = {}
        section_dict['forwarding']['config'] ={}
        section_dict['forwarding']['egress-interfaces'] = {}
        section_dict['forwarding']['egress-interfaces']['egress-interface'] = []
        egress_dict = {}
        egress_dict['config'] ={}
        section_dict['forwarding']['next-hops'] = {}
        section_dict['forwarding']['next-hops']['next-hop'] = []
        section_dict['forwarding']['next-hop-groups'] = {}
        section_dict['forwarding']['next-hop-groups']['next-hop-group'] = []
        nexthop_dict = {}
        nexthop_dict['config']={}

        base_url = rest_urls['policy_flow_create'].format(flow_data['policy_name'])
        delete_oc_url = rest_urls['policy_flow_delete'].format(flow_data['policy_name'],flow_data['class_name'])
        delete_base_url = rest_urls['policy_flow_nexthop_delete'].format(flow_data['policy_name'], flow_data['class_name'])
        if flow_data['flow'] != 'del':
            result = config_policy_table(dut, enable='create',policy_name=flow_data['policy_name'],
                                         policy_type=flow_data['policy_type'],
                                         cli_type=cli_type)
            if not result: return False
            if flow_data['flow'] == 'add' and 'priority_value' in flow_data:
                flow_data['flow_priority'] = int(flow_data['priority_value'])

            section_dict['class'] = flow_data['class_name']
            section_dict['config']['name'] = flow_data['class_name']
            if 'flow_priority' in flow_data:
                section_dict['config']['priority'] = flow_data['flow_priority']
            if 'description' in flow_data:
                if config_cmd != 'no':
                    section_dict['config']['description']= flow_data['description']
                else:
                    rest_url = rest_urls['policy_flow_delete'].format(flow_data['policy_name'])
                    response = delete_rest(dut,rest_url=rest_url+'/config/description')
                    if not response:
                        return False

            if nhgroup_name:
                rest_url = delete_oc_url+'/forwarding/next-hop-groups/next-hop-group'
                nhgroup_name = list(nhgroup_name) if type(nhgroup_name) is list else [nhgroup_name]
                set_version = 'NEXT_HOP_GROUP_TYPE_IPV4' if version == 'IP' else 'NEXT_HOP_GROUP_TYPE_IPV6'
                if next_hop_priority:
                    next_hop_priority = list(next_hop_priority) if type(next_hop_priority) is list else [next_hop_priority]
                    if config_cmd != 'no':
                        for nhg, prio in zip(nhgroup_name, next_hop_priority):
                                nexthop_dict = dict()
                                nexthop_dict['config'] = dict()
                                nexthop_dict['group-name'] = nhg
                                nexthop_dict['config']['group-name'] = nhg
                                nexthop_dict['config']['priority'] =prio
                                nexthop_dict['config']['group-type'] =set_version
                                section_dict['forwarding']['next-hop-groups']['next-hop-group'].append(nexthop_dict)
                    else:
                        for nhg in (nhgroup_name):
                            delete_url = rest_url+'={}'.format(nhg)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                else:
                    if config_cmd != 'no':
                        for nhg in (nhgroup_name):
                            nexthop_dict = dict()
                            nexthop_dict['config'] = dict()
                            nexthop_dict['group-name'] = nhg
                            nexthop_dict['config']['group-name'] = nhg
                            nexthop_dict['config']['group-type'] =set_version
                            section_dict['forwarding']['next-hop-groups']['next-hop-group'].append(nexthop_dict)
                    else:
                        for nhg in (nhgroup_name):
                            delete_url = rest_url+'={}'.format(nhg)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False

            if set_action and set_action == 'next-hop':
                set_version = 'SET_IP_NEXTHOP' if version == 'IP' else 'SET_IPV6_NEXTHOP'
                rest_url = delete_oc_url+'/forwarding/next-hops/next-hop'
                next_hop = list(next_hop) if type(next_hop) is list else [next_hop]
                if vrf_name:
                    vrf_name = list(vrf_name) if type(vrf_name) is list else [vrf_name]
                if next_hop_priority:
                    next_hop_priority = list(next_hop_priority) if type(next_hop_priority) is list else [next_hop_priority]

                if not vrf_name and not next_hop_priority:
                    if config_cmd != 'no':
                        for nh in next_hop:
                            nexthop_dict = dict()
                            nexthop_dict['config'] = dict()
                            nexthop_dict['ip-address'] = nh
                            nexthop_dict['network-instance'] = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict['config']['ip-address'] = nh
                            nexthop_dict['config']['network-instance'] = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for nh in next_hop:
                            delete_url = rest_url+'={},openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE'.format(nh)
                            response = delete_rest(dut,rest_url=delete_url)
                            if not response:
                                return False
                elif not vrf_name and  next_hop_priority:
                    if config_cmd != 'no':
                        for nh, prio in zip(next_hop, next_hop_priority):
                            nexthop_dict = dict()
                            nexthop_dict['config'] = dict()
                            nexthop_dict['ip-address'] = nh
                            nexthop_dict['network-instance'] = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict['config']['ip-address'] = nh
                            nexthop_dict['config']['network-instance'] = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict['config']['priority'] = prio
                            section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for nh,prio in zip(next_hop,next_hop_priority):
                            delete_url = delete_base_url+set_version+'={}||{}'.format(nh,prio)
                            response = delete_rest(dut,rest_url=delete_url)
                            if not response:
                                return False
                elif vrf_name and  not next_hop_priority:
                    if config_cmd != 'no':
                        for nh, vrf in zip(next_hop, vrf_name):
                            if vrf == '': vrf = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict = dict()
                            nexthop_dict['config'] = dict()
                            nexthop_dict['ip-address'] = nh
                            nexthop_dict['network-instance'] = vrf
                            nexthop_dict['config']['ip-address'] = nh
                            nexthop_dict['config']['network-instance'] = vrf
                            section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for nh,vrf in zip(next_hop, vrf_name):
                            delete_url = rest_url+'={},{}'.format(nh,vrf)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                elif vrf_name and next_hop_priority:
                    if config_cmd != 'no':
                        for nh, vrf, prio in zip(next_hop, vrf_name, next_hop_priority):
                            if vrf == '': vrf = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict = dict()
                            nexthop_dict['config'] = dict()
                            nexthop_dict['ip-address'] = nh
                            nexthop_dict['network-instance'] = vrf
                            nexthop_dict['config']['ip-address'] = nh
                            nexthop_dict['config']['network-instance'] = vrf
                            nexthop_dict['config']['priority'] =prio
                            section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for nh,vrf,prio in zip(next_hop, vrf_name,next_hop_priority):
                            delete_url = delete_base_url+ set_version + '={}|{}|{}'.format(nh,vrf,prio)
                            st.log(delete_url)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False


            elif set_action and set_action == 'interface':
                interface_str = '/forwarding/egress-interfaces/egress-interface'
                null_str = '/forwarding/config/discard'
                rest_url = delete_oc_url + interface_str
                set_interface = list(set_interface) if type(set_interface) is list else [set_interface]
                if set_interface_priority:
                    set_interface_priority = list(set_interface_priority) if type(set_interface_priority) is list else [set_interface_priority]
                if not set_interface_priority:

                    if config_cmd != 'no':
                        for intf in set_interface:
                            if 'null' not in intf:
                                egress_dict = dict()
                                egress_dict['config'] = dict()
                                egress_dict['intf-name'] = intf
                                egress_dict['config']['intf-name'] = intf
                                section_dict['forwarding']['egress-interfaces']['egress-interface'].append(egress_dict)
                            else:
                                section_dict['forwarding']['config']['discard'] = True
                                #section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        null_str = 'DEFAULT_PACKET_ACTION'
                        for intf in set_interface:
                            if 'null' not in intf:
                                delete_url = rest_url + '={}'.format(intf)
                            else:
                                delete_url = delete_base_url + null_str
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                else:
                    if config_cmd != 'no':
                        for intf, priority in zip(set_interface, set_interface_priority):
                            if 'null' not in intf:
                                egress_dict = dict()
                                egress_dict['config'] = dict()
                                egress_dict['intf-name'] = intf
                                egress_dict['config']['intf-name'] = intf
                                egress_dict['config']['priority'] = priority
                                section_dict['forwarding']['egress-interfaces']['egress-interface'].append(egress_dict)
                            else:
                                section_dict['forwarding']['config']['discard'] = False
                                section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for intf,priority in zip(set_interface,set_interface_priority):
                            delete_url = delete_base_url + interface_str + '={},{}'.format(intf, priority)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                 return False
            elif set_action and 'police' in set_action:
                 if 'priority_value_1' in flow_data:
                    flow_data['cir'] = str(flow_data['priority_value_1'])
                    flow_data['cbs'] = str(flow_data['priority_value_2'])
                    flow_data['pir'] = str(flow_data['priority_value_3'])
                    flow_data['pbs'] = str(flow_data['priority_value_4'])
                 if config_cmd == '':
                     section_dict['qos']['policer']['config']['cir'] = flow_data['cir']
                     section_dict['qos']['policer']['config']['pir'] = flow_data['pir']
                     section_dict['qos']['policer']['config']['cbs'] = flow_data['cbs']
                     section_dict['qos']['policer']['config']['pbs'] = flow_data['pbs']
                 else:
                     ocdata = {"openconfig-fbs-ext:config":{}}
                     response = config_rest(dut, http_method='rest-put', rest_url=delete_oc_url + '/qos/policer/config',
                                            json_data=ocdata)
                     if not response:
                         return False
            elif set_action and 'dscp' in set_action:
                if '--no' not in set_action:
                    section_dict['qos']['remark']['config']['set-dscp'] = int(flow_data['priority_value'])
                else:
                    response = delete_rest(dut,rest_url=delete_oc_url+'/qos/remark/config/set-dscp')
                    if not response:
                        return False

            elif set_action and 'pcp' in set_action:
                if '--no' not in set_action:
                    section_dict['qos']['remark']['config']['set-dot1p'] = int(flow_data['priority_value'])
                else:
                    response = delete_rest(dut,rest_url=delete_oc_url+'/qos/remark/config/set-dot1p')
                    if not response:
                        return False
            elif set_action and 'traffic_class' in set_action:
                if config_cmd != 'no':
                    section_dict['qos']['queuing']['config']['output-queue-index'] = traffic_class
                else:
                    response = delete_rest(dut,rest_url= delete_oc_url+'/qos/queuing/config/output-queue-index')
                    if not response:
                        return False
            elif set_action and "mirror-session" in set_action:
                rest_url = delete_oc_url + '/monitoring/mirror-sessions/mirror-session'
                if config_cmd != 'no':
                    monitoring_dict['session-name'] = flow_data['priority_value']
                    monitoring_dict['config']['session-name'] = flow_data['priority_value']
                    section_dict['monitoring']['mirror-sessions']['mirror-session'].append(monitoring_dict)
                else:
                    response = delete_rest(dut,rest_url=rest_url)
                    if not response:
                        return False


            if section_dict['config'] == {}: del section_dict['config']
            if section_dict['qos']['remark']['config'] == {}: del section_dict['qos']['remark']['config']
            if section_dict['qos']['remark'] == {}: del section_dict['qos']['remark']
            if section_dict['qos']['policer']['config'] == {}:del section_dict['qos']['policer']['config']
            if section_dict['qos']['policer'] == {}: del section_dict['qos']['policer']
            if section_dict['qos']['queuing']['config'] == {}: del section_dict['qos']['queuing']['config']
            if section_dict['qos']['queuing'] == {}: del section_dict['qos']['queuing']
            if section_dict['qos'] == {}: del section_dict['qos']
            if section_dict['monitoring']['mirror-sessions']['mirror-session'] == []:del section_dict['monitoring']['mirror-sessions']['mirror-session']
            if section_dict['monitoring']['mirror-sessions'] == {}: del section_dict['monitoring']['mirror-sessions']
            if section_dict['monitoring'] == {}: del section_dict['monitoring']
            if monitoring_dict['config'] == {}:del monitoring_dict['config']
            if section_dict['forwarding']['egress-interfaces']['egress-interface'] == []:del section_dict['forwarding']['egress-interfaces']['egress-interface']
            if section_dict['forwarding']['egress-interfaces'] == {}: del section_dict['forwarding']['egress-interfaces']
            if section_dict['forwarding']['config'] == {}: del section_dict['forwarding']['config']
            if egress_dict['config'] == {}:del egress_dict['config']
            if section_dict['forwarding']['next-hops']['next-hop'] == []: del section_dict['forwarding']['next-hops'][
                'next-hop']
            if section_dict['forwarding']['next-hops'] == {}:del section_dict['forwarding']['next-hops']
            if section_dict['forwarding']['next-hop-groups']['next-hop-group'] == []: del section_dict['forwarding']['next-hop-groups'][
                'next-hop-group']
            if section_dict['forwarding']['next-hop-groups'] == {}:del section_dict['forwarding']['next-hop-groups']
            if nexthop_dict['config'] == {}:del nexthop_dict['config']
            if section_dict['forwarding'] == {}: del section_dict['forwarding']

            ocdata["openconfig-fbs-ext:sections"]['section'].append(section_dict)
            if config_cmd != 'no':
                if len(ocdata["openconfig-fbs-ext:sections"]['section']) > 0:
                    response = config_rest(dut,http_method=http_method,rest_url=base_url,json_data=ocdata)
                    if not response:
                        return False
        else:
            response = delete_rest(dut,rest_url=delete_oc_url)
            if not response:
                return False
        return True
    else:
        st.error("Invalid config command selection")
        return False

    return True


def config_service_policy_table(dut, skip_error=False, **kwargs):
    """
    Creating to update the classifier table
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to update the  service_policy table
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    service_data = kwargs
    policy_type = kwargs.get('policy_type', 'qos')
    if not service_data:
        st.error("service policy data failed because of invalid data ..")
    if cli_type in get_supported_ui_type_list():
        fbs_obj = umf_fbs.Root()
        interface = kwargs.get('interface_name', None)
        direction = 'in' if policy_type != 'qos' else kwargs.get('stage','in')
        policy_name = kwargs.get('service_policy_name', '')
        stage = 'ingress' if direction == 'in' else 'egress'
        cli_clear = force_cli_type_to_klish(cli_type=cli_type)
        if service_data['policy_kind'] == "clear_policy":
            command = "clear counters service-policy policy-map {}".format(policy_name)
            st.config(dut, command, type=cli_clear,conf=False,skip_error_check=skip_error)
        elif service_data['policy_kind'] == "clear_interface":
            if interface.lower() == "switch":
                command = "clear counters service-policy Switch"
            else:
                interface = get_interface_number_from_name(interface)
                if isinstance(interface, dict):
                    command = "clear counters service-policy interface {} {}".format(interface['type'], interface['number'])
                else:
                    command = "clear counters service-policy interface {}".format(interface)
            st.config(dut, command, type=cli_clear, conf=False,skip_error_check=skip_error)
        else:
            if kwargs['policy_kind'] == 'unbind':
                config_cmd = 'no'
                policy_name = ''
            elif kwargs['policy_kind'] == 'bind':
                config_cmd = ''
            if interface:
                if interface != 'Switch':
                    interface_details = get_interface_number_from_name(interface)
                    intf_obj = umf_fbs.Interface(Id=interface_details.get("type")+interface_details.get("number"),
                                                 Root=fbs_obj)
                    if policy_type == "qos" and direction == "in":
                        intf_obj.InQoSPolicy = policy_name
                    elif policy_type == "qos" and direction == "out":
                        intf_obj.EgrQoSPolicy = policy_name
                    elif policy_type == "forwarding":
                        intf_obj.InFwdPolicy = policy_name
                    elif policy_type == "monitoring":
                        intf_obj.InMonPolicy = policy_name
                    else:
                        st.log("kindly specify \'policy_type\' arg")
                else:
                    intf_obj = umf_fbs.Interface(Id='Switch', Root=fbs_obj)
                    if policy_type == "qos" and direction == "in":
                        intf_obj.InQoSPolicy = policy_name
                    elif policy_type == "qos" and direction == "out":
                        intf_obj.EgrQoSPolicy = policy_name
                    elif policy_type == "forwarding":
                        intf_obj.InFwdPolicy = policy_name
                    elif policy_type == "monitoring":
                        intf_obj.InMonPolicy = policy_name
                    else:
                        st.log("kindly specify \'policy_type\' arg")
            else:
                intf_obj = umf_fbs.Interface(Id='Switch', Root=fbs_obj)
                if policy_type == "qos" and direction == "in":
                    intf_obj.InQoSPolicy = policy_name
                elif policy_type == "qos" and direction == "out":
                    intf_obj.EgrQoSPolicy = policy_name
                elif policy_type == "forwarding":
                    intf_obj.InFwdPolicy = policy_name
                elif policy_type == "monitoring":
                    intf_obj.InMonPolicy = policy_name
                else:
                    st.log("kindly specify \'policy_type\' arg")
            if config_cmd == 'no':
                result = intf_obj.unConfigure(dut, cli_type=cli_type)
            else:
                result = intf_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: service policy: {} fails for {}'.format(policy_name,result.data))
                return False   
    elif cli_type == "click":
        if service_data['policy_kind'] == "bind":
            command = "config service-policy bind {} {} {} {}".format(service_data['interface_name'], policy_type,
                                                                       service_data['stage'],
                                                                       service_data['service_policy_name'])
            out = st.config(dut, command, type='click', skip_error_check=skip_error)
            if re.search(r'Error: Another policy.*', out):
                return False
            elif "Failed" in out or "Error" in out:
                return False
        elif service_data['policy_kind'] == "unbind":
            command = "config service-policy unbind {} {} {}".format(service_data['interface_name'], policy_type,
                                                                      service_data['stage'])
            st.config(dut, command, type='click')
        elif service_data['policy_kind'] == "clear_policy":
            command = "show service-policy policy {} -c".format(service_data['service_policy_name'])
            st.config(dut, command, type='click', skip_error_check=skip_error)
        elif service_data['policy_kind'] == "clear_interface":
            command = "show service-policy interface {} -c".format(service_data['interface_name'])
            st.config(dut, command, type='click')
    elif cli_type == 'klish':
        interface = kwargs.get('interface_name', None)
        direction = 'in' if policy_type != 'qos' else kwargs.get('stage','in')
        policy_name = kwargs.get('service_policy_name', '')

        command = list()
        if service_data['policy_kind'] == "clear_policy":
            command.append("clear counters service-policy policy-map {}".format(policy_name))
            st.config(dut, command, type='klish',conf=False,skip_error_check=skip_error)
        elif service_data['policy_kind'] == "clear_interface":
            if interface.lower() == "switch":
                command.append("clear counters service-policy Switch")
            else:
                interface = get_interface_number_from_name(interface)
                if isinstance(interface, dict):
                    command.append("clear counters service-policy interface {} {}".format(interface['type'], interface['number']))
                else:
                    command.append("clear counters service-policy interface {}".format(interface))
            st.config(dut, command, type='klish', conf=False,skip_error_check=skip_error)
        else:
            if kwargs['policy_kind'] == 'unbind':
                config_cmd = 'no'
                policy_name = ''
            elif kwargs['policy_kind'] == 'bind':
                config_cmd = ''
            if interface:
                if interface != 'Switch':
                    interface_details = get_interface_number_from_name(interface)
                    command.append("interface {} {}".format(interface_details.get("type"),
                                                          interface_details.get("number")))
                command.append('{} service-policy type {} {} {}\n'.format(config_cmd, policy_type, direction, policy_name))
                out = st.config(dut, command, type='klish', skip_error_check=skip_error)
                if re.search(r'Error.*', out):
                    if interface and interface != "Switch":
                        st.config(dut, "exit", type="klish")
                    return False
                if interface and interface != "Switch":
                    st.config(dut, "exit", type="klish", skip_error_check=skip_error)
            else:
                command.append('{} service-policy type {} {} {}'.format(config_cmd, policy_type, direction, policy_name))
                out =st.config(dut, command, type='klish', skip_error_check=skip_error)
                if re.search(r'Error.*', out):
                    return False
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.get('http_mathod',cli_type)
        interface = kwargs.get('interface_name',None)
        policy_type = kwargs.get('policy_type','qos')
        direction = kwargs.get('stage','in')
        policy_name = kwargs.get('service_policy_name','')
        rest_urls = st.get_datastore(dut,'rest_urls')
        stage = 'ingress' if direction == 'in' else 'egress'
        if service_data['policy_kind'] == "clear_policy":
            rest_url = rest_urls['clear_service_policy_counters']
            ocdata = {"sonic-flow-based-services:input": {"POLICY_NAME": policy_name}}
            response = config_rest(dut, http_method='post', rest_url=rest_url, json_data=ocdata)
            if not response:
                st.log(response)
                return False
        elif service_data['policy_kind'] == "clear_interface":
            rest_url = rest_urls['clear_service_policy_counters']
            ocdata = {"sonic-flow-based-services:input": {"INTERFACE_NAME": interface}}
            response = config_rest(dut, http_method='post', rest_url=rest_url, json_data=ocdata)
            if not response:
                return False
        else:
            intf = interface if interface else 'Switch'
            rest_url = rest_urls['service_policy_bind_unbind'].format(intf,stage,policy_type)
            if kwargs['policy_kind'] == 'unbind':
                response = delete_rest(dut,rest_url=rest_url)
                if not response:
                    return False
            elif kwargs['policy_kind'] == 'bind':
                rest_url = rest_urls['service_policy_bind_unbind'].format(intf, stage, policy_type)
                ocdata = {"openconfig-fbs-ext:{}".format(policy_type): {'config': {'policy-name':policy_name} }}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
                if not response:
                    return False
        return True
    else:
        st.error("Invalid config command selection")
        return False

    return True


def show(dut,*argv,**kwargs):
    """
    show commands summary
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs:
    :param classifier:
    :param match_type:
    :param class_name:
    :param policy_name:
    :param interface_name:
    :param servie_policy_summary:
    :return:
    """
    rest_urls = st.get_datastore(dut, "rest_urls")
    cli_type = kwargs.get("cli_type",st.get_ui_type(dut,**kwargs))
    input_data = {}
    yang_model = kwargs.pop('yang_model','ocyang')
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if "classifier" in argv:
        command = "show class-map" if cli_type == 'klish' else "show classifier"
        rest_url =rest_urls['show_classifier_{}'.format(yang_model)]
        input_data = {"sonic-flow-based-services:input": {}}
        parse_type='CLASSIFIERS'
    elif 'match_type' in kwargs:
        if cli_type == 'click':
            command = "show classifier -m {} {}".format(kwargs['match_type'], kwargs['class_name'])
        elif cli_type == 'klish':
            command = "show class-map match-type {}".format(kwargs['match_type'])
        if 'class_name' in kwargs:
           rest_url = rest_urls['show_classifier_sonic'] if yang_model == 'sonic' \
                else rest_urls['show_classifier_name_ocyang'].format(kwargs['class_name'])
        else:
            rest_url = rest_urls['show_classifier_{}'.format(yang_model)]
        input_data = {"sonic-flow-based-services:input":{"MATCH_TYPE":kwargs['match_type'].upper()}}
        parse_type = 'CLASSIFIERS'
    elif 'policy' in argv:
        command = "show policy" if cli_type == 'click' else "show policy-map"
        rest_url = rest_urls['show_policy_{}'.format(yang_model)]
        input_data = {"sonic-flow-based-services:input":{}}
        parse_type = 'POLICIES'
    elif 'policy_name' in kwargs:
        command = "show policy {}".format(kwargs['policy_name']) if cli_type == 'click' else "show policy-map {}".format(kwargs['policy_name'])
        rest_url = rest_urls['show_policy_sonic'] if yang_model =='sonic' else rest_urls['show_policy_id_ocyang'].format(kwargs['policy_name'])
        input_data = {"sonic-flow-based-services:input":{"POLICY_NAME":kwargs['policy_name']}}
        parse_type = 'POLICIES'
    elif 'service_policy_name' in kwargs:
        yang_model='sonic'
        if cli_type == 'click':
            command = "show service-policy policy {}".format(kwargs['service_policy_name'])
        else:
            command = "show service-policy policy-map {}".format(kwargs['service_policy_name'])
        rest_url = rest_urls['show_service_policy_sonic']
        input_data = {"sonic-flow-based-services:input":{"POLICY_NAME":kwargs['service_policy_name']}}
        parse_type = 'INTERFACES'
    elif 'interface_name' in kwargs:
        if cli_type == 'klish':
            if kwargs.get("interface_name") != "Switch":
                interface = get_interface_number_from_name(kwargs['interface_name'])
                command = "show service-policy interface {} {}".format(interface['type'],interface['number'])
            else:
                command = "show service-policy {}".format(kwargs['interface_name'])
        elif cli_type == 'click':
            command = "show service-policy interface {}".format(kwargs['interface_name'])
        rest_url = rest_urls['show_service_policy_sonic'] if yang_model =='sonic' \
            else rest_urls['show_service_policy_ocyang'].format(kwargs['interface_name'])
        input_data = {"sonic-flow-based-services:input":{"INTERFACE_NAME":kwargs['interface_name']}}
        parse_type = 'INTERFACES'
    elif 'service_policy_summary' in argv:
        command = "show service-policy summary"
        rest_url = rest_urls['show_service_policy_summary']
        input_data = None
        parse_type = 'SUMMARY'
    else:
        st.error("incorrect arguments given for the show")
        return False

    if 'rest' in cli_type:
        if input_data:
            if yang_model == 'ocyang':
                output = get_rest(dut,rest_url=rest_url)['output']
            else:
                output =  st.rest_create(dut,path=rest_url,data=input_data)['output'].get('sonic-flow-based-services:output',{})
                st.log(output)
            output = convert_rest_key_to_template(parse_type,output,yang_model=yang_model,**kwargs)
            return output
        else:
            output = st.rest_read(dut,path=rest_url)['output'].get('sonic-flow-based-services:POLICY_BINDING_TABLE_LIST',[])
            st.log(output)
            output = convert_rest_key_to_template(parse_type,output,yang_model=yang_model,**kwargs)
            return output

    output = st.show(dut, command, type=cli_type,skip_error_check=True)
    return output


def get(dut, *argv, **kwargs):
    """
    To Get counters matched from show service-policy interface
    Author : prudviraj k (prudviraj.kristipati@broadcom.com)

    :param dut:
    :return:
    """
    output = show(dut, *argv, **kwargs)
    st.log(output)
    entries = filter_and_select(output, [kwargs["value"]])
    if entries:
        if not kwargs.get("full_output"):
            return entries[0][kwargs['value']]
        else:
            return entries

def verify_policy_counters(dut, **kwargs):
    """
    Verifying show service policy counters
    Author : Kanala Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :param packet_count:
    :param packet_size:
    :return:
    """
    packet_count = int(str(kwargs.get('packet_count', 0)).replace(',',''))
    packet_size = kwargs.get('packet_size', 64)
    interface = kwargs.get('interface', "Switch")
    class_name = kwargs.get('class_name', "")
    output = show(dut, interface_name=interface)
    result = filter_and_select(output, match = {'class_name': class_name})
    if result:
        result = result[0]
    else:
        return result
    policy_pkt_cnt = int(result["match_pkts_val"].replace(',',''))
    policy_byt_cnt = int(result["match_bytes_val"].replace(',',''))
    if int(0.99*packet_count) > int(policy_pkt_cnt) or int(policy_pkt_cnt) > int(1.01*packet_count):
        st.error("Service policy counters packets are not matching with actual traffic")
        return False
    if policy_pkt_cnt*packet_size != policy_byt_cnt:
        st.error("Service policy counters bytes are not matching")
        return False
    return True


def verify(dut,*argv,**kwargs):
    """
    show commands summary
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs:
    :param :verify_list:
    :return:
    """
    result = True
    yang_model = 'ocyang'
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut,**kwargs))
    for item in kwargs['verify_list']:
        if 'classifier' in kwargs or 'class_name' in kwargs or 'match_type' in kwargs:
            if 'policy_name' in item.keys() or 'priority_val' in item.keys():
                yang_model = 'sonic'
        elif 'policy' in argv or 'policy_name' in kwargs:
            if 'interface' in item.keys() or 'stage' in item.keys():
                yang_model = 'sonic'
    if "classifier" in argv:
        output = show(dut,'classifier',yang_model=yang_model,cli_type=cli_type)
    elif 'match_type' in kwargs and 'class_name' in kwargs:
        if cli_type in get_supported_ui_type_list():
            return copp_api.verify_show_class_map_acl(dut,class_name=kwargs['class_name'],match_type=kwargs['match_type'],cli_type=cli_type)
        output = show(dut, match_type=kwargs['match_type'],class_name=kwargs['class_name'],yang_model=yang_model,cli_type=cli_type)
    elif 'match_type' in kwargs and 'class_name' not in kwargs:
        output = show(dut, match_type=kwargs['match_type'],yang_model=yang_model,cli_type=cli_type)
    elif 'policy_name' in kwargs:
        if cli_type in get_supported_ui_type_list() and 'class_name' in kwargs:
            kwarg2 = {}             
            if 'verify_list' in kwargs:
                for v_list in kwargs['verify_list']:
                    if 'pcp_val' in v_list: kwarg2['pcp_val'] = v_list['pcp_val']
                    if 'dscp_val' in v_list: kwarg2['dscp_val'] = v_list['dscp_val']
                    if 'discard_val' in v_list: kwarg2['discard_val'] = v_list['discard_val']
                    if 'tc_val' in v_list: kwarg2['tc_val'] = v_list['tc_val']
                    if 'priority_val' in v_list: kwarg2['priority_val'] = v_list['priority_val']
                    if 'cir_val' in v_list: kwarg2['cir_val'] = v_list['cir_val']
                    if 'cbs_val' in v_list: kwarg2['cbs_val'] = v_list['cbs_val']
            kwarg2['cli_type'] = cli_type
            return copp_api.verify_show_acl_copp_policy(dut,policy_name=kwargs['policy_name'],class_name=kwargs['class_name'],**kwarg2)
        output = show(dut, policy_name=kwargs['policy_name'],yang_model=yang_model,cli_type=cli_type)
    elif 'policy' in argv:
        output = show(dut,'policy',yang_model=yang_model,cli_type=cli_type)
    elif 'service_policy_name' in kwargs:
        yang_model = 'sonic'
        output = show(dut, service_policy_name=kwargs['service_policy_name'],yang_model=yang_model,cli_type=cli_type)
    elif 'service_policy_interface' in kwargs:
        output = show(dut, interface_name=kwargs['service_policy_interface'],yang_model=yang_model,cli_type=cli_type)
    elif 'service_policy_summary' in argv:
        output = show(dut, 'service_policy_summary', cli_type=cli_type)
    else:
        st.error("incorrect arguments given for verification")
        return False

    if 'rest' in cli_type and yang_model =='sonic':
        if 'classifier' in argv or 'match_type' in kwargs:
            for each,index in zip(kwargs['verify_list'],range(len(kwargs['verify_list']))):
                if 'tcp_flags_type' in each.keys():
                    kwargs['verify_list'][index]['tcp_flags_type'] = convert_tcp_flags_to_hex(each['tcp_flags_type'])

    for each in kwargs['verify_list']:
        if not filter_and_select(output, None, each):
            st.log("{} is not matching in the output \n {}".format(each, output))
            result = False
    return result


def convert_rest_key_to_template(type,output,yang_model='ocyang',**kwargs):
    transformed_output_list = []
    if type == 'CLASSIFIERS' and yang_model == 'sonic':
        for item in output.get('CLASSIFIERS',[]):
            transformed_output = {}
            transformed_output['class_name'] = item.pop('CLASSIFIER_NAME', '')
            transformed_output['acl_name'] = item.pop('ACL_NAME', '')
            transformed_output['match_type'] = item.pop('MATCH_TYPE', '').lower()
            transformed_output['desc_name'] = item.pop('DESCRIPTION', '')
            transformed_output['field_value'] = item.pop('ETHER_TYPE', '').lower()
            transformed_output['src_port_val'] = item.pop('L4_SRC_PORT', '')
            transformed_output['dst_port_val'] = item.pop('L4_DST_PORT', '')
            transformed_output['src_ip_val'] = item.pop('SRC_IP', '')
            transformed_output['dst_ip_val'] = item.pop('DST_IP', '')
            transformed_output['src_mac_val'] = item.pop('SRC_MAC', '')
            transformed_output['dst_mac_val'] = item.pop('DST_MAC', '')
            transformed_output['src_ipv6_val'] = item.pop('SRC_IPV6', '')
            transformed_output['dst_ipv6_val'] = item.pop('DST_IPV6', '')
            transformed_output['tcp_flags_type'] = item.pop('TCP_FLAGS', '')
            ip_protocol_val = item.pop('IP_PROTOCOL', '')
            if ip_protocol_val:
                transformed_output['ip_protocol_val'] = 'tcp' if str(ip_protocol_val) == '6' else 'udp'
            reference = item.pop('REFERENCES', [])
            for index in range(len(reference)):
                transformed_output1 = transformed_output.copy()
                transformed_output1['policy_name'] = reference[index].pop('POLICY_NAME', '')
                transformed_output1['priority_val'] = reference[index].pop('PRIORITY', '')
                transformed_output_list.append(transformed_output1)
            if not (ip_protocol_val and len(reference)):
                transformed_output_list.append(transformed_output)
    elif type == 'CLASSIFIERS' and yang_model =='ocyang':
        output = output.get('openconfig-fbs-ext:classifier',[]) if 'class_name' in kwargs else \
            output.get('openconfig-fbs-ext:classifiers',{}).get('classifier',[])
        for item in output:
            transformed_output = {}
            transformed_output['class_name'] = item.get('state',{}).get('name','')
            transformed_output['acl_name'] = item.get('match-acl',{}).get('acl-name','')
            match_type = item.get('state', {}).get('match-type','').lower().split('_')
            transformed_output['match_type'] = '' if len(match_type) ==  0 else match_type[1]
            transformed_output['desc_name'] = item.get('state',{}).get('description', '')
            transformed_output['field_value'] = item.get('match-hdr-fields',{}).get('l2',{}).get('state',{}).get('ethertype', '')
            if transformed_output['field_value']:
                if 'openconfig-packet-match' in transformed_output['field_value']:
                    transformed_output['field_value'] = transformed_output['field_value'].split('_')[1]
                else:
                    transformed_output['field_value'] = hex(int(transformed_output['field_value']))
            transformed_output['src_port_val'] = item.get('match-hdr-fields',{}).get('transport',{}).get('state',{}).get('source-port', '')
            transformed_output['dst_port_val'] = item.get('match-hdr-fields',{}).get('transport',{}).get('state',{}).get('destination-port', '')
            transformed_output['src_ip_val'] = item.get('match-hdr-fields',{}).get('ipv4',{}).get('state',{}).get('source-address', '')
            transformed_output['dst_ip_val'] = item.get('match-hdr-fields',{}).get('ipv4',{}).get('state',{}).get('destination-address', '')
            transformed_output['src_mac_val'] = item.get('match-hdr-fields',{}).get('l2',{}).get('state',{}).get('source-mac', '')
            transformed_output['dst_mac_val'] = item.get('match-hdr-fields',{}).get('l2',{}).get('state',{}).get('destination-mac', '')
            transformed_output['src_ipv6_val'] = item.get('match-hdr-fields',{}).get('ipv6',{}).get('state',{}).get('source-address', '')
            transformed_output['dst_ipv6_val'] = item.get('match-hdr-fields',{}).get('ipv6',{}).get('state',{}).get('destination-address', '')
            tcp_flag_type = item.get('match-hdr-fields',{}).get('transport',{}).get('state',{}).get('tcp-flags', [])
            if tcp_flag_type:
                tcp_flags = ''
                for flag in tcp_flag_type:
                    flag = flag.split(':')[1]
                    if 'TCP_NOT_' not in flag:
                        if tcp_flags: tcp_flags+=' '
                        tcp_flags += flag.replace('TCP_','').lower()
                    else:
                        if tcp_flags: tcp_flags += ' '
                        tcp_flags += flag.replace('TCP_NOT_','no-').lower()
                transformed_output['tcp_flags_type'] = tcp_flags
            else:
                transformed_output['tcp_flags_type'] = ''
            ip_protocol_val = item.get('match-hdr-fields',{}).get('ip',{}).get('state',{}).get('protocol', '')
            if ip_protocol_val:
                transformed_output['ip_protocol_val'] = 'tcp' if 'IP_TCP' in str(ip_protocol_val) else 'udp'
            else:
                transformed_output['ip_protocol_val'] = ''
            transformed_output_list.append(transformed_output)
    elif type == 'POLICIES' and yang_model == 'sonic':
        for item in output.get('POLICIES',[]):
            ip_next_hop = ipv6_next_hop = egress_interface = ""
            default_packet_action = False
            transformed_output = {}
            transformed_output['policy_name'] = item.pop("POLICY_NAME", '')
            transformed_output['policy_type'] = item.pop("TYPE", '').lower()
            transformed_output['desc_name'] = item.pop("DESCRIPTION", '')
            flows = item.pop('FLOWS', [])
            for flow_index in range(len(flows)):
                transformed_output['class_name'] = flows[flow_index].get("CLASS_NAME", '')
                transformed_output['priority_val'] = flows[flow_index].get("PRIORITY", '')
                transformed_output['dscp_val'] = flows[flow_index].get('SET_DSCP','')
                transformed_output['pcp_val'] = flows[flow_index].get('SET_PCP', '')
                transformed_output['mirror_session'] = flows[flow_index].get("SET_MIRROR_SESSION", '')
                ip_next_hop = flows[flow_index].pop("SET_IP_NEXTHOP", [])
                if ip_next_hop:
                    for nh_index in range(len(ip_next_hop)):
                        transformed_output1 = transformed_output.copy()
                        transformed_output1['next_hop'] = ip_next_hop[nh_index].get('IP_ADDRESS', '')
                        transformed_output1['next_hop_vrf'] = ip_next_hop[nh_index].get('VRF', '')
                        transformed_output1['next_hop_priority'] = ip_next_hop[nh_index].get('PRIORITY', '')
                        transformed_output_list.append(transformed_output1)
                ipv6_next_hop = flows[flow_index].pop("SET_IPV6_NEXTHOP", [])
                if ipv6_next_hop:
                    for nh_index in range(len(ipv6_next_hop)):
                        transformed_output2 = transformed_output.copy()
                        transformed_output2['next_hop'] = ipv6_next_hop[nh_index].get('IP_ADDRESS', '')
                        transformed_output2['next_hop_vrf'] = ipv6_next_hop[nh_index].get('VRF', '')
                        transformed_output2['next_hop_priority'] = ipv6_next_hop[nh_index].get('PRIORITY', '')
                        transformed_output_list.append(transformed_output2)
                egress_interface = flows[flow_index].pop("SET_INTERFACE", [])
                if egress_interface:
                    for nh_index in range(len(egress_interface)):
                        transformed_output3 = transformed_output.copy()
                        transformed_output3['next_hop_interface'] = egress_interface[nh_index].get('INTERFACE', '')
                        transformed_output3['interface_priority'] = egress_interface[nh_index].get('PRIORITY', '')
                        transformed_output_list.append(transformed_output3)

                if 'DEFAULT_PACKET_ACTION' in flows[flow_index].keys():
                    default_packet_action = True
                    transformed_output4 = transformed_output.copy()
                    transformed_output4['next_hop_interface'] = 'null'
                    transformed_output_list.append(transformed_output4)

            applied_ports = item.pop('APPLIED_INTERFACES',[])
            for port_index in range(len(applied_ports)):
                transformed_output5 = transformed_output.copy()
                transformed_output5['interface'] = applied_ports[port_index].get("INTERFACE_NAME",'')
                transformed_output5['stage'] = applied_ports[port_index].get("STAGE",'').capitalize()
                transformed_output_list.append(transformed_output5)

            if not (len(applied_ports) and ip_next_hop and ipv6_next_hop and egress_interface and default_packet_action):
                transformed_output_list.append(transformed_output)
    elif type == 'POLICIES' and yang_model == 'ocyang':
        for item in output.get('openconfig-fbs-ext:policy',[]):
            transformed_output = {}
            transformed_output['policy_name'] = item.get('state',{}).get("name", '')
            policy_type = item.get('state',{}).get("type", '').lower()
            if 'openconfig-fbs-ext' in policy_type:
                transformed_output['policy_type'] = policy_type.split('_')[1]
            else:
                transformed_output['policy_type'] = ''
            transformed_output['desc_name'] = item.get('state',{}).get("description", '')
            flows = item.get('sections',{}).get('section', [])
            for flow_index in range(len(flows)):
                transformed_output['class_name'] = flows[flow_index].get('state',{}).get("name", '')
                transformed_output['priority_val'] = flows[flow_index].get('state',{}).get("priority", '')
                transformed_output['dscp_val'] = flows[flow_index].get('qos',{}).get('state',{}).get('set-dscp','')
                transformed_output['pcp_val'] = flows[flow_index].get('qos',{}).get('state',{}).get('set-dot1p','')
                mirror_session = flows[flow_index].get('monitoring',{}).get('mirror-sessions',{}).get('mirror-session',[])
                if mirror_session:
                    transformed_output['mirror_session'] = mirror_session[0]
                else:
                    transformed_output['mirror_session'] = ''
                ip_next_hop = flows[flow_index].get('forwarding',{}).get('next-hops', {}).get('next-hop',[])
                if ip_next_hop:
                    for nh_index in range(len(ip_next_hop)):
                        transformed_output1 = transformed_output.copy()
                        transformed_output1['next_hop'] = ip_next_hop[nh_index].get('state',{}).get('ip-address', '')
                        next_hop_vrf = ip_next_hop[nh_index].get('state',{}).get('network-instance', '')
                        if 'openconfig-fbs-ext' in next_hop_vrf:
                            next_hop_vrf = next_hop_vrf.split('_')[1]
                            if 'NETWORK' in next_hop_vrf:next_hop_vrf=''
                        transformed_output1['next_hop_vrf'] =  next_hop_vrf
                        transformed_output1['next_hop_priority'] = ip_next_hop[nh_index].get('state',{}).get('priority', '')
                        transformed_output_list.append(transformed_output1)
                egress_interface = flows[flow_index].get('forwarding',{}).get('egress-interfaces', {}).get('egress-interface',[])
                if egress_interface:
                    for nh_index in range(len(egress_interface)):
                        transformed_output3 = transformed_output.copy()
                        transformed_output3['next_hop_interface'] = egress_interface[nh_index].get('state',{}).get('intf-name', '')
                        transformed_output3['interface_priority'] = egress_interface[nh_index].get('state',{}).get('priority', '')
                        transformed_output_list.append(transformed_output3)

                discard_action = flows[flow_index].get('forwarding',{}).get('config',{}).get('discard',False)
                if discard_action:
                    #default_packet_action = True
                    transformed_output4 = transformed_output.copy()
                    transformed_output4['next_hop_interface'] = 'null'
                    transformed_output_list.append(transformed_output4)
            transformed_output_list.append(transformed_output)
    elif type == 'INTERFACES' and yang_model =='sonic':
        transformed_output = {}
        for item in output.get('INTERFACES',[]):
            transformed_output['interface_name'] = item.pop('INTERFACE_NAME','')
            policy_list = item.pop("APPLIED_POLICIES",[])
            default_packet_action = False
            if policy_list:
              for index in range(len(policy_list)):
                transformed_output1 = transformed_output.copy()
                transformed_output1['policy_name'] = policy_list[index].pop('POLICY_NAME','')
                transformed_output1['policy_type'] = policy_list[index].pop('TYPE','').lower()
                transformed_output1['stage'] = policy_list[index].pop('STAGE','').lower()
                transformed_output_list.append(transformed_output1)
                default_packet_action = True

                flows = policy_list[index].pop('FLOWS',[])
                if flows:
                  for flow_index in range(len(flows)):
                    default_flow_action = False
                    transformed_output2 = transformed_output1.copy()
                    transformed_output2['class_name'] = flows[flow_index].get("CLASS_NAME", '')
                    transformed_output2['priority_val'] = flows[flow_index].get("PRIORITY", '')
                    transformed_output2['dscp_val'] = flows[flow_index].get("SET_DSCP", '')
                    transformed_output2['pcp_val'] = flows[flow_index].get("SET_PCP", '')
                    transformed_output2['mirror_session'] = flows[flow_index].get("SET_MIRROR_SESSION", '')
                    transformed_output2['cir_val'] = flows[flow_index].get("SET_POLICER_CIR", '')
                    transformed_output2['cbs_val'] = flows[flow_index].get("SET_POLICER_CBS", '')
                    transformed_output2['pir_val'] = flows[flow_index].get("SET_POLICER_PIR", '')
                    transformed_output2['pbs_val'] = flows[flow_index].get("SET_POLICER_PBS", '')
                    transformed_output2['tc_val'] = flows[flow_index].get("SET_TC", '')

                    state = flows[flow_index].pop("STATE", '')
                    selected_dict = {}
                    if state:
                        transformed_output3 = transformed_output2.copy()
                        flow_state = state.get('STATUS', '')
                        transformed_output3['flow_state'] = '('+str(flow_state)+')'
                        transformed_output3['match_pkts_val'] = state.get('MATCHED_PACKETS', '')
                        transformed_output3['match_bytes_val'] = state.get('MATCHED_BYTES', '')
                        selected_entry = state.get('FORWARDING_SELECTED',{})
                        selected_dict['next_hop'] = selected_entry.get('IP_ADDRESS','')
                        selected_dict['next_hop_vrf'] = selected_entry.get('VRF','')
                        selected_dict['next_hop_priority'] = selected_entry.get('PRIORITY','')
                        selected_dict['next_hop_interface'] = selected_entry.get('INTERFACE_NAME')
                        selected_dict['null'] = selected_entry.get('PACKET_ACTION','')
                        transformed_output_list.append(transformed_output3)
                        default_packet_action = default_flow_action = True
                    ip_next_hop = flows[flow_index].pop("SET_IP_NEXTHOP", [])
                    if ip_next_hop:
                        for nh_index in range(len(ip_next_hop)):
                            transformed_output4 = transformed_output3.copy()
                            transformed_output4['next_hop'] = ip_next_hop[nh_index].get('IP_ADDRESS', '')
                            transformed_output4['next_hop_vrf'] = ip_next_hop[nh_index].get('VRF', '')
                            transformed_output4['next_hop_priority'] = ip_next_hop[nh_index].get('PRIORITY', '')
                            if selected_dict['next_hop'] == transformed_output4['next_hop'] and selected_dict['next_hop_vrf'] == transformed_output4['next_hop_vrf']:
                              transformed_output4['selected'] = 'Selected'
                            transformed_output_list.append(transformed_output4)
                            default_packet_action = default_flow_action = True
                    ipv6_next_hop = flows[flow_index].pop("SET_IPV6_NEXTHOP", [])
                    if ipv6_next_hop:
                        for nh_index in range(len(ipv6_next_hop)):
                            transformed_output5 = transformed_output3.copy()
                            transformed_output5['next_hop'] = ipv6_next_hop[nh_index].get('IP_ADDRESS', '')
                            transformed_output5['next_hop_vrf'] = ipv6_next_hop[nh_index].get('VRF', '')
                            transformed_output5['next_hop_priority'] = ipv6_next_hop[nh_index].get('PRIORITY', '')
                            if selected_dict['next_hop'] == transformed_output5['next_hop'] and selected_dict['next_hop_vrf'] == transformed_output5['next_hop_vrf']:
                              transformed_output5['selected'] = 'Selected'
                            transformed_output_list.append(transformed_output5)
                            default_packet_action = default_flow_action = True
                    egress_interface = flows[flow_index].pop("SET_INTERFACE", [])
                    if egress_interface:
                        for nh_index in range(len(egress_interface)):
                            transformed_output6 = transformed_output3.copy()
                            transformed_output6['next_hop_interface'] = egress_interface[nh_index].get('INTERFACE', '')
                            transformed_output6['interface_priority'] = egress_interface[nh_index].get('PRIORITY', '')
                            if selected_dict['next_hop_interface'] == transformed_output6['next_hop_interface'] and selected_dict['next_hop_priority'] == transformed_output6['interface_priority']:
                              transformed_output6['selected'] = 'Selected'
                            transformed_output_list.append(transformed_output6)
                            default_packet_action = default_flow_action = True

                    if 'DEFAULT_PACKET_ACTION' in flows[flow_index].keys():
                        transformed_output7 = transformed_output3.copy()
                        transformed_output7['next_hop_interface'] = 'null'
                        if selected_dict['null'] == 'DROP':
                          transformed_output7['selected'] = 'Selected'
                        transformed_output_list.append(transformed_output7)
                        default_packet_action = default_flow_action = True
                    if not default_flow_action:
                        transformed_output_list.append(transformed_output2)
                        default_packet_action = True
            if not default_packet_action:
                transformed_output_list.append(transformed_output)
    elif type == 'INTERFACES' and yang_model == 'ocyang':
        transformed_output1 = {}
        for item in output.get('openconfig-fbs-ext:interface',[]):
          transformed_output1['interface_name'] = item.get('state',{}).get('id','')
          for direction in ['ingress','egress']:
              for policy_type in item.get("{}-policies".format(direction),{}).keys():
                transformed_output1['policy_name'] = item.get('{}-policies'.format(direction),{}).get(policy_type,{}).get('state',{}).get('policy-name','')
                transformed_output1['policy_type'] = policy_type
                transformed_output1['stage'] = direction
                transformed_output_list.append(transformed_output1)

                flows = item.get('{}-policies'.format(direction),{}).get(policy_type,{}).get('sections',{}).get('section',[])
                if flows:
                  for flow_index in range(len(flows)):
                    #default_flow_action = False
                    transformed_output2 = transformed_output1.copy()
                    transformed_output2['class_name'] = flows[flow_index].get('state',{}).get("class-name", '')
                    transformed_output2['cir_val'] = flows[flow_index].get('state',{}).get("cir", '')
                    transformed_output2['cbs_val'] = flows[flow_index].get('state',{}).get("cbs", '')
                    transformed_output2['pir_val'] = flows[flow_index].get('state',{}).get("pir", '')
                    transformed_output2['pbs_val'] = flows[flow_index].get('state',{}).get("pbs", '')
                    discard = flows[flow_index].get('state', {}).get("discard", False)

                    flow_state = flows[flow_index].get('state',{}).get("active",False)
                    if flow_state:
                        transformed_output2['flow_state'] = '(Active)'
                    else:
                        transformed_output2['flow_state'] = '(Inactive)'
                    transformed_output2['match_pkts_val'] = flows[flow_index].get('state',{}).get("matched-packets", '0')
                    transformed_output2['match_bytes_val'] = flows[flow_index].get('state',{}).get("matched-octets", '0')
                    transformed_output2['next_hop'] = flows[flow_index].get('next-hop',{}).get('state',{}).get('ip-address','')
                    next_hop_vrf = flows[flow_index].get('next-hop',{}).get('state',{}).get('network-instance','')
                    if 'openconfig-fbs-ext' in next_hop_vrf:
                        next_hop_vrf = next_hop_vrf.split('_')[1]
                        if 'NETWORK' in next_hop_vrf: next_hop_vrf = ''
                    transformed_output2['next_hop_vrf'] = next_hop_vrf
                    transformed_output2['next_hop_priority'] = flows[flow_index].get('next-hop',{}).get('state',{}).get('priority','')
                    transformed_output2['next_hop_interface'] = flows[flow_index].get('egress-interface',{}).get('state',{}).get('intf-name','')
                    transformed_output2['selected'] = 'Selected'
                    if discard:
                        transformed_output2['next_hop_interface'] = 'null'
                    transformed_output_list.append(transformed_output2)
    elif type =='SUMMARY':
        for item in output:
            transformed_output ={}
            transformed_output['interface_name'] = item.get('INTERFACE_NAME', '')
            for k in item.keys():
                if 'INTERFACE' not in k:
                    match = k.split('_')
                    if match:
                        transformed_output1 = transformed_output.copy()
                        transformed_output1['stage'] = match[0].lower()
                        transformed_output1['policy_type'] = match[1].lower()
                        transformed_output1['policy_name'] = item.pop('{}_{}_POLICY'.format(match[0],match[1]))
                        transformed_output_list.append(transformed_output1)

    return transformed_output_list

def config_pbf_nhgroup(dut,nhgroup_name, **kwargs):
    """
    author: Raghukumar Rampur
    :param nhg_type:
    :type nhg_type:
    :param nhgroup_name:
    :type nhgroup_name:
    :param entryID:
    :type entryID:
    :param next_hop:
    :type next_hop:
    :param vrf_name:
    :type vrf_name:
    :param next_hop_type:
    :type next_hop_type:
    :param threshold_type:
    :type threshold_type:
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    config_pbf_nhgroup(dut1,nhgroup_name='IPV4_TCP_LOAD_BALANCER',entryID ='1',next_hop='1.1.1.2')
    config_pbf_nhgroup(dut1,nhgroup_name='IPV6_TCP_LOAD_BALANCER',entryID ='1',next_hop='2001::10',nhg_type='ipv6')
    config_pbf_nhgroup(dut1,nhgroup_name='IPV4_TCP_LOAD_BALANCER',entryID ='1',next_hop='1.1.1.2',next_hop_type='non-recursive')
    config_pbf_nhgroup(dut1,nhgroup_name='IPV4_TCP_LOAD_BALANCER',entryID =[1,2],next_hop=['1.1.1.2','2.2.2.1'],vrf_name='vrf-red',next_hop_type='recursive')
    config_pbf_nhgroup(dut1,nhgroup_name='IPV4_TCP_LOAD_BALANCER',entryID =[1,2],next_hop=['1.1.1.2','2.2.2.1'],vrf_name='vrf-red',next_hop_type='recursive',threshold_type='count')
    config_pbf_nhgroup(dut1,nhgroup_name='IPV4_TCP_LOAD_BALANCER',entryID =[1,2],next_hop=['1.1.1.2','2.2.2.1'],vrf_name='vrf-red',next_hop_type='recursive',threshold_type='percentage',up_value=100,down_value=1)
    config_pbf_nhgroup(dut1,nhgroup_name='IPV4_TCP_LOAD_BALANCER',entryID =[1,2],config='no')
    config_pbf_nhgroup(dut1,nhgroup_name='IPV4_TCP_LOAD_BALANCER',config='no')
    """
    nhg_type = kwargs.pop('nhg_type', 'ip')
    config = kwargs.pop('config', 'yes')
    skip_error = kwargs.pop('skip_error', False)


    cli_type = st.get_ui_type(dut,**kwargs)
    #if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'

    cmd =''
    if cli_type in get_supported_ui_type_list():
        fbs_obj = umf_fbs.Root()
        group_type = 'NEXT_HOP_GROUP_TYPE_IPV4' if nhg_type == 'ip' else 'NEXT_HOP_GROUP_TYPE_IPV6'
        nhgroup_obj = umf_fbs.NextHopGroup(Name=nhgroup_name, Type=group_type, Root=fbs_obj)
        if config.lower() == "yes":
            nhgroup_obj.configure(dut, cli_type=cli_type)
            if 'entryID' in kwargs and 'next_hop' in kwargs:
                kwargs['entryID'] = [kwargs['entryID']] if type(kwargs['entryID']) is str else kwargs['entryID']
                kwargs['next_hop'] = [kwargs['next_hop']] if type(kwargs['next_hop']) is str else kwargs['next_hop']
                vrf_name = kwargs.pop('vrf_name', '')
                next_hop_type = kwargs.pop('next_hop_type', '')
                if next_hop_type == 'overlay':
                    nh_type = 'NEXT_HOP_TYPE_OVERLAY'
                elif next_hop_type == 'recursive':
                    nh_type = 'NEXT_HOP_TYPE_RECURSIVE'
                elif next_hop_type == 'non-recursive':
                    nh_type = 'NEXT_HOP_TYPE_NON_RECURSIVE'
                if vrf_name == '':
                    vrf_name = None
                if len(kwargs['entryID']) != len(kwargs['next_hop']):
                   st.error('Please check entryID list and next_hop list, number of entries should be same')
                   return False
                for id,nextHop_ip in zip(kwargs['entryID'],kwargs['next_hop']):
                    nhent_obj = umf_fbs.NHGroupMember(EntryId=id, Ip=nextHop_ip,
                                                                Vrf=vrf_name,
                                                                NhType=nh_type,
                                                                NextHopGroup=nhgroup_obj)
                    result = nhent_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Creation of nexthop group entry {}'.format(result.data))
            if 'threshold_type' in kwargs:
                if kwargs['threshold_type'] == 'count':
                    nhg_tytype = 'NEXT_HOP_GROUP_THRESHOLD_COUNT'
                else:
                    nhg_tytype = 'NEXT_HOP_GROUP_THRESHOLD_PERCENTAGE'
                nhgroup_obj.ThrType = nhg_tytype
                if 'up_value' in kwargs and 'down_value' in kwargs:
                   nhgroup_obj.ThrUp = kwargs['up_value']
                   nhgroup_obj.ThrDown = kwargs['down_value']
                result = nhgroup_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Creation of nexthop group threashold {}'.format(result.data))
        elif config.lower() == "no":
            if 'threshold_type' in kwargs:
               if kwargs['threshold_type'] == 'count':
                    nhg_tytype = 'NEXT_HOP_GROUP_THRESHOLD_COUNT'
               else:
                    nhg_tytype = 'NEXT_HOP_GROUP_THRESHOLD_PERCENTAGE'
               nhgroup_obj.ThrType = nhg_tytype
               result = nhgroup_obj.unConfigure(dut, cli_type=cli_type, target_attr=nhgroup_obj.ThrType)
            elif 'entryID' in kwargs:
                kwargs['entryID'] = [kwargs['entryID']] if type(kwargs['entryID']) is str else kwargs['entryID']
                for id in kwargs['entryID']:
                    nhent_obj = umf_fbs.NHGroupMember(EntryId=id, NextHopGroup=nhgroup_obj)
                    result = nhent_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Deletion of nexthop group entry {}'.format(result.data))
            else:
                result = nhgroup_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Deletion of nexthop group threshold {}'.format(result.data))
    elif cli_type == "klish":
        if config.lower() == "yes":
            cmd += " pbf next-hop-group {} type {}\n".format(nhgroup_name,nhg_type)
            if 'entryID' in kwargs and 'next_hop' in kwargs:
                kwargs['entryID'] = [kwargs['entryID']] if type(kwargs['entryID']) is str else kwargs['entryID']
                kwargs['next_hop'] = [kwargs['next_hop']] if type(kwargs['next_hop']) is str else kwargs['next_hop']
                vrf_name = kwargs.pop('vrf_name', '')
                next_hop_type = kwargs.pop('next_hop_type', '')
                if vrf_name !='':
                    vrf_name = 'vrf '+vrf_name
                if len(kwargs['entryID']) != len(kwargs['next_hop']):
                   st.error('Please check entryID list and next_hop list, number of entries should be same')
                   return False
                for id,nextHop_ip in zip(kwargs['entryID'],kwargs['next_hop']):
                    cmd += " entry {} next-hop {} {} {}\n".format(id,nextHop_ip,vrf_name,next_hop_type)
            if 'threshold_type' in kwargs:
                if kwargs['threshold_type'] == 'count':
                    if 'up_value' in kwargs and 'down_value' in kwargs:
                        cmd += " threshold type {} up {} down {}\n".format(kwargs['threshold_type'],kwargs['up_value'],kwargs['down_value'])
                    else:
                        cmd += " threshold type {} \n".format(kwargs['threshold_type'])
                else:
                    if 'up_value' in kwargs and 'down_value' in kwargs:
                        cmd += " threshold type {} up {} down {}\n".format(kwargs['threshold_type'],kwargs['up_value'],kwargs['down_value'])
                    else:
                        cmd += " threshold type {} \n".format(kwargs['threshold_type'])

            cmd += "exit\n"
        elif config.lower() == "no":
            if 'threshold_type' in kwargs:
                cmd += " pbf next-hop-group {} type {}\n".format(nhgroup_name,nhg_type)
                cmd += "no threshold \n"
                cmd += "exit\n"
            elif 'entryID' in kwargs:
                kwargs['entryID'] = [kwargs['entryID']] if type(kwargs['entryID']) is str else kwargs['entryID']
                cmd += " pbf next-hop-group {} type {}\n".format(nhgroup_name,nhg_type)
                for id in kwargs['entryID']:
                    cmd += "no entry {} \n".format(id)
                cmd += "exit\n"
            else:
                cmd += "no pbf next-hop-group {}\n".format(nhgroup_name)
        output =st.config(dut, cmd, skip_error_check=skip_error, type=cli_type)
        return output
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        if config.lower() == "yes":
            group_type = 'NEXT_HOP_GROUP_TYPE_IPV4' if nhg_type == 'ip' else 'NEXT_HOP_GROUP_TYPE_IPV6'
            st.banner('nhg_type {}'.format(nhg_type))
            rest_url = rest_urls['config_pbf_nhg_name'].format(nhgroup_name)
            payload ={'openconfig-fbs-ext:next-hop-group': [{'group-name': nhgroup_name, 'config': {'group-type': group_type, 'name': nhgroup_name}}]}
            config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

            if 'entryID' in kwargs and 'next_hop' in kwargs:
                kwargs['entryID'] = [kwargs['entryID']] if type(kwargs['entryID']) is str else kwargs['entryID']
                kwargs['next_hop'] = [kwargs['next_hop']] if type(kwargs['next_hop']) is str else kwargs['next_hop']
                vrf_name = kwargs.pop('vrf_name', '')
                next_hop_type = kwargs.pop('next_hop_type', '')
                st.banner('Next hop type is {}'.format(next_hop_type))
                if next_hop_type !='':
                    if next_hop_type == 'overlay':
                        nh_type = 'NEXT_HOP_TYPE_OVERLAY'
                    elif next_hop_type == 'recursive':
                        nh_type = 'NEXT_HOP_TYPE_RECURSIVE'
                    elif next_hop_type == 'non-recursive':
                        nh_type = 'NEXT_HOP_TYPE_NON_RECURSIVE'

                if len(kwargs['entryID']) != len(kwargs['next_hop']):
                   st.error('Please check entryID list and next_hop list, number of entries should be same')
                   return False
                if vrf_name !='':
                    for id,nextHop_ip in zip(kwargs['entryID'],kwargs['next_hop']):
                        rest_url = rest_urls['config_pbf_nhg_details'].format(nhgroup_name,id)
                        if next_hop_type !='':
                            payload ={'openconfig-fbs-ext:next-hop': [{"entry-id": id, 'config': {'entry-id': id, 'next-hop-type': nh_type, 'network-instance': vrf_name, 'ip-address': nextHop_ip}}]}
                        else:
                            payload ={'openconfig-fbs-ext:next-hop': [{'entry-id': id, 'config': {'entry-id': id, 'network-instance': vrf_name ,"ip-address": nextHop_ip}}]}

                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                else:
                    for id,nextHop_ip in zip(kwargs['entryID'],kwargs['next_hop']):
                        rest_url = rest_urls['config_pbf_nhg_details'].format(nhgroup_name,id)
                        if next_hop_type !='':
                            payload ={'openconfig-fbs-ext:next-hop': [{"entry-id": id, 'config': {'entry-id': id, 'next-hop-type': nh_type, 'ip-address': nextHop_ip}}]}
                        else:
                            payload ={'openconfig-fbs-ext:next-hop': [{'entry-id': id, 'config': {'entry-id': id, "ip-address": nextHop_ip}}]}

                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

            if 'threshold_type' in kwargs:
                rest_url = rest_urls['config_pbf_nhg_threshold_details'].format(nhgroup_name)
                if kwargs['threshold_type'] == 'count':
                    nhg_tytype = 'NEXT_HOP_GROUP_THRESHOLD_COUNT'
                    if 'up_value' in kwargs and 'down_value' in kwargs:
                        payload ={'openconfig-fbs-ext:config': {'threshold-type': nhg_tytype, "threshold-up": kwargs['up_value'], "threshold-down": kwargs['down_value']}}
                    else:
                        payload ={'openconfig-fbs-ext:config': {'threshold-type': nhg_tytype}}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                else:
                    nhg_tytype = 'NEXT_HOP_GROUP_THRESHOLD_PERCENTAGE'
                    if 'up_value' in kwargs and 'down_value' in kwargs:
                        payload ={'openconfig-fbs-ext:config': {'threshold-type': nhg_tytype, "threshold-up": kwargs['up_value'], "threshold-down": kwargs['down_value']}}
                    else:
                        payload ={'openconfig-fbs-ext:config': {'threshold-type': nhg_tytype}}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

        elif config.lower() == "no":
            if 'threshold_type' in kwargs:
                rest_url = rest_urls['delete_pbf_nhg_threshold_details'].format(nhgroup_name)
                delete_rest(dut, http_method=cli_type, rest_url=rest_url)
            elif 'entryID' in kwargs:
                kwargs['entryID'] = [kwargs['entryID']] if type(kwargs['entryID']) is str else kwargs['entryID']
                for id in kwargs['entryID']:
                    rest_url = rest_urls['delete_pbf_nhg_details'].format(nhgroup_name,id)
                    delete_rest(dut, http_method=cli_type, rest_url=rest_url)
            else:
                rest_url = rest_urls['delete_pbf_nhg_name'].format(nhgroup_name)
                delete_rest(dut, http_method=cli_type, rest_url=rest_url)
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def show_pbf_nhgroup(dut,nhgroup_name, **kwargs):
    """
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :param :nhgroup_name: Name of next-hop-group:
    :param :nhg_type: Type - ip or ipv6:
    :return:
    """

    cli_type = st.get_ui_type(dut,**kwargs)
    # This is not supported in click.
    cli_type = 'klish' if cli_type == 'click' else cli_type
    skip_error = kwargs.get('skip_error', False)
    #cmd_name = kwargs.get('nhgroup_name', '')
    cmd_type = kwargs.get('nhg_type', 'ip')
    if cmd_type != '':
        cmd_type = "type {}".format(cmd_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'klish':
        command = "show pbf next-hop-group {}".format(cmd_type)
        return st.show(dut, command, type=cli_type, skip_error_check=skip_error)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_pbf_nhg'].format(nhgroup_name)
        out = get_rest(dut, rest_url=rest_url)
        nhg_type = ''
        th_type =''
        th_down =''
        th_up=''
        policy_name=''
        policy_priority=''
        desc_name=''
        multi_var =[]


        if 'threshold-type' in out['output']['openconfig-fbs-ext:next-hop-group'][0]['state']:
            th_type =str(out['output']['openconfig-fbs-ext:next-hop-group'][0]['state']['threshold-type'])
        if th_type =="openconfig-fbs-ext:NEXT_HOP_GROUP_THRESHOLD_COUNT":
            th_type ="Count"
        elif th_type =="openconfig-fbs-ext:NEXT_HOP_GROUP_THRESHOLD_PERCENTAGE":
            th_type ="Percentage"
        if 'threshold-down' in out['output']['openconfig-fbs-ext:next-hop-group'][0]['state']:
            th_down =str(out['output']['openconfig-fbs-ext:next-hop-group'][0]['state']['threshold-down'])
        if 'threshold-up' in out['output']['openconfig-fbs-ext:next-hop-group'][0]['state']:
            th_up =str(out['output']['openconfig-fbs-ext:next-hop-group'][0]['state']['threshold-up'])
        if 'group-type' in out['output']['openconfig-fbs-ext:next-hop-group'][0]['state']:
            nhg_type =str(out['output']['openconfig-fbs-ext:next-hop-group'][0]['state']['group-type'])
        if nhg_type =="openconfig-fbs-ext:NEXT_HOP_GROUP_TYPE_IPV4":
            nhg_type ="ip"
        elif nhg_type =="openconfig-fbs-ext:NEXT_HOP_GROUP_TYPE_IPV6":
            nhg_type ="ipv6"

        nhgroup_name =str(out['output']['openconfig-fbs-ext:next-hop-group'][0]['state']['name'])
        single_var ={'threshold_type': th_type, 'threshold_down': th_down, 'threshold_up': th_up,'nhgroup_name':nhgroup_name,'policy_name':policy_name,'policy_priority':policy_priority,'desc_name':desc_name,'nhg_type':nhg_type}

        if 'next-hops' in out['output']['openconfig-fbs-ext:next-hop-group'][0]:
            len_entries =len(out['output']['openconfig-fbs-ext:next-hop-group'][0]['next-hops']['next-hop'])
            for i in range(len_entries):
                entry_id=''
                nh_type =''
                nh_ip=''
                nh_vrf=''
                entry = out['output']['openconfig-fbs-ext:next-hop-group'][0]['next-hops']['next-hop'][i]
                entry_id =str(entry['state']['entry-id'])
                if 'next-hop-type' in entry['state']:
                    nh_type =str(entry['state']['next-hop-type'])
                if nh_type =="openconfig-fbs-ext:NEXT_HOP_TYPE_OVERLAY":
                    nh_type='overlay'
                if nh_type =="openconfig-fbs-ext:NEXT_HOP_TYPE_RECURSIVE":
                    nh_type='recursive'
                if nh_type =="openconfig-fbs-ext:NEXT_HOP_TYPE_NON_RECURSIVE":
                    nh_type='non-recursive'

                if 'network-instance' in entry['state']:
                    nh_vrf =str(entry['state']['network-instance'])
                nh_ip =str(entry['state']['ip-address'])
                entry_dict= {'entry': entry_id, 'nh_type': nh_type, 'nh_ip': nh_ip,'nh_vrf':nh_vrf}
                multi_var.append(entry_dict)

        multi_var.append(single_var)
        st.banner(multi_var)
        return multi_var
    else:
        st.error("Unsupported CLI_TYPE: {}.".format(cli_type))
    return False


def verify_pbf_nexthopgroup(dut,nhgroup_name, **kwargs):
    """
    Verify
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :ip: ipv4 values (single or list)
    :param :ipv6: ipv6 values (single or list)
    :param :seed: hash seed value
    :param :cli_type:
    :param :skip_error:
    :return:
    """
    return_key = True

    output = show_pbf_nhgroup(dut,nhgroup_name, **kwargs)
    st.log("output={}, kwargs={}".format(output,kwargs))
    for key in ['cli_type', 'skip_error']:
        kwargs.pop(key, None)

    str_params = ['nhgroup_name', 'nhg_type', 'desc_name', 'threshold_type', 'threshold_up', 'threshold_down', 'policy_name', 'policy_priority']
    # Length of all list params should be equal.
    list_params = ['nh_ip', 'entry', 'nh_type', 'nh_vrf']

    valid_str_dict = {}
    for key in str_params:
        if key in kwargs:
            valid_str_dict[key] = kwargs[key]
    if not filter_and_select(output, None, valid_str_dict):
        st.log("{} is not matching in the output:\n {}".format(valid_str_dict, output))
        return_key = False

    nh_list=''
    entry_list=''
    nht_list=''
    nhv_list=''
    if 'nh_ip' in kwargs:
        nh_list = kwargs['nh_ip']
        nh_list = [nh_list] if type(nh_list) is str else nh_list
        entry_list = kwargs.get('entry', ['']*len(nh_list))
        nht_list = kwargs.get('nh_type', ['']*len(nh_list))
        nhv_list = kwargs.get('nh_vrf', ['']*len(nh_list))
        entry_list = [entry_list] if type(entry_list) is str else entry_list
        nht_list = [nht_list] if type(nht_list) is str else nht_list
        nhv_list = [nhv_list] if type(nhv_list) is str else nhv_list
        valid_dict={}
        for nh, ent, nht, nhv in zip(nh_list, entry_list, nht_list, nhv_list):
            valid_dict = dict(zip(list_params,[nh, ent, nht, nhv]))
            for k, v in dict(valid_dict).items():
                if v == '':
                    del valid_dict[k]
        if not filter_and_select(output, None, valid_dict):
            st.log("{} is not matching in the output.".format(valid_dict))
            return_key = False

    return return_key

def show_pbf_nhg_status(dut, **kwargs):
    """
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :param :interface: Name of the interface
    :return:
    """

    cli_type = st.get_ui_type(dut,**kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    skip_error = kwargs.get('skip_error', False)
    if 'interface' not in kwargs:
        st.error("Mandatory parameter - interface name is missing")
        return False
    intf_name = kwargs.get('interface', '')
    pintf = get_interface_number_from_name(intf_name)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'klish':
        command = "show pbf next-hop-group status interface {} {}".format(pintf['type'], pintf['number'])
        return st.show(dut, command, type=cli_type, skip_error_check=skip_error)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_pbf_nhg_status'].format(kwargs['interface'])
        out = get_rest(dut, rest_url=rest_url)

        multi_var =[]
        len_entries =len(out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'])
        for i in range(len_entries):
            nhgroup_name=''
            nhg_type=''
            status=''
            
            if 'active' in out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'][i]['state']:
                status =str(out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'][i]['state']['active'])
                if status =='False':
                    status='Inactive'
                elif status =='True':
                    status='Active'
            if 'name' in out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'][i]['state']:
                nhgroup_name =str(out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'][i]['state']['name'])
            
            if 'group-type' in out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'][i]['state']:               
                nhg_type =str(out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'][i]['state']['group-type'])
                if nhg_type =="openconfig-fbs-ext:NEXT_HOP_GROUP_TYPE_IPV4":
                    nhg_type ="ip"
                elif nhg_type =="openconfig-fbs-ext:NEXT_HOP_GROUP_TYPE_IPV6":
                    nhg_type ="ipv6"
            entry_dict_single= {'nhg_type':nhg_type ,'status':status,'nhgroup_name':nhgroup_name}
            multi_var.append(entry_dict_single)

            if 'next-hops' in out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'][i]:
                len_entries_nh =len(out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'][i]['next-hops']['next-hop'])
                for j in range(len_entries_nh):
                    entry_id=''
                    nh_type =''
                    nh_ip=''
                    nh_vrf=''
                    nh_status=''

                    entry = out['output']['openconfig-fbs-ext:next-hop-groups']['next-hop-group'][i]['next-hops']['next-hop'][j]
                    entry_id =str(entry['state']['entry-id'])
                    if 'next-hop-type' in entry['state']:
                        nh_type =str(entry['state']['next-hop-type'])
                    if nh_type =="openconfig-fbs-ext:NEXT_HOP_TYPE_OVERLAY":
                        nh_type='overlay'
                    if nh_type =="openconfig-fbs-ext:NEXT_HOP_TYPE_RECURSIVE":
                        nh_type='recursive'
                    if nh_type =="openconfig-fbs-ext:NEXT_HOP_TYPE_NON_RECURSIVE":
                        nh_type='non-recursive'

                    if 'network-instance' in entry['state']:
                        nh_vrf =str(entry['state']['network-instance'])
                    nh_ip =str(entry['state']['ip-address'])
                    nh_status =str(entry['state']['active'])
                    if nh_status =='False':
                       nh_status=''
                    elif nh_status =='True':
                        nh_status='Active'
                    entry_dict= {'entry': entry_id, 'nh_type': nh_type, 'nh_ip': nh_ip,'nh_vrf':nh_vrf,'nh_status':nh_status}
                    multi_var.append(entry_dict)

            #multi_var.append(single_var)
        st.banner(multi_var)
        return multi_var
    else:
        st.error("Unsupported CLI_TYPE: {}.".format(cli_type))
    return False


def verify_pbf_nhg_status(dut, **kwargs):
    """
    Verify
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :nhgroup_name
    :param :nhg_type
    :param :status
    :param :nh_ip
    :param :nh_type
    :param :nh_status
    :param :nh_vrf
    :param :entry
    :param :cli_type:
    :param :skip_error:
    :return:
    """
    return_key = True

    output = show_pbf_nhg_status(dut, **kwargs)
    st.log("output={}, kwargs={}".format(output,kwargs))
    for key in ['cli_type', 'skip_error']:
        kwargs.pop(key, None)

    str_params = ['nhgroup_name', 'nhg_type', 'status']
    # Length of all list params should be equal.
    list_params = ['nh_ip', 'entry', 'nh_type', 'nh_vrf','nh_status']

    valid_str_dict = {}
    for key in str_params:
        if key in kwargs:
            valid_str_dict[key] = kwargs[key]
    if not filter_and_select(output, None, valid_str_dict):
        st.log("{} is not matching in the output:\n {}".format(valid_str_dict, output))
        return_key = False

    nh_list=''
    entry_list=''
    nht_list=''
    nhv_list=''
    nhs_list=''
    if 'nh_ip' in kwargs:
        nh_list = kwargs['nh_ip']
        nh_list = [nh_list] if type(nh_list) is str else nh_list
        entry_list=kwargs.get('entry', ['']*len(nh_list))
        nht_list=kwargs.get('nh_type', ['']*len(nh_list))
        nhv_list=kwargs.get('nh_vrf', ['']*len(nh_list))
        nhs_list=kwargs.get('nh_status', ['']*len(nh_list))

        entry_list = [entry_list] if type(entry_list) is str else entry_list
        nht_list = [nht_list] if type(nht_list) is str else nht_list
        nhv_list = [nhv_list] if type(nhv_list) is str else nhv_list
        nhs_list = [nhs_list] if type(nhs_list) is str else nhs_list
        valid_dict={}
        for nh, ent, nht, nhv, nhs in zip(nh_list, entry_list, nht_list, nhv_list,nhs_list):
            valid_dict = dict(zip(list_params,[nh, ent, nht, nhv, nhs]))
            for k, v in dict(valid_dict).items():
                if v == '':
                    del valid_dict[k]
        if not filter_and_select(output, None, valid_dict):
            st.log("{} is not matching in the output.".format(valid_dict))
            return_key = False

    return return_key

def config_pbf_replication_group(dut,repgroup_name, **kwargs):
    """
    author: Raghukumar Rampur
    :param repg_type:
    :type repg_type:
    :param repgroup_name:
    :type repgroup_name:
    :param entryID:
    :type entryID:
    :param next_hop:
    :type next_hop:
    :param vrf_name:
    :type vrf_name:
    :param next_hop_type:
    :type next_hop_type:
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    config_pbf_replication_group(dut1,repgroup_name='IPv4_Rep_Group',entryID ='1',next_hop='1.1.1.2')
    config_pbf_replication_group(dut1,repgroup_name='IPv6_Rep_Group',entryID ='1',next_hop='2001::10',repg_type='ipv6')
    config_pbf_replication_group(dut1,repgroup_name='IPv4_Rep_Group',entryID ='1',next_hop='1.1.1.2',next_hop_type='non-recursive')
    config_pbf_replication_group(dut1,repgroup_name='IPv4_Rep_Group',entryID =[1,2],next_hop=['1.1.1.2','2.2.2.1'],vrf_name='vrf-red',next_hop_type='recursive')
    config_pbf_replication_group(dut1,repgroup_name='IPv4_Rep_Group',entryID =[1,2],next_hop=['1.1.1.2','2.2.2.1'],vrf_name='vrf-red',next_hop_type='overlay ')
    config_pbf_replication_group(dut1,repgroup_name='IPv4_Rep_Group',entryID =[1,2],next_hop=['1.1.1.2','2.2.2.1'],vrf_name='vrf-red',next_hop_type='single-copy')
    config_pbf_replication_group(dut1,repgroup_name='IPv4_Rep_Group',entryID =[1,2],config='no')
    config_pbf_replication_group(dut1,repgroup_name='IPv4_Rep_Group',config='no')
    """
    repg_type = kwargs.pop('repg_type', 'ip')
    config = kwargs.pop('config', 'yes')
    skip_error = kwargs.pop('skip_error', False)


    cli_type = st.get_ui_type(dut,**kwargs)
    if cli_type in ['rest-patch', 'rest-put', 'click']: cli_type = 'klish'

    cmd =''
    if cli_type in get_supported_ui_type_list():
        fbs_obj = umf_fbs.Root()
        rgroup_type = 'REPLICATION_GROUP_TYPE_IPV4' if repg_type == 'ip' else 'REPLICATION_GROUP_TYPE_IPV6'
        repgroup_obj = umf_fbs.ReplicationGroup(Name=repgroup_name, Type=rgroup_type, Root=fbs_obj)
        if config.lower() == "yes":
            repgroup_obj.configure(dut, cli_type=cli_type)
            if 'entryID' in kwargs and 'next_hop' in kwargs:
                kwargs['entryID'] =make_list(kwargs['entryID'])
                kwargs['next_hop'] =make_list(kwargs['next_hop'])
                vrf_name = kwargs.pop('vrf_name', '')
                next_hop_type = kwargs.pop('next_hop_type', '')
                single_copy =None
                if next_hop_type == 'overlay':
                    nh_type = 'NEXT_HOP_TYPE_OVERLAY'
                elif next_hop_type == 'recursive':
                    nh_type = 'NEXT_HOP_TYPE_RECURSIVE'
                elif next_hop_type == 'non-recursive':
                    nh_type = 'NEXT_HOP_TYPE_NON_RECURSIVE'
                elif next_hop_type == 'single-copy':
                    single_copy = True
                    nh_type = None                  
                if vrf_name == '':
                    vrf_name = None
                if len(kwargs['entryID']) != len(kwargs['next_hop']):
                   st.error('Please check entryID list and next_hop list, number of entries should be same')
                   return False
                for id,nextHop_ip in zip(kwargs['entryID'],kwargs['next_hop']):
                    repGroupMember_obj = umf_fbs.ReplGroupMember(EntryId=id, Ip=nextHop_ip, Vrf=vrf_name,
                                    NhType=nh_type, SingleCopy=single_copy ,ReplicationGroup=repgroup_obj)              
                    result = repGroupMember_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Creation of Replication group entry {}'.format(result.data))
        
        if config.lower() == "no":
            if 'entryID' in kwargs:
                kwargs['entryID'] =make_list(kwargs['entryID'])             
                for id in kwargs['entryID']:
                    repGroupMember_obj = umf_fbs.ReplGroupMember(EntryId=id,ReplicationGroup=repgroup_obj) 
                    result = repGroupMember_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Deletion of Replication group entry {}'.format(result.data))
            else:
                result = repgroup_obj.unConfigure(dut, cli_type=cli_type)           
            if not result.ok():
                st.log('test_step_failed: Deletion of Replication group {}'.format(result.data))
                    
    elif cli_type == "klish":
        if config.lower() == "yes":
            cmd += "pbf replication-group {} type {}\n".format(repgroup_name,repg_type)
            if 'entryID' in kwargs and 'next_hop' in kwargs:
                kwargs['entryID'] =make_list(kwargs['entryID'])
                kwargs['next_hop'] =make_list(kwargs['next_hop'])
                vrf_name = kwargs.pop('vrf_name', '')
                next_hop_type = kwargs.pop('next_hop_type', '')
                if vrf_name !='':
                    vrf_name = 'vrf '+vrf_name
                if len(kwargs['entryID']) != len(kwargs['next_hop']):
                   st.error('Please check entryID list and next_hop list, number of entries should be same')
                   return False
                for id,nextHop_ip in zip(kwargs['entryID'],kwargs['next_hop']):
                    cmd += " entry {} next-hop {} {} {}\n".format(id,nextHop_ip,vrf_name,next_hop_type)
            cmd += "exit\n"
        elif config.lower() == "no":
            if 'entryID' in kwargs:
                kwargs['entryID'] =make_list(kwargs['entryID'])
                cmd += "pbf replication-group {} type {}\n".format(repgroup_name,repg_type)
                for id in kwargs['entryID']:
                    cmd += "no entry {} \n".format(id)

                cmd += "exit\n"
            else:
                cmd += "no pbf replication-group {}\n".format(repgroup_name)
        output =st.config(dut, cmd, skip_error_check=skip_error, type=cli_type)
        return output
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def show_pbf_replication_group(dut,repgroup_name, **kwargs):
    """
    Author: Raghukumar Rampur

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :param :repgroup_name: Name of next-hop-replication-group:
    :param :repg_type: Type - ip or ipv6:
    :return:
    """

    cli_type = st.get_ui_type(dut,**kwargs)
    if cli_type in ['rest-patch', 'rest-put','click']: cli_type = 'klish'
    skip_error = kwargs.get('skip_error', False)
    cmd_type = kwargs.get('repg_type', 'ip')
    if cmd_type != '':
        cmd_type = "type {}".format(cmd_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'klish':
        command = "show pbf replication-group {}".format(cmd_type)
        return st.show(dut, command, type=cli_type, skip_error_check=skip_error)
    else:
        st.error("Unsupported CLI_TYPE: {}.".format(cli_type))
    return False

def verify_pbf_replication_group(dut,repgroup_name, **kwargs):
    """
    Verify
    Author: Raghukumar Rampur

    :param :dut:
    :param :ip: ipv4 values (single or list)
    :param :ipv6: ipv6 values (single or list)
    :param :repgroup_name
    :param :repg_type
    :param :policy_name
    :param :policy_priority
    :param :nh_ip
    :param :entry
    :param :nh_vrf
    :param :desc_name
    :param :cli_type:
    :param :skip_error:
    :return:
    """
    return_key = True

    output = show_pbf_replication_group(dut,repgroup_name, **kwargs)
    st.log("output={}, kwargs={}".format(output,kwargs))
    for key in ['cli_type', 'skip_error']:
        kwargs.pop(key, None)

    str_params = ['repgroup_name', 'repg_type', 'desc_name','policy_name', 'policy_priority']
    # Length of all list params should be equal.
    list_params = ['nh_ip', 'entry', 'nh_type', 'nh_vrf']

    valid_str_dict = {}
    for key in str_params:
        if key in kwargs:
            valid_str_dict[key] = kwargs[key]
    if not filter_and_select(output, None, valid_str_dict):
        st.log("{} is not matching in the output:\n {}".format(valid_str_dict, output))
        return_key = False

    nh_list=''
    entry_list=''
    nht_list=''
    nhv_list=''
    if 'nh_ip' in kwargs:
        nh_list = kwargs['nh_ip']
        nh_list = [nh_list] if type(nh_list) is str else nh_list
        entry_list = kwargs.get('entry', ['']*len(nh_list))
        nht_list = kwargs.get('nh_type', ['']*len(nh_list))
        nhv_list = kwargs.get('nh_vrf', ['']*len(nh_list))
        entry_list = [entry_list] if type(entry_list) is str else entry_list
        nht_list = [nht_list] if type(nht_list) is str else nht_list
        nhv_list = [nhv_list] if type(nhv_list) is str else nhv_list
        valid_dict={}
        for nh, ent, nht, nhv in zip(nh_list, entry_list, nht_list, nhv_list):
            valid_dict = dict(zip(list_params,[nh, ent, nht, nhv]))
            for k, v in dict(valid_dict).items():
                if v == '':
                    del valid_dict[k]
        if not filter_and_select(output, None, valid_dict):
            st.log("{} is not matching in the output.".format(valid_dict))
            return_key = False

    return return_key

def show_pbf_replication_group_status(dut, **kwargs):
    """
    Author: Raghukumar Rampur

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :param :interface: Name of the interface
    :return:
    """

    cli_type = st.get_ui_type(dut,**kwargs)
    if cli_type in ['rest-patch', 'rest-put','click']: cli_type = 'klish'
    skip_error = kwargs.get('skip_error', False)
    if 'interface' not in kwargs:
        st.error("Mandatory parameter - interface name is missing")
        return False
    intf_name = kwargs.get('interface', '')
    pintf = get_interface_number_from_name(intf_name)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'klish':
        command = "show pbf replication-group status interface {} {}".format(pintf['type'], pintf['number'])
        return st.show(dut, command, type=cli_type, skip_error_check=skip_error)
    else:
        st.error("Unsupported CLI_TYPE: {}.".format(cli_type))
    return False


def verify_pbf_replication_group_status(dut, **kwargs):
    """
    Verify
    Author: Raghukumar Rampur

    :param :dut:
    :param :repgroup_name
    :param :repg_type
    :param :status
    :param :nh_ip
    :param :nh_type
    :param :nh_status
    :param :nh_vrf
    :param :entry
    :param :cli_type:
    :param :skip_error:
    :return:
    """
    return_key = True

    output = show_pbf_replication_group_status(dut, **kwargs)
    st.log("output={}, kwargs={}".format(output,kwargs))
    for key in ['cli_type', 'skip_error']:
        kwargs.pop(key, None)

    str_params = ['repgroup_name', 'repg_type', 'status']
    # Length of all list params should be equal.
    list_params = ['nh_ip', 'entry', 'nh_type', 'nh_vrf','nh_status']

    valid_str_dict = {}
    for key in str_params:
        if key in kwargs:
            valid_str_dict[key] = kwargs[key]
    if not filter_and_select(output, None, valid_str_dict):
        st.log("{} is not matching in the output:\n {}".format(valid_str_dict, output))
        return_key = False

    nh_list=''
    entry_list=''
    nht_list=''
    nhv_list=''
    nhs_list=''
    if 'nh_ip' in kwargs:
        nh_list = kwargs['nh_ip']
        nh_list = [nh_list] if type(nh_list) is str else nh_list
        entry_list=kwargs.get('entry', ['']*len(nh_list))
        nht_list=kwargs.get('nh_type', ['']*len(nh_list))
        nhv_list=kwargs.get('nh_vrf', ['']*len(nh_list))
        nhs_list=kwargs.get('nh_status', ['']*len(nh_list))

        entry_list = [entry_list] if type(entry_list) is str else entry_list
        nht_list = [nht_list] if type(nht_list) is str else nht_list
        nhv_list = [nhv_list] if type(nhv_list) is str else nhv_list
        nhs_list = [nhs_list] if type(nhs_list) is str else nhs_list
        valid_dict={}
        for nh, ent, nht, nhv, nhs in zip(nh_list, entry_list, nht_list, nhv_list,nhs_list):
            valid_dict = dict(zip(list_params,[nh, ent, nht, nhv, nhs]))
            for k, v in dict(valid_dict).items():
                if v == '':
                    del valid_dict[k]
        if not filter_and_select(output, None, valid_dict):
            st.log("{} is not matching in the output.".format(valid_dict))
            return_key = False

    return return_key
