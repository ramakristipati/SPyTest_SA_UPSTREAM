import re

from spytest import st
import utilities.inet as tol
import apis.qos.acl as acl_obj
import utilities.common as utils

try:
    import apis.yang.codegen.messages.acl as umf_acl
except ImportError:
    pass

def create_ACLtable_scale(dut, **kwargs):
    """
    Author:
	create_ACLtable_scale(dut=dut1,max_acl=1,aclName='ACL',direction ='INGRESS', acl_type='L3')
    """
    result = True
    max_acl = kwargs.get('max_acl', 1)
    aclName = kwargs.get('aclName', None)

    if aclName is None:
        st.log('Mandatory parameter aclName is not found')
        return False

    direction = kwargs.get('direction', 'INGRESS')
    acl_type = kwargs.get('acl_type', 'L3')

    st.log('creating  ACL tables ')
    for i in range(max_acl):
        result =acl_obj.create_acl_table(dut=dut, name=aclName+str(i), stage=direction, type=acl_type, description="Testing acl scale")
    return result

def delete_ACLtable_scale(dut, **kwargs):
    """
    Author:
    delete_ACLtable_scale(dut=dut1,max_acl=10,acl_name='ACL')

    :return:
    """
    max_acl = kwargs.get('max_acl', 1)
    acl_name = kwargs.get('acl_name', None)

    if acl_name is None:
        st.log('Mandatory parameter aclName is not found')
        return False

    st.log('Deleting  ACL tables ')
    for i in range(max_acl):
        acl_obj.delete_acl_table(dut=dut, acl_table_name=acl_name+str(i))
    return True

def delete_ACLrule_scale(dut, **kwargs):
    """
    Author:
    delete_ACLrule_scale(dut=dut1,acl_name='ACL01',rule_name='test', max_rule=10)

    :return:
    """
    max_rule = kwargs.get('max_rule', 1)
    rule_name = kwargs.get('rule_name', None)
    acl_name = kwargs.get('acl_name', None)

    if acl_name is None:
        st.log('Mandatory parameter aclName is not found')
        return False

    st.log('Dleteing ACL rules under given acl table ')
    for i in range(max_rule):
        acl_obj.delete_acl_rule(dut=dut, acl_table_name=acl_name, acl_rule_name =rule_name+'_'+str(i))
    return True

def create_aclrule_scale(**kwargs):
    #import pdb;pdb.set_trace()
    mnd_params=['dut','acl_name' ]
    for param in mnd_params:
        if param not in kwargs:
            st.log('Mandatory parameter {} is not found'.format(param))
            return False

    input_params=['src_ip', 'src_ip_incr', 'src_ip_mask', 'dst_ip', 'dst_ip_incr', 'dst_ip_mask', 'src_ipv6','src_ipv6_incr', 'src_ipv6_mask', 'dst_ipv6', 'dst_ipv6_incr', 'dst_ipv6_mask', 'src_port', 'src_port_incr', 'dst_port', 'dst_port_incr', 'rule_name', 'action', 'priority', 'priority_incr', 'ip_type', 'ip_protocol', 'tcp_flags', 'dscp', 'mirror_action', 'ether_type', 'dut', 'acl_name', 'acl_name_incr', 'count']
    def_list=['','','24','','','24','','','64','','','64','','','','','1','forward','1', '', '', '', '', '', '', '', '', '', '', '1']
    list_params=list(map(input_params.__getitem__,[0,3,6,9,12,14,16,17,18,19,20,22,23,24,25,27]))
    d={}
    for i,param in enumerate(input_params):
        d[param] = kwargs.get(param,def_list[i])

    d['count'] = int(d['count'])

    # To conver the values to list if user has not provided.
    for param in list_params:
        if param in kwargs:
            d[param]= list(kwargs[param]) if type(kwargs[param]) is list else [kwargs[param]]
        else:
            d[param]= [d[param]]

    if d['count'] != 1:
        for param in list_params:
            if len(d[param]) != d['count']:
                if param != 'rule_name':
                    if param+'_incr' in kwargs:
                        if param == 'src_ip' or param == 'dst_ip':
                            d[param]=tol.range_ipv4(d[param][0], d['count'], d[param+'_mask'])
                        if param == 'src_ipv6' or param == 'dst_ipv6':
                            d[param]=tol.range_ipv6(d[param][0], d['count'], d[param+'_mask'])
                        if param == 'src_port' or param == 'dst_port' or param == 'priority':
                            d[param]=range(int(d[param][0]), d['count']+int(d[param][0]))
                        if param == 'acl_name':
                            d[param]=[str(d[param][0])+str(x) for x in range(d['count'])]
                    else:
                        d[param] = d[param]*d['count']
                else:
                    d['rule_name']=[str(d[param][0])+'_'+str(x) for x in range(d['count'])]
    key_params=['SRC_IP', 'DST_IP', 'SRC_IPV6', 'DST_IPV6', 'rule_name',  'packet_action', 'priority', 'ip_type', 'ip_protocol', 'tcp_flags', 'dscp', 'mirror_action', 'ether_type', 'table_name']
    spl_key_params=['l4_src_port', 'l4_dst_port', 'l4_src_port_range', 'l4_dst_port_range']
    # 1:1 mapping with key_params that of input_params indexes.
    value_params=list(map(input_params.__getitem__,[0,3,6,9,16,17,18,19,20,22,23,24,25,27]))
    spl_value_params=map(input_params.__getitem__,[12,14])

    values=[d[x] for x in value_params]
    spl_values=[d[x] for x in spl_value_params]
    for line, s_line in zip(zip(*values), zip(*spl_values)):
        dict_param={'dut':d['dut']}
        for i,val in enumerate(line):
            if val != '':
                dict_param[key_params[i]] = val
        for i,val in enumerate(s_line):
            if val != '':
                j=2 if re.search('-',val) else 0
                dict_param[spl_key_params[i+j]] = val
        acl_obj.create_acl_rule(**dict_param)

    return True


def create_acl(dut, acl_dict, gnmi_op, **kwargs):
    cli_type = st.get_ui_type(dut,**kwargs)
    acl_obj = umf_acl.Root()
    acl_table_obj = umf_acl.Acl(Name=acl_dict[dut]['Name'], Type=acl_dict[dut]['Type'])
    acl_obj.add_Acl(acl_table_obj)
    result = acl_obj.configure(dut, cli_type=cli_type)
    if not result.ok():
        st.log('test_step_failed: Operation:{} of Acl {}'.format(gnmi_op, result.data))
        return False
    else:
        st.log('test_step_pass: Operation:{} of Acl {}'.format(gnmi_op, result.data))
        return True

def acl_rule_change(dut, acl_dict, aclrule_dict, gnmi_op, **kwargs):
    cli_type = st.get_ui_type(dut,**kwargs)
    ### Create Acl Object
    acl_table_obj = umf_acl.Acl(Name=acl_dict[dut]['Name'], Type=acl_dict[dut]['Type'])
    ### Create Acl Rule Object
    rule_obj = umf_acl.AclRule(SeqNum=int(aclrule_dict[dut]['SeqNum']), Acl=acl_table_obj)
    for k, v in aclrule_dict[dut].items():
        setattr(rule_obj, k, v)
    result = rule_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
    if not result.ok():
        st.log('test_step_failed: Operation:{} of Acl Rule {}'.format(gnmi_op, result.data))
        return False
    else:
        st.log('test_step_pass: Operation:{} of Acl Rule {}'.format(gnmi_op, result.data))
        return True

def acl_rule_verify(dut, acl_dict, aclrule_dict, **kwargs):
    cli_type = st.get_ui_type(dut,**kwargs)
    query_params_obj = utils.get_query_params(yang_data_type='ALL', cli_type=cli_type)
    ### Create Acl Object
    acl_table_obj = umf_acl.Acl(Name=acl_dict[dut]['Name'], Type=acl_dict[dut]['Type'])
    ### Create Acl Rule Object
    rule_obj = umf_acl.AclRule(SeqNum=int(aclrule_dict[dut]['SeqNum']), Acl=acl_table_obj)
    for k, v in aclrule_dict[dut].items():
        setattr(rule_obj, k, v)
    result = acl_table_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
    if not result.ok():
        st.log('test_step_failed: Acl Rule:Updated Values not reflected')
        return False
    else:
        st.log('test_step_pass: Acl Rule:Updated Values reflected')
        return True