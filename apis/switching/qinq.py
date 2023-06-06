# List of API's which performs Vlan Transalation and Vlan Stacking operations.
import re
from spytest import st

from utilities.utils import get_supported_ui_type_list, get_interface_number_from_name
import utilities.common as co_utils

try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    import apis.yang.codegen.messages.system as umf_sys
    from apis.yang.utils.common import Operation
except ImportError:
    pass

get_phy_port = lambda intf: re.search(r"(\S+)\.\d+", intf).group(1) if re.search(r"(\S+)\.\d+", intf) else intf

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type

def config_vlan_translation(dut,interface,s_vlan,**kwargs):
    '''
    :param dut:
    :param interface:
    :param s_vlan:
    :param c_vlan:
    :param inner_c_vlan:
    :param kwargs:
    :param c_vlan_op:
    :param prioirty:
    :return:

    Usage:
        config_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,inner_c_vlan=100,vlan_priority=1)
        config_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,inner_c_vlan=100) -- Double Tag
        config_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10 -- Single Tag
        config_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,config="no")
    '''
    st.log('API_NAME: config_vlan_translation, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)

    config = kwargs.get('config', 'yes').lower()
    outer_c_vlan = kwargs.get('outer_c_vlan', '')
    inner_c_vlan = kwargs.get('inner_c_vlan', '')
    #skip_error = kwargs.get('skip_error', False)
    priority = kwargs.get('vlan_priority', None)

    if cli_type in get_supported_ui_type_list()+['klish']:
        interface_name = get_phy_port(interface)
        intf_obj = umf_intf.Interface(Name=interface_name)
        map_vlan_obj = umf_intf.MappedVlan(VlanId=s_vlan,Interface=intf_obj)
        if config in ['yes','verify'] :
            gnmi_op = Operation.UPDATE
            if inner_c_vlan and outer_c_vlan:
                map_vlan_obj.OuterVlanId = outer_c_vlan
                map_vlan_obj.InnerVlanId = inner_c_vlan
            elif outer_c_vlan:
                map_vlan_obj.VlanIds = co_utils.make_list(outer_c_vlan)

            if priority:
                map_vlan_obj.IngressMappingMappedVlanPriority = priority
                map_vlan_obj.EgressMappingMappedVlanPriority = priority

            map_vlan_obj.IngressMappingVlanStackAction = 'SWAP'
            map_vlan_obj.EgressMappingVlanStackAction = 'SWAP'

            if config == 'verify':
                return map_vlan_obj

            result = map_vlan_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: {}: Config Vlan translation for s-vlan:{} result: {}'
                       .format(cli_type.upper(), s_vlan, result.data))
                return False
        elif config =='no':
            if priority:
                ### Unconfig only s-vlan prioirty
                map_vlan_obj.IngressMappingMappedVlanPriority = priority
                result = map_vlan_obj.unConfigure(dut, target_attr=map_vlan_obj.IngressMappingMappedVlanPriority,
                                                  cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed:  UnConfig of ingress s_vlan prioirty: {}'.format(result.data))
                    return False

                map_vlan_obj.EgressMappingMappedVlanPriority = priority
                result = map_vlan_obj.unConfigure(dut, target_attr=map_vlan_obj.EgressMappingMappedVlanPriority,
                                                  cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed:  UnConfig of egresss s_vlan prioirty: {}'.format(result.data))
                    return False
            else:
                result = map_vlan_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: {}: UnConfig of vlan translation for s-vlan:{} result: {}'
                           .format(cli_type.upper(), s_vlan, result.data))
                    return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return True


def config_vlan_stacking(dut,interface,s_vlan,**kwargs):
    '''
    :param dut:
    :param interface:
    :param s_vlan:
    :param c_vlan_list:
    :param kwargs:
    :param c_vlan_op:
    :param prioirty:
    :return:

    Usage:
        config_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,c_vlan_list=[10,20,30],vlan_priority=1)
        config_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1040,c_vlan_list=[40,50])
        config_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,vlan_priority=2) -- config s-vlan prioirty alone
        config_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,vlan_priority=2,config="no") -- unconfig s-vlan prioirty alone
        config_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,config="no")
    '''
    st.log('API_NAME: config_vlan_stacking, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)

    config = kwargs.get('config', 'yes').lower()
    #skip_error = kwargs.get('skip_error', False)
    c_vlan_list = kwargs.get('c_vlan_list', None)
    add_c_vlans = kwargs.get('add_c_vlans', None)
    rem_c_vlans = kwargs.get('rem_c_vlans', None)
    priority = kwargs.get('vlan_priority', None)

    if cli_type in get_supported_ui_type_list() + ['klish']:
        interface_name = get_phy_port(interface)
        intf_obj = umf_intf.Interface(Name=interface_name)
        map_vlan_obj = umf_intf.MappedVlan(VlanId=s_vlan, Interface=intf_obj)
        if config in ['yes','verify'] :
            gnmi_op = Operation.UPDATE
            if c_vlan_list:
                map_vlan_obj.VlanIds = co_utils.make_list(c_vlan_list)
            elif add_c_vlans:
                ### add-rem case handling -- klish only option
                add_c_vlans = co_utils.make_list(add_c_vlans)
                add_c_vlans = ','.join(str(e) for e in add_c_vlans)
                intf = get_interface_number_from_name(interface)
                command = "interface {} {}".format(intf['type'], intf['number'])
                cmd = [command]
                cmd.append("switchport vlan-mapping add {} dot1q-tunnel {}".format(add_c_vlans,s_vlan))
                cmd.append("exit")
                return st.config(dut, cmd, type="klish", conf=True)
            elif rem_c_vlans:
                ### add-rem case handling -- klish only option
                rem_c_vlans = co_utils.make_list(rem_c_vlans)
                rem_c_vlans = ','.join(str(e) for e in rem_c_vlans)
                intf = get_interface_number_from_name(interface)
                command = "interface {} {}".format(intf['type'], intf['number'])
                cmd = [command]
                cmd.append("switchport vlan-mapping remove {} dot1q-tunnel {}".format(rem_c_vlans,s_vlan))
                cmd.append("exit")
                return st.config(dut, cmd, type="klish", conf=True)
            if priority:
                map_vlan_obj.IngressMappingMappedVlanPriority = priority
                map_vlan_obj.EgressMappingMappedVlanPriority = priority

            map_vlan_obj.IngressMappingVlanStackAction = 'PUSH'
            map_vlan_obj.EgressMappingVlanStackAction = 'POP'
            if config == 'verify':
                return map_vlan_obj

            result = map_vlan_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: {}: Config Vlan stacking for s-vlan:{} result: {}'
                       .format(cli_type.upper(), s_vlan, result.data))
                return False
        elif config == 'no':
            if priority:
                ### Unconfig only s-vlan prioirty
                map_vlan_obj.IngressMappingMappedVlanPriority = priority
                result = map_vlan_obj.unConfigure(dut, target_attr=map_vlan_obj.IngressMappingMappedVlanPriority, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed:  UnConfig of ingress s_vlan prioirty: {}'.format(result.data))
                    return False

                map_vlan_obj.EgressMappingMappedVlanPriority = priority
                result = map_vlan_obj.unConfigure(dut, target_attr=map_vlan_obj.EgressMappingMappedVlanPriority,
                                                  cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed:  UnConfig of egresss s_vlan prioirty: {}'.format(result.data))
                    return False
            else:
                result = map_vlan_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: {}: UnConfig of vlan stacking for s-vlan:{} result: {}'
                           .format(cli_type.upper(), s_vlan, result.data))
                    return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return True

def enable_qinq(dut,**kwargs):
    '''
    To enable Vlan stacking and transalation in TD4 platforms
    :param dut:
    :param kwargs:
    :return:

    USAGE:
        enable_qinq(data.dut1)
        enable_qinq(data.dut1,config='no')
    '''
    st.log('API_NAME: enable_qinq, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    #cli_type = 'gnmi'
    config = kwargs.get('config', 'yes').lower()

    if cli_type in get_supported_ui_type_list() + ['klish']:
        sys_obj = umf_sys.System()
        sw_resource_obj = umf_sys.Resource(Name='VLAN_STACKING', System=sys_obj)
        if config in ['yes']:
            #gnmi_op = Operation.UPDATE
            gnmi_op = Operation.CREATE
            ### TD4 uat mode value
            #sw_resource_obj.VlanStacking= 0
            sw_resource_obj.VlanStacking = 'ENABLED'
            result = sw_resource_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: {}: Enable vlan-stacking, result: {}'
                       .format(cli_type.upper(), result.data))
                return False
        elif config == 'no':
            #sw_resource_obj.VlanStacking = 1
            sw_resource_obj.VlanStacking = 'DISABLED'
            result = sw_resource_obj.unConfigure(dut, target_attr=sw_resource_obj.VlanStacking,
                                                  cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed:{}  Disable vlan-stacking: {}'.format(cli_type.upper(), result.data))
                return False

    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return True

def verify_qinq_enable(dut,qinq_conf_state='enabled',qinq_oper_state='enabled',**kwargs):
    '''
    :param dut:
    :param qinq_conf_state:
    :param qinq_oper_state:
    :param kwargs:
    :return:

    USAGE:
        qinq_api.verify_qinq_enable(data.dut1,qinq_conf_state='disabled',qinq_oper_state='disabled')
        qinq_api.verify_qinq_enable(data.dut1,qinq_conf_state='disabled',qinq_oper_state='enabled')
        qinq_api.verify_qinq_enable(data.dut1,qinq_conf_state='enabled',qinq_oper_state='disabled')
        qinq_api.verify_qinq_enable(data.dut1,qinq_conf_state='enabled',qinq_oper_state='enabled')
    '''
    st.log('API_NAME: verify_qinq_enable, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    ### Forcing to gnmi due to JIRA: 70421
    cli_type = force_cli_type_to_klish(cli_type)

    if cli_type in get_supported_ui_type_list():
        sys_obj = umf_sys.System()
        sw_resource_obj = umf_sys.Resource(Name='VLAN_STACKING', System=sys_obj)
        if qinq_conf_state == 'enabled' and qinq_oper_state == 'enabled':
            sw_resource_obj.VlanStacking = 'ENABLED'
            filter_type = kwargs.get('filter_type', 'ALL')
        elif qinq_conf_state == 'enabled' and qinq_oper_state == 'disabled':
            sw_resource_obj.VlanStacking = 'ENABLED'
            filter_type = kwargs.get('filter_type', 'CONFIG')
        elif qinq_conf_state == 'disabled' and qinq_oper_state == 'disabled':
            #sw_resource_obj.VlanStacking=0
            filter_type = kwargs.get('filter_type', 'CONFIG')
        elif qinq_conf_state == 'disabled' and qinq_oper_state == 'enabled':
            sw_resource_obj.VlanStacking = 'ENABLED'
            filter_type = kwargs.get('filter_type', 'NON_CONFIG')
        query_params_obj = co_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        #sw_resource_obj = enable_qinq(dut, config='verify', **kwargs)
        result = sw_resource_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: {}: Match NOT Found: qinq Enable state:{}, result:{}'
                   .format(cli_type.upper(), sw_resource_obj.VlanStacking, result.data))
            return False
    elif cli_type == 'klish':
        ret_val = True
        command = "show switch-resource vlan-stacking"
        output = st.show(dut, command, type=cli_type)

        if 'return_output' in kwargs:
            return output
        if not output:
            st.log("Output is empty")
            return False

        for key in ['qinq_conf_state','qinq_oper_state']:
            if key == 'qinq_conf_state':
                expect_val = qinq_conf_state
            elif key == 'qinq_oper_state':
                expect_val = qinq_oper_state
            if str(expect_val) != str(output[0][key]):
                st.error(
                    "Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(str(key), expect_val, output[0][key]))
                ret_val = False
            else:
                st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(str(key), expect_val, output[0][key]))
        return ret_val
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return True

def verify_vlan_mappings(dut,interface,s_vlan,outer_c_vlan,inner_c_vlan='',**kwargs):
    st.log('API_NAME: verify_vlan_mappings, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type in get_supported_ui_type_list() + ['klish']:
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = co_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        map_vlan_obj = config_vlan_translation(dut,interface,s_vlan,outer_c_vlan=outer_c_vlan,inner_c_vlan=inner_c_vlan, config='verify', **kwargs)
        result = map_vlan_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: {}: Match NOT Found: vlan mappings for s-vlan:{} under interface:{}, result:{}'
                   .format(cli_type.upper(), s_vlan, interface, result.data))
            return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return True


def verify_dot1q_tunnels(dut,interface,s_vlan,c_vlan_list='',**kwargs):
    st.log('API_NAME: verify_dot1q_tunnels, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type in get_supported_ui_type_list() + ['klish']:
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = co_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        map_vlan_obj= config_vlan_stacking(dut,interface,s_vlan,c_vlan_list=c_vlan_list,config='verify',**kwargs)
        result = map_vlan_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: {}: Match NOT Found: dot1q tunnels for s-vlan:{} under interface:{}, result:{}'
                    .format(cli_type.upper(), s_vlan, interface, result.data))
            return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return True


def verify_all_vlan_mappings(dut,**kwargs):
    st.log('API_NAME: verify_all_vlan_mappings, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)

    s_vlan_dict_list = kwargs.get('s_vlan_dict_list', [])

    command= "show interface vlan-mappings"
    output = st.show(dut, command, type=cli_type)

    if 'return_output' in kwargs:
        return output
    if not output:
        st.log("Output is empty")
        return False

    for s_v_dict in s_vlan_dict_list:
        #entries = filter_and_select(output, None, {"interface": s_v_dict['interface'],
        #                                           "s_vlan": s_v_dict['s_vlan']})
        entries = co_utils.filter_and_select(output, None, s_v_dict)
        if not entries:
            st.log("Match NOT FOUND: s_vlan_dict:{} not found under interface:{}".format(s_v_dict,
                                                                                    s_v_dict['interface']))
            return False

    return True



def verify_all_dot1q_tunnels(dut, **kwargs):
    st.log('API_NAME: verify_all_dot1q_tunnels, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)

    s_vlan_dict_list = kwargs.get('s_vlan_dict_list', [])

    command = "show interface vlan-mappings dot1q-tunnel"
    output = st.show(dut, command, type=cli_type)

    if 'return_output' in kwargs:
        return output
    if not output:
        st.log("Output is empty")
        return False

    for s_v_dict in s_vlan_dict_list:
        # entries = filter_and_select(output, None, {"interface": s_v_dict['interface'],
        #                                           "s_vlan": s_v_dict['s_vlan']})
        entries = co_utils.filter_and_select(output, None, s_v_dict)
        if not entries:
            st.log("Match NOT FOUND: s_vlan_dict:{} not found under interface:{}".format(s_v_dict,
                                                                                         s_v_dict['interface']))
            return False

    return True