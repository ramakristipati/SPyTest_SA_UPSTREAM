from utilities.common import filter_and_select
from spytest import st
from utilities.utils import get_interface_number_from_name, get_supported_ui_type_list
from utilities.common import make_list
from apis.system.rest import delete_rest, config_rest, get_rest

try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    import apis.yang.codegen.messages.network_instance as umf_ni
    from apis.yang.utils.common import Operation
except ImportError:
    pass

def config_igmp(dut, **kwargs):
    """
    config_igmp(dut=data.dut1,intf ='Ethernet10',igmp_enable='yes',join='yes',group='225.1.1.1',source='10.10.10.2',version='2',
                query_interval=10,query_max_response='34',oil_prefix='prefix1',config='yes', cli_type='vtysh')

    Configure interface with pim configurations
    :param dut:
    :param intf:
    :param igmp_enable:
    :param join:
    :param verson:
    :param query_interval:
    :param query_max_response:
    :param cli type
    :return:
    """

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    cli_type=st.get_ui_type(dut, **kwargs)
    if 'intf' in kwargs:
        if type(kwargs['intf']) is list:
            kwargs['intf'] = list(kwargs['intf'])
        else:
            kwargs['intf'] = [kwargs['intf']]
    if cli_type in get_supported_ui_type_list():
        for ifname in make_list(kwargs['intf']):
            intf_obj = umf_intf.Interface(Name=ifname)
            igmp_intf_obj = umf_intf.Subinterface(Index=0, Interface=intf_obj)
            if config in ['yes', 'verify']:
                if 'igmp_enable' in kwargs:
                    igmp_intf_obj.IgmpEnabled = True
                if 'query_max_response' in kwargs:
                    igmp_intf_obj.QueryMaxResponseTime = float(kwargs['query_max_response'])
                if 'query_interval' in kwargs:
                    igmp_intf_obj.QueryInterval = float(kwargs['query_interval'])
                if 'version' in kwargs:
                    igmp_intf_obj.Version = int(kwargs['version'])
                if config == 'verify': return igmp_intf_obj
                result = igmp_intf_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.error("test_step_failed: Failed to config IGMP Config : {}".format(result.data))
                    return False
                if 'join' in kwargs:
                    operation = Operation.CREATE
                    for src in make_list(kwargs['source']):
                        igmp_join_obj = umf_intf.Join(Mcastgrpaddr=kwargs['group'], Srcaddr=src, Subinterface=igmp_intf_obj)
                        result = igmp_join_obj.configure(dut, operation=operation, cli_type=cli_type)
                        if not result.ok():
                            st.error("test_step_failed: Failed to config IGMP Config : {}".format(result.data))
                            return False
            else:
                if 'igmp_enable' in kwargs:
                    igmp_intf_obj.IgmpEnabled = False
                    result = igmp_intf_obj.unConfigure(dut, target_path='ipv4/igmp/config')
                    if not result.ok():
                        st.log('test_step_failed: Failed for IGMP Intf lvl Config {}'.format(result.data))
                        return False
                if 'version' in kwargs:
                    result = igmp_intf_obj.unConfigure(dut, target_attr=igmp_intf_obj.Version)
                    if not result.ok():
                        st.log('test_step_failed: Failed for IGMP Intf lvl Config {}'.format(result.data))
                        return False
                if 'query_interval' in kwargs:
                    result = igmp_intf_obj.unConfigure(dut, target_attr=igmp_intf_obj.QueryInterval)
                    if not result.ok():
                        st.log('test_step_failed: Failed for IGMP Intf lvl Config {}'.format(result.data))
                        return False
                if 'query_max_response' in kwargs:
                    result = igmp_intf_obj.unConfigure(dut, target_attr=igmp_intf_obj.QueryMaxResponseTime)
                    if not result.ok():
                        st.log('test_step_failed: Failed for IGMP Intf lvl Config {}'.format(result.data))
                        return False
                if 'join' in kwargs:
                    for src in make_list(kwargs['source']):
                        igmp_join_obj = umf_intf.Join(Mcastgrpaddr=kwargs['group'], Srcaddr=src, Subinterface=igmp_intf_obj)
                        result = igmp_join_obj.unConfigure(dut)
                        if not result.ok():
                            st.error("test_step_failed: Failed to Delete IGMP Config : {}".format(result.data))
                            return False
        return True
    if cli_type == 'click':
        cli_type = 'vtysh'
        my_cmd = ''
        for intf in kwargs['intf']:
            my_cmd += 'interface {}\n'.format(intf)

            if config_cmd != 'no':
                if 'igmp_enable' in kwargs:
                    my_cmd += 'ip igmp \n'

            if 'version' in kwargs:
                my_cmd += '{} ip igmp version {} \n'.format(config_cmd, kwargs['version'])

            if 'query_max_response' in kwargs:
                if config_cmd == 'no': kwargs['query_max_response'] = ''
                my_cmd += '{} ip igmp query-max-response-time {} \n'.format(config_cmd, kwargs['query_max_response'])

            if 'query_interval' in kwargs:
                if config_cmd == 'no': kwargs['query_interval'] = ''
                my_cmd += '{} ip igmp query-interval {} \n'.format(config_cmd, kwargs['query_interval'])

            if 'last_member_query_interval' in kwargs:
                if config_cmd == 'no': kwargs['last_member_query_interval'] = ''
                my_cmd += '{} ip igmp last-member-query-interval {} \n'.format(config_cmd,
                                                                               kwargs['last_member_query_interval'])

            if 'last_member_query_count' in kwargs:
                if config_cmd == 'no': kwargs['last_member_query_count'] = ''
                my_cmd += '{} ip igmp last-member-query-count {} \n'.format(config_cmd,
                                                                            kwargs['last_member_query_count'])

            if 'join' in kwargs:
                if type(kwargs['source']) is list:
                    for source in kwargs['source']:
                        my_cmd += '{} ip igmp join {} {}\n'.format(config_cmd, kwargs['group'], source)
                else:
                    my_cmd += '{} ip igmp join {} {}\n'.format(config_cmd, kwargs['group'], kwargs['source'])

            if config_cmd == 'no':
                if 'igmp_enable' in kwargs:
                    my_cmd += 'no ip igmp \n'
            # my_cmd += 'exit\n'
        if my_cmd:
            st.config(dut, my_cmd, type=cli_type)
            return True
    elif cli_type == 'klish':
        my_cmd = list()
        for intf in kwargs['intf']:
            intf_data = get_interface_number_from_name(intf)
            my_cmd.append("interface {} {}".format(intf_data['type'], intf_data['number']))
            if 'igmp_enable' in kwargs:
                my_cmd.append('{} ip igmp'.format(config_cmd))

            if 'query_max_response' in kwargs:
                if config == 'yes':
                    my_cmd.append('ip igmp query-max-response-time {}'.format(kwargs['query_max_response']))
                else:
                    my_cmd.append('no ip igmp query-max-response-time')

            if 'query_interval' in kwargs:
                if config == 'yes':
                    my_cmd.append('ip igmp query-interval {}'.format(kwargs['query_interval']))
                else:
                    my_cmd.append('no ip igmp query-interval')

            if 'join' in kwargs:
                if type(kwargs['source']) is list:
                    for source in kwargs['source']:
                        my_cmd.append('{} ip igmp join {} {}'.format(config_cmd, kwargs['group'], source))
                else:
                    my_cmd.append('{} ip igmp join {} {}'.format(config_cmd, kwargs['group'], kwargs['source']))

            if 'version' in kwargs:
                if config == 'yes':
                    my_cmd.append('ip igmp version {}'.format(kwargs['version']))
                else:
                    my_cmd.append('no ip igmp version')
            my_cmd.append('exit')
        if my_cmd:
            st.config(dut, my_cmd, type=cli_type)
            return True

    elif cli_type in ['rest-patch', 'rest-put']:
        for ifname in make_list(kwargs['intf']):
            rest_urls = st.get_datastore(dut, 'rest_urls')
            if config == 'yes':
                temp = dict()
                url = rest_urls['igmp'].format(name=ifname, index=0)
                if 'igmp_enable' in kwargs:
                    temp.update(enabled=True)
                if 'query_max_response' in kwargs:
                    temp.update({"query-max-response-time": float(kwargs['query_max_response'])})
                if 'query_interval' in kwargs:
                    temp.update({"query-interval": float(kwargs['query_interval'])})
                if 'version' in kwargs:
                    temp.update({"version": int(kwargs['version'])})
                if temp:
                    config_data = {"openconfig-igmp-ext:config": temp}
                    if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                        return False
                if 'join' in kwargs:
                    for src in make_list(kwargs['source']):
                        url = rest_urls["igmp_join"].format(ifname=ifname, index=0)
                        config_data = {"openconfig-igmp-ext:joins": {"join": [{"srcaddr": src, "config": {"srcaddr": src, "mcastgrpaddr": kwargs['group']}, "mcastgrpaddr": kwargs['group']}]}}
                        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                            return False

            else:
                rest_urls = st.get_datastore(dut, 'rest_urls')
                if 'igmp_enable' in kwargs:
                    url = rest_urls["igmp_disable"].format(name=ifname, index=0)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to Disable IGMP Configuration")
                        return False
                if 'version' in kwargs:
                    url = rest_urls["igmp_version"].format(ifname=ifname, index=0)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to Disable Version Configuration")
                        return False
                if 'query_interval' in kwargs:
                    url = rest_urls["query_interval"].format(ifname=ifname, index=0)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to Disable Query IntervalConfiguration")
                        return False
                if 'query_max_response' in kwargs:
                    url = rest_urls["query_max_resp"].format(ifname=ifname, index=0)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to Disable Query Max Response Configuration")
                        return False
                if 'join' in kwargs:
                    for src in make_list(kwargs['source']):
                        url = rest_urls['delete_join'].format(ifname=ifname, index=0, mcastgrpaddr=kwargs['group'], srcaddr=src)
                        if not delete_rest(dut, rest_url=url):
                            st.error("Failed to Cleanup IGMP Configuration")
                            return False
        return True

def verify_ip_igmp(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut
    :type string
    :param vrf
    :type string
    :param cmd_type
    :type string (CLI type)
    :param cli_type
    :type string


    :API type: "show ip igmp groups"
    :arg_list: 'interface', 'address', 'group', 'mode', 'timer', 'source_count', 'version', 'uptime'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='groups',interface='Ethernet45',address='10.1.1.1',mode='INCL',group='225.1.1.1',version='2')


    :API type: "show ip igmp sources"
    :arg_list:  'interface', 'address', 'source', 'group', 'timer', 'fwd', 'uptime'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='sources',interface='Ethernet45',address='10.1.1.1',source='20.1.1.1',group='225.1.1.1',vrf='RED')

    :API type: "show ip igmp groups retransmissions"
    :arg_list: 'interface', 'address', 'group', 'ret_timer', 'counter', 'ret_sources'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='groups retransmissions',interface='Ethernet45',address='10.1.1.1',counter='0',group='225.1.1.1',ret_sources='3')


    :API type: "show ip igmp sources retransmissions"
    :arg_list: 'interface', 'address', 'group', 'source', 'counter'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='sources retransmissions',interface='Ethernet45',address='10.1.1.1',source='20.1.1.2',group='225.1.1.1',counter=10)

    :API type: "show ip igmp join"
    :arg_list: 'interface', 'address', 'source', 'group', 'socket', 'uptime'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='join',interface='Ethernet45',address='10.1.1.1',source='20.1.1.2',group='225.1.1.1')

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    kwargs.pop('cli_type', None)
    ret_val = True
    cmd = ''
    if 'cmd_type' in kwargs:
        cmd_type = kwargs['cmd_type']
        del kwargs['cmd_type']
    else:
        cmd_type = 'groups'

    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False

    if cli_type in ['rest-patch', 'rest-put'] and vrf_name == 'all':
        cli_type = 'klish'

    if cli_type in ['click', 'klish']:
        if vrf_name != 'default':
            cmd = 'show ip igmp vrf {} {}'.format(vrf_name, cmd_type)
        else:
            cmd = "show ip igmp {}".format(cmd_type)

    elif cli_type in ['rest-patch', 'rest-put']:
        vrf_command = 'default' if vrf_name == 'default' else '{}'.format(vrf_name)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if cmd_type == 'sources':
            url = rest_urls['igmp_source'].format(name=vrf_command, identifier='IGMP', name1='igmp')
            res = get_rest(dut, http_method=cli_type, rest_url=url)
            if res:
                if 'return_output' in kwargs:
                    output = res['output']
                else:
                    if len(res['output']) == 0:
                        st.error("DUT Failed to display the Output")
                        return False
                    else:
                        output = parse_igmp_output(res['output'], type='source')
        elif cmd_type == 'groups':
            url = rest_urls['igmp_group'].format(name=vrf_command, identifier='IGMP', name1='igmp')
            res = get_rest(dut, http_method=cli_type, rest_url=url)
            if res:
                if 'return_output' in kwargs:
                    output = res['output']
                else:
                    if len(res['output']) == 0:
                        st.error("DUT Failed to display the Output")
                        return False
                    else:
                        output = parse_igmp_output(res['output'], type='group')
    if cli_type == 'click':
        cli_type = 'vtysh'

    if cli_type in ['vtysh', 'klish']:
        output = st.show(dut, cmd, type=cli_type, skip_error_check=skip_error)

    if 'return_output' in kwargs:
        return output

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'entry' in kwargs:
        entry_list = kwargs['entry']
        del kwargs['entry']
    else:
        entry_list = [True]*len(kwargs['group'])
    #Converting all kwargs to list type to handle single or list of mroute instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    if cli_type in ['klish', 'rest-patch', 'rest-put']:
        if 'mode' in list(kwargs.keys()):
            for i in range(len(kwargs['mode'])):
                if kwargs['mode'][i]  == 'INCL': kwargs['mode'][i] = 'INCLUDE'
                if kwargs['mode'][i]  == 'EXCL': kwargs['mode'][i] = 'EXCLUDE'
    for i in range(len(kwargs[list(kwargs.keys())[0]])):
        temp_dict = {}
        for key in list(kwargs.keys()):
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict, entry in zip(input_dict_list, entry_list):
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            if entry is False:
                st.error("DUT {} -> Match Found {} which is not expected".format(dut,input_dict))
                ret_val = False
        else:
            if entry is False:
                st.log("DUT {} -> Match Not Found {} as expected".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val


def verify_igmp_stats(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param interface
    :type string
    :param query_v1
    :type string
    :param query_v2
    :type string
    :param query_v3
    :type string
    :param leave_v2
    :type string
    :param report_v1
    :type string
    :param report_v2
    :type string
    :param report_v3
    :type string
    :param mtrace_response
    :type string
    :param mtrace_request
    :type string
    :param unsupported
    :type string
    :param vrf
    :type string
    :param cli_type
    :type string
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    kwargs.pop('cli_type', None)
    ret_val = True
    cmd = ''
    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
    else:
        vrf_name = 'default'

    skip_error = kwargs.pop('skip_error', False)
    skip_tmpl = kwargs.pop('skip_tmpl',False)

    if cli_type in ['click', 'klish']:
        if vrf_name != 'default':
            cmd = 'show ip igmp vrf {} statistics '.format(vrf_name)
        else:
            cmd = 'show ip igmp statistics '

        if 'interface' in kwargs:
            cmd += 'interface {}'.format(kwargs['interface'])

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if 'interface' in kwargs:
            url = rest_urls['igmp_counters'].format(name=vrf_name, identifier='IGMP', name1='igmp', ifname=kwargs['interface'])
            res = get_rest(dut, rest_url=url)
            if res:
                if len(res['output']) == 0:
                    st.error("DUT Failed to display the Output")
                    return False
                else:
                    output = parse_igmp_output(res['output'], type='counters')
        else:
            url = rest_urls['igmp_counters_stats'].format(name=vrf_name, identifier='IGMP', name1='igmp')
            res = get_rest(dut, rest_url=url)
            if res:
                if len(res['output']) == 0:
                    st.error("DUT Failed to display the Output")
                    return False
                else:
                    output = parse_igmp_output(res['output'], type='statistics')

    if cli_type == 'click':
        cli_type = 'vtysh'

    if cli_type in ['vtysh', 'klish']:
        output = st.show(dut, cmd, type=cli_type, skip_tmpl=skip_tmpl, skip_error_check=skip_error)

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for key in kwargs:
        if str(kwargs[key]) != str(output[0][key]):
            st.error("Match not Found for {} :  Expected - {} Actual-{} ".format(key,kwargs[key],output[0][key]))
            ret_val = False
        else:
            st.log("Match Found for {} :  Expected - {} Actual-{} ".format(key,kwargs[key],output[0][key]))

    return ret_val



def verify_igmp_interface(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param interface
    :type string
    :param state
    :type string
    :param address
    :type string
    :param uptime
    :type string
    :param version
    :type string
    :param querier
    :type string
    :param start_count
    :type string
    :param query_timer
    :type string
    :param other_timer
    :type string
    :param gmi
    :type string
    :param last_member_query_time
    :type string
    :param old_host_present_interval
    :type string
    :param other_querier_present_interval
    :type string
    :param query_interval
    :type string
    :param query_response_interval
    :type string
    :param robustness
    :type string
    :param startup_query_interval
    :type string
    :param all_multicast
    :type string
    :param broadcast
    :type string
    :param deleted
    :type string
    :param ifindex
    :type string
    :param multicast
    :type string
    :param multicast_loop
    :type string
    :param promiscuous
    :type string
    :param vrf
    :type string
    :param cli_type
    :type string
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    #cli_type = force_cli_type_to_klish(cli_type)
    #comment the above line once defect 65227, 65229 are fixed
    kwargs.pop('cli_type', None)
    ret_val = True
    cmd = ''
    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    skip_tmpl = kwargs.pop('skip_tmpl', False)
    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='IGMP', Name='igmp', NetworkInstance=ni_obj)
        igmp_proto_obj = umf_ni.igmpProtoInterface(InterfaceId=kwargs['interface'], Protocol=proto_obj)
        if 'query_interval' in kwargs: setattr(igmp_proto_obj, 'QueryInterval', int(kwargs['query_interval']))
        if 'version' in kwargs: setattr(igmp_proto_obj, 'Version', kwargs['version'])
        if 'query_max_response' in kwargs: setattr(igmp_proto_obj, 'QueryResponseInterval', kwargs['query_max_response'])
        if 'last_member_query_interval' in kwargs: setattr(igmp_proto_obj, 'LastMemberQueryTime', kwargs['last_member_query_interval'])
        result = igmp_proto_obj.verify(dut, match_subset=True, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verify IGMP Interface: {}'.format(kwargs['interface']))
            return False

        return True
    if cli_type in ['rest-patch', 'rest-put'] and vrf_name == 'all':
        cli_type = 'klish'

    if cli_type in ['click', 'klish']:
        if vrf_name != 'default':
            cmd = 'show ip igmp vrf {} interface {}'.format(vrf_name, kwargs['interface'])
        else:
            cmd = 'show ip igmp interface {}'.format(kwargs['interface'])

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['igmp_intf_lvl'].format(name=vrf_name, identifier='IGMP', name1='igmp', ifname=kwargs['interface'])
        res = get_rest(dut,http_method=cli_type, rest_url=url)
        if res:
            if len(res['output']) == 0:
                st.error("DUT Failed to display the Output")
                return False
            else:
                output = parse_igmp_output(res['output'], type='intflvl')

    if cli_type == 'click':
        cli_type = 'vtysh'

    if cli_type in ['vtysh', 'klish']:
        output = st.show(dut, cmd, type=cli_type, skip_error_check=skip_error, skip_tmpl=skip_tmpl)

    if len(output) == 0 :
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for key in kwargs:
        if str(kwargs[key]) != str(output[0][key]):
            st.error("Match not Found for {} :  Expected - {} Actual-{} ".format(key, kwargs[key], output[0][key]))
            ret_val = False
        else:
            st.log("Match Found for {} :  Expected - {} Actual-{} ".format(key, kwargs[key], output[0][key]))

    return ret_val


def clear_igmp_interfaces(dut, vrf='default', cli_type=''):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param vrf:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type)
    if cli_type in ['click', 'klish']:
        if vrf == 'default':
            cmd = "clear ip igmp interfaces"
        else:
            cmd = "clear ip igmp vrf {} interfaces".format(vrf)
        if cli_type == 'click':
            cli_type = 'vtysh'
        st.config(dut, cmd, type=cli_type, conf=False)

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['clear_igmp']
        config_data = {"sonic-igmp:input": {"vrf-name": vrf,"interface": "string","interface-all": True}}
        if not config_rest(dut, rest_url=url, http_method='post', json_data=config_data):
            st.error("Failed to Clear the interfaces")
            return False
        return True

def debug_igmp(dut, **kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :return:
    """
    if 'config' in kwargs:
        config= kwargs['config']
    else:
        config = 'yes'

    if config == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    cmd = "{} debug igmp packets\n".format(config_cmd)
    cmd += "{} debug igmp events\n".format(config_cmd)
    cmd += "{} debug igmp trace\n".format(config_cmd)
    cmd += "{} debug igmp\n".format(config_cmd)
    cmd += '{0} log syslog debugging\n {0} log stdout\n'.format(config_cmd)
    st.config(dut,cmd, type='vtysh')

def config_ip_igmp(dut, **kwargs):
    """
    Config IP IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        commands.append("{} ip igmp".format(config_cmd))
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get('skip_error'))
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get("skip_error_check", False))
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include ip igmp", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_join(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    print(kwargs)
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'mcastgrpaddr' not in kwargs:
        st.error("Mandatory parameter mcastgrpaddr not found")
        return False

    if 'srcaddr' not in kwargs:
        st.error("Mandatory parameter srcaddr not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        commands.append("{} ip igmp join {} {}".format(config_cmd,
                                          kwargs['mcastgrpaddr'],
                                          kwargs['srcaddr']))
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get('skip_error'))
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get("skip_error_check", False))
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp join", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_qinterval(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'qinterval' not in kwargs:
        st.error("Mandatory parameter query interval not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'


    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        if config.lower() == 'yes':
            commands.append("ip igmp query-interval {}".format(kwargs.get('qinterval')))
        else:
            commands.append("no ip igmp query-interval")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get('skip_error'))
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get("skip_error_check", False))
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include query-interval", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_version(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'version' not in kwargs:
        st.error("Mandatory parameter version is not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        if config.lower() == 'yes':
            commands.append("ip igmp version {}".format(kwargs.get('version')))
        else:
            commands.append("no ip igmp version")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get('skip_error'))
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get("skip_error_check", False))
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp version", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_qmrestime(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'qmrestime' not in kwargs:
        st.error("Mandatory parameter query max response time not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))

        if config.lower() == 'yes':
            commands.append("ip igmp query-max-response-time {}".format(kwargs.get('qmrestime')))
        else:
            commands.append("no ip igmp query-max-response-time")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get('skip_error'))
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get("skip_error_check", False))
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp query-max-response-time", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_lmqcount(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'lmqcount' not in kwargs:
        st.error("Mandatory parameter last member query count not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        if config.lower() == 'yes':
            commands.append("ip igmp last-member-query-count {}".format(kwargs.get('lmqcount')))
        else:
            commands.append("no ip igmp last-member-query-count")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get("skip_error_check", False))
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp last-member-query-count", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_lmqinterval(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'lmqinterval' not in kwargs:
        st.error("Mandatory parameter last-member-query-interval not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        if config.lower() == 'yes':
            commands.append("ip igmp last-member-query-interval {}".format(kwargs.get('lmqinterval')))
        else:
            commands.append("no ip igmp last-member-query-interval")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type, skip_error_check=kwargs.get("skip_error_check", False))
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp last-member-query-interval", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def parse_igmp_output(response, type):

    output = list()
    if type == 'source':
        needed_output = response["openconfig-igmp-ext:sources"]['source']
        for entry in needed_output:
            temp = dict()
            if entry in needed_output:
                temp['interface'] = entry['interface-id'] if entry.get('interface-id') else ''
                temp['source'] = entry['src-addr'] if entry.get('src-addr') else ''
                temp['group'] = entry['mcastgrp-addr'] if entry.get('mcastgrp-addr') else ''
                temp['fwd'] = entry['state']['source-forwarding'] if entry['state'].get('source-forwarding') else ''
                temp['address'] = entry['state']['ip-addr'] if entry['state'].get('ip-addr') else ''
                temp['timer'] = entry['state']['timer'] if entry['state'].get('timer') else ''
                temp['uptime'] = entry['state']['uptime'] if entry['state'].get('uptime') else ''
            output.append(temp)

    elif type == 'group':
        needed_output = response["openconfig-igmp-ext:groups"]['group']
        for entry in needed_output:
            temp = dict()
            if entry in needed_output:
                temp['interface'] = entry['interface-id'] if entry.get('interface-id') else ''
                temp['version'] = str(entry['state']['version']) if entry['state'].get('version') else ''
                temp['source_count'] = str(entry['state']['sources-count']) if entry['state'].get('sources-count') else ''
                temp['group'] = entry['mcastgrp-addr'] if entry.get('mcastgrp-addr') else ''
                temp['mode'] = entry['state']['mode'] if entry['state'].get('mode') else ''
                temp['address'] = entry['state']['ip-addr'] if entry['state'].get('ip-addr') else ''
                temp['uptime'] = entry['state']['uptime'] if entry['state'].get('uptime') else ''
                temp['timer'] = entry['state']['timer'] if entry['state'].get('timer') else ''
            output.append(temp)

    elif type == 'intflvl':
        needed_output = response['openconfig-network-instance:interface']
        output = list()
        for entry in needed_output:
            if 'state' in entry:
                temp = dict()
                temp['interface'] = entry['interface-id'] if entry.get('interface-id') else ''
                temp['querier'] = entry['state']['openconfig-igmp-ext:querier']['querier-type'] if entry['state'][
                    'openconfig-igmp-ext:querier'].get('querier-type') else ''
                temp['query_timer'] = entry['state']['openconfig-igmp-ext:querier']['query-timer'] if entry['state'][
                    'openconfig-igmp-ext:querier'].get('query-timer') else ''
                temp['other_timer'] = entry['state']['openconfig-igmp-ext:querier']['query-general-timer'] if \
                entry['state']['openconfig-igmp-ext:querier'].get('query-general-timer') else ''
                temp['start_count'] = entry['state']['openconfig-igmp-ext:querier']['query-startup-count'] if \
                entry['state']['openconfig-igmp-ext:querier'].get('query-startup-count') else ''
                temp['address'] = entry['state']['openconfig-igmp-ext:querier']['ip-addr'] if entry['state'][
                    'openconfig-igmp-ext:querier'].get('ip-addr') else ''
                temp['state'] = entry['state']['openconfig-igmp-ext:querier']['status'] if entry['state'][
                    'openconfig-igmp-ext:querier'].get('status') else ''
                temp['startup_query_interval'] = str(
                    entry['state']['openconfig-igmp-ext:timers']['startup-query-interval']) if entry['state'][
                    'openconfig-igmp-ext:timers'].get('startup-query-interval') else ''
                temp['robustness'] = str(entry['state']['openconfig-igmp-ext:timers']['robustness-variable']) if \
                entry['state']['openconfig-igmp-ext:timers'].get('startup-query-interval') else ''
                temp['query_response_interval'] = str(
                    entry['state']['openconfig-igmp-ext:timers']['query-response-interval']) if entry['state'][
                    'openconfig-igmp-ext:timers'].get('query-response-interval') else ''
                temp['query_interval'] = str(entry['state']['openconfig-igmp-ext:timers']['query-interval']) if \
                entry['state']['openconfig-igmp-ext:timers'].get('query-interval') else ''
                temp['old_host_present_interval'] = str(
                    entry['state']['openconfig-igmp-ext:timers']['older-host-present-interval']) if entry['state'][
                    'openconfig-igmp-ext:timers'].get('older-host-present-interval') else ''
                temp['other_querier_present_interval'] = str(
                    entry['state']['openconfig-igmp-ext:timers']['querier-present-interval']) if entry['state'][
                    'openconfig-igmp-ext:timers'].get('querier-present-interval') else ''
                temp['last_member_query_time'] = str(
                    entry['state']['openconfig-igmp-ext:timers']['last-member-query-time']) if entry['state'][
                    'openconfig-igmp-ext:timers'].get('last-member-query-time') else ''
                temp['last_member_query_count'] = str(
                    entry['state']['openconfig-igmp-ext:timers']['last-member-query-count']) if entry['state'][
                    'openconfig-igmp-ext:timers'].get('last-member-query-count') else ''
                temp['gmi'] = str(entry['state']['openconfig-igmp-ext:timers']['group-membership-interval']) if \
                entry['state']['openconfig-igmp-ext:timers'].get('group-membership-interval') else ''
                temp['version'] = str(entry['state']['version']) if entry['state'].get('version') else ''
                temp['all_multicast'] = entry['state']['openconfig-igmp-ext:flags']['all-multicast'] if entry['state'][
                    'openconfig-igmp-ext:flags'].get('all-multicast') else ''
                temp['broadcast'] = entry['state']['openconfig-igmp-ext:flags']['broadcast'] if entry['state'][
                    'openconfig-igmp-ext:flags'].get('broadcast') else ''
                temp['deleted'] = entry['state']['openconfig-igmp-ext:flags']['deleted'] if entry['state'][
                    'openconfig-igmp-ext:flags'].get('deleted') else ''
                temp['ifindex'] = str(entry['state']['openconfig-igmp-ext:flags']['index']) if entry['state'][
                    'openconfig-igmp-ext:flags'].get('index') else ''
                temp['multicast'] = entry['state']['openconfig-igmp-ext:flags']['multicast'] if entry['state'][
                    'openconfig-igmp-ext:flags'].get('multicast') else ''
                temp['promiscuous'] = entry['state']['openconfig-igmp-ext:flags']['promiscous'] if entry['state'][
                    'openconfig-igmp-ext:flags'].get('promiscous') else ''
                output.append(temp)

    elif type == 'counters':
        needed_output = response["openconfig-network-instance:counters"]
        output = list()
        temp = dict()
        temp['query_v1'] = str(needed_output['queries']['sent']['state']['v1'])
        temp['query_v2'] = str(needed_output['queries']['sent']['state']['v2'])
        temp['query_v3'] = str(needed_output['queries']['sent']['state']['v3'])
        temp['report_v1'] = str(needed_output['reports']['state']['v1'])
        temp['report_v2'] = str(needed_output['reports']['state']['v2'])
        temp['report_v3'] = str(needed_output['reports']['state']['v3'])
        output.append(temp)

    elif type == 'statistics':
        needed_output = response["openconfig-igmp-ext:statistics"]
        output = list()
        temp = dict()
        temp['mtrace_request'] = str(needed_output['mtrace-counters']['state']['mtrace-request'])
        temp['mtrace_response'] = str(needed_output['mtrace-counters']['state']['mtrace-response'])
        temp['unsupported'] = str(needed_output['mtrace-counters']['state']['unsupported'])
        temp['report_v1'] = str(needed_output['counters']['reports']['state']['v1'])
        temp['report_v2'] = str(needed_output['counters']['reports']['state']['v2'])
        temp['report_v3'] = str(needed_output['counters']['reports']['state']['v3'])
        temp['query_v1'] = str(needed_output['counters']['queries']['sent']['state']['v1'])
        temp['query_v2'] = str(needed_output['counters']['queries']['sent']['state']['v2'])
        temp['query_v3'] = str(needed_output['counters']['queries']['sent']['state']['v3'])
        output.append(temp)

    return output


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type
