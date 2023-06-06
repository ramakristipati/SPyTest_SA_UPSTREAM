import re
from spytest import st
from apis.common import redis
from apis.common.asic import asic_show
from apis.system.rest import delete_rest, config_rest, get_rest
from utilities.common import filter_and_select, make_list
from utilities.utils import get_interface_number_from_name, get_intf_short_name, segregate_intf_list_type, is_a_single_intf, get_supported_ui_type_list, convert_intf_name_to_component

try:
    import apis.yang.codegen.messages.network_instance as umf_ni
    from apis.yang.utils.common import Operation
except ImportError:
    pass


def config_pim_global(dut, **kwargs):
    """
    config_pim_global(dut=data.dut1,pim_enable='yes',config='yes',hello_intv= 50)

    Configure interface with pim configurations
    :param dut:
    :param ecmp_rebalance:
    :param ecmp:
    :param join_prune_interval:
    :param packets:
    :param ssm_prefix_list:
    :param rp_address:
    :param rp_group:
    :param rp_mask:
    :param rp_prefix_list:
    :param spt_infinity:
    :param spt_prefix_list:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if 'config' in kwargs:
        config = kwargs.get('config')
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    if 'vrf' in kwargs:
        vrf = kwargs.get('vrf')
    else:
        vrf = 'default'

    skip_error = bool(kwargs.get('skip_error', False))

    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0

    cli_type = 'click' if 'packets' in kwargs else cli_type
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        pim_obj = umf_ni.Protocol(ProtoIdentifier='PIM', Name='pim', NetworkInstance=ni_obj)
        if config == 'yes':
            if 'keep_alive' in kwargs:
                pim_obj.KeepAliveTimer = float(kwargs['keep_alive'])
            if 'ecmp' in kwargs:
                pim_obj.EcmpEnabled = True
            if 'ecmp_rebalance' in kwargs:
                pim_obj.EcmpRebalanceEnabled = True
            if 'join_prune_interval' in kwargs:
                pim_obj.JoinPruneInterval = float(kwargs['join_prune_interval'])
            if 'ssm_prefix_list' in kwargs:
                pim_obj.SsmRanges = kwargs['ssm_prefix_list']
            try:
                result = pim_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                    return False
            except ValueError as exp:
                if skip_error:
                   st.log('ValueError: {}'.format(exp))
                   st.log('Negative Scenario: Errors/Expception expected')
                   return False
                else:
                    raise
        else:
            if 'keep_alive' in kwargs:
                result = pim_obj.unConfigure(dut, target_attr=pim_obj.KeepAliveTimer, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                    return False
            if 'ecmp_rebalance' in kwargs:
                result = pim_obj.unConfigure(dut, target_attr=pim_obj.EcmpRebalanceEnabled, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                    return False
            if 'ecmp' in kwargs:
                result = pim_obj.unConfigure(dut, target_attr=pim_obj.EcmpEnabled, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                    return False
            if 'join_prune_interval' in kwargs:
                result = pim_obj.unConfigure(dut, target_attr=pim_obj.JoinPruneInterval, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                    return False
            if 'ssm_prefix_list' in kwargs:
                result = pim_obj.unConfigure(dut, target_attr=pim_obj.SsmRanges, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                    return False
        return True

    elif cli_type == 'click':
        cli_type='vtysh'
        if vrf == 'default':
            my_cmd = ''
        else:
            my_cmd = 'vrf {}\n'.format(vrf)

        if 'ecmp_rebalance' in kwargs:
            my_cmd += '{} ip pim ecmp rebalance \n'.format(config_cmd)

        if 'ecmp' in kwargs:
            my_cmd += '{} ip pim ecmp \n'.format(config_cmd)

        if 'join_prune_interval' in kwargs:
            my_cmd += '{} ip pim join-prune-interval {} \n'.format(config_cmd, kwargs['join_prune_interval'])

        if 'keep_alive' in kwargs:
            my_cmd += '{} ip pim keep-alive-timer {} \n'.format(config_cmd, kwargs['keep_alive'])

        if 'packets' in kwargs:
            my_cmd += '{} ip pim packets {} \n'.format(config_cmd, kwargs['packets'])

        if 'ssm_prefix_list' in kwargs:
            my_cmd += '{} ip pim ssm prefix-list {} \n'.format(config_cmd, kwargs['ssm_prefix_list'])

        if 'rp_address' in kwargs:
            for key in kwargs:
                if key in ['rp_address', 'rp_group','rp_mask','rp_prefix_list']:
                    kwargs[key] = list(kwargs[key]) if type(kwargs[key]) is list else [kwargs[key]]

            for i in range(0, len(kwargs['rp_address'])):
                if 'rp_group' in kwargs and 'rp_mask' in kwargs:
                    my_cmd += '{} ip pim rp {} {}/{}\n'.format(config_cmd, kwargs['rp_address'][i],kwargs['rp_group'][i],kwargs['rp_mask'][i])
                elif 'rp_prefix_list' in kwargs:
                    my_cmd += '{} ip pim rp {} prefix-list {}\n'.format(config_cmd, kwargs['rp_address'][i],kwargs['rp_prefix_list'][i])
                else:
                    my_cmd += '{} ip pim rp {} \n'.format(config_cmd, kwargs['rp_address'][i])

        if 'spt_infinity' in kwargs:
            if 'spt_prefix_list' in kwargs:
                my_cmd += '{} ip pim spt-switchover infinity-and-beyond prefix-list {}\n'.format(config_cmd, kwargs['spt_prefix_list'])
            else:
                my_cmd += '{} ip pim spt-switchover infinity-and-beyond\n'.format(config_cmd)

        if vrf != 'default':
            my_cmd += 'exit-vrf\n'

        return st.config(dut, my_cmd, type=cli_type, skip_error_check=skip_error, max_time=maxtime)

    elif cli_type == 'klish':
        vrf_command = '' if vrf == 'default' else 'vrf {}'.format(vrf)
        my_cmd = list()

        if config == 'yes':
            if 'ecmp' in kwargs:
                my_cmd.append('ip pim {} ecmp'.format(vrf_command))

            if 'ecmp_rebalance' in kwargs:
                my_cmd.append('ip pim {} ecmp rebalance'.format(vrf_command))
        else:
            if 'ecmp_rebalance' in kwargs:
                my_cmd.append('no ip pim {} ecmp rebalance'.format(vrf_command))

            if 'ecmp' in kwargs:
                my_cmd.append('no ip pim {} ecmp'.format(vrf_command))

        if 'join_prune_interval' in kwargs:
            if config == 'yes':
                my_cmd.append('ip pim {} join-prune-interval {}'.format(vrf_command, kwargs['join_prune_interval']))
            else:
                my_cmd.append('no ip pim {} join-prune-interval'.format(vrf_command))

        if 'keep_alive' in kwargs:
            if config == 'yes':
                my_cmd.append('ip pim {} keep-alive-timer {}'.format(vrf_command, kwargs['keep_alive']))
            else:
                my_cmd.append('no ip pim {} keep-alive-timer'.format(vrf_command))

        if 'ssm_prefix_list' in kwargs:
            if config == 'yes':
                my_cmd.append('ip pim {} ssm prefix-list {}'.format(vrf_command, kwargs['ssm_prefix_list']))
            else:
                my_cmd.append('no ip pim {} ssm prefix-list'.format(vrf_command))

        if 'rp_address' in kwargs:
            for key in kwargs:
                if key in ['rp_address', 'rp_prefix_list']:
                    kwargs[key] = list(kwargs[key]) if type(kwargs[key]) is list else [kwargs[key]]

            for i in range(0, len(kwargs['rp_address'])):
                if config == 'yes':
                    if 'rp_prefix_list' in kwargs:
                        my_cmd.append('ip pim {} rp-address {} prefix-list {}\n'.format(vrf_command, kwargs['rp_address'][i],kwargs['rp_prefix_list'][i]))
                    else:
                        my_cmd.append('ip pim {} rp-address {} \n'.format(vrf_command, kwargs['rp_address'][i]))
                else:
                    if 'rp_prefix_list' in kwargs:
                        my_cmd.append('no ip pim {} rp-address {} prefix-list \n'.format(vrf_command, kwargs['rp_address'][i]))
                    else:
                        my_cmd.append('no ip pim {} rp-address {} \n'.format(vrf_command, kwargs['rp_address'][i]))

        if 'spt_infinity' in kwargs:
            if config == 'yes':
                if 'spt_prefix_list' in kwargs:
                    my_cmd.append('ip pim {} spt-threshold infinity prefix-list {}\n'.format(vrf_command, kwargs['spt_prefix_list']))
                else:
                    my_cmd.append('ip pim {} spt-threshold infinity\n'.format(vrf_command))
            else:
                my_cmd.append('no ip pim {} spt-threshold infinity\n'.format(vrf_command))

        return st.config(dut, my_cmd, type=cli_type, skip_error_check=skip_error, max_time=maxtime)

    elif cli_type in ['rest-put', 'rest-patch']:
        vrf_command = 'default' if vrf == 'default' else '{}'.format(vrf)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if config == 'yes':
            temp = dict()
            url = rest_urls['pim_config'].format(name=vrf_command, identifier='PIM', name1='pim')
            if 'keep_alive' in kwargs:
                temp.update({"keep-alive-timer": float(kwargs['keep_alive'])})
            if 'ecmp' in kwargs:
                temp.update({"ecmp-enabled": True})
            if 'ecmp_rebalance' in kwargs:
                temp.update({"ecmp-rebalance-enabled": True})
            if 'join_prune_interval' in kwargs:
                temp.update({"join-prune-interval": float(kwargs['join_prune_interval'])})
            if temp:
                config_data = {"openconfig-network-instance:global": {"openconfig-pim-ext:config": temp}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to Enable Global Configuration")
                    return False
            if 'ssm_prefix_list' in kwargs:
                config_data = {"openconfig-network-instance:global": {"ssm": {"config": {"ssm-ranges": kwargs['ssm_prefix_list']}}}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to Enable Global Configuration")
                    return False

            return True
        else:
            if 'keep_alive' in kwargs:
                url = rest_urls['pim_keep_alive'].format(name=vrf_command, identifier='PIM', name1='pim')
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to Unconfig")
                    return False
            if 'ecmp_rebalance' in kwargs:
                url = rest_urls['pim_rebalance'].format(name=vrf_command, identifier='PIM', name1='pim')
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to Unconfig")
                    return False
            if 'ecmp' in kwargs:
                url = rest_urls['pim_ecmp'].format(name=vrf_command, identifier='PIM', name1='pim')
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to Unconfig")
                    return False
            if 'join_prune_interval' in kwargs:
                url = rest_urls['pim_join'].format(name=vrf_command, identifier='PIM', name1='pim')
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to Unconfig")
                    return False
            if 'ssm_prefix_list' in kwargs:
                url = rest_urls['pim_ssm'].format(name=vrf_command, identifier='PIM', name1='pim')
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to Unconfig")
                    return False
            return True

    else:
        st.error("Unsupported CLI TYPE--{}".format(cli_type))
        return False


def config_intf_pim(dut, **kwargs):
    """
    config_intf_pim(dut=data.dut1,intf =['Ethernet10','Ethernet11'],pim_enable='yes',config='yes',hello_intv= 50)

    Configure interface with pim configurations
    :param dut:
    :param intf:
    :param pim_enable:
    :param hello_intv:
    :param drpriority:
    :param use_source:
    :param bfd_enable:
    :param bfd_profile:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if 'config' in kwargs:
        config = kwargs.get('config')
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    vrf = kwargs.pop('vrf', 'default')

    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0

    if 'intf' not in kwargs:
        st.error("Interface is mandatory parameter")
        return False

    my_cmd= ''
    output = ''
    use_batch = bool(kwargs.get('use_batch', True))
    skip_error = bool(kwargs.get('skip_error', False))
    cli_type = 'click' if 'hold_time' in kwargs else cli_type
    if cli_type in get_supported_ui_type_list():
        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        intf_list = port_hash_list['intf_list_all']
        for ifname in intf_list:
            ni_obj = umf_ni.NetworkInstance(Name=vrf)
            pim_obj = umf_ni.Protocol(ProtoIdentifier='PIM', Name='pim', NetworkInstance=ni_obj)
            intf_pim_obj = umf_ni.PimInterface(InterfaceId=ifname, Protocol=pim_obj)
            if config == 'yes':
                operation = Operation.CREATE
                if 'pim_enable' in kwargs:
                    intf_pim_obj.Mode = "PIM_MODE_SPARSE"
                if 'hello_intv' in kwargs:
                    intf_pim_obj.HelloInterval = int(kwargs['hello_intv'])
                if 'drpriority' in kwargs:
                    intf_pim_obj.DrPriority = int(kwargs['drpriority'])
                if 'bfd_enable' in kwargs:
                    intf_pim_obj.Enabled = True
                if 'bfd_profile' in kwargs:
                    intf_pim_obj.Enabled = True
                    intf_pim_obj.BfdProfile = kwargs['bfd_profile']
                try:
                    result = intf_pim_obj.configure(dut, operation=operation, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Failed for PIM Config at interface level {}'.format(result.data))
                        return False
                except ValueError as exp:
                    if skip_error:
                       st.log('ValueError: {}'.format(exp))
                       st.log('Negative Scenario: Errors/Expception expected')
                       return False
                    else:
                        raise
            else:
                if 'pim_enable' in kwargs:
                    result = intf_pim_obj.unConfigure(dut, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                        return False
                if 'hello_intv' in kwargs:
                    result = intf_pim_obj.unConfigure(dut, target_attr=intf_pim_obj.HelloInterval, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                        return False
                if 'bfd_enable' in kwargs:
                    for attr in [intf_pim_obj.Enabled, intf_pim_obj.BfdProfile]:
                        result = intf_pim_obj.unConfigure(dut, target_attr=attr, cli_type=cli_type)
                        if not result.ok():
                            st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                            return False
                if 'drpriority' in kwargs:
                    result = intf_pim_obj.unConfigure(dut, target_attr=intf_pim_obj.DrPriority, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                        return False
                if 'bfd_profile' in kwargs:
                    result = intf_pim_obj.unConfigure(dut, target_attr=intf_pim_obj.BfdProfile, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Failed for PIM global Config {}'.format(result.data))
                        return False
        return True
    elif cli_type == 'click':
        cli_type = 'vtysh'
        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        intf_list = port_hash_list['intf_list_all']
        for intf in intf_list:
            intf = get_intf_short_name(intf)
            my_cmd += 'interface {}\n'.format(intf)
            if 'pim_enable' in kwargs:
                my_cmd += '{} ip pim \n'.format(config_cmd)

            if 'hello_intv' in kwargs:
                if 'hold_time' in kwargs:
                    my_cmd += '{} ip pim hello {} {}\n'.format(config_cmd, kwargs['hello_intv'], kwargs['hold_time'])
                else:
                    my_cmd += '{} ip pim hello {} \n'.format(config_cmd, kwargs['hello_intv'])

            if 'drpriority' in kwargs:
                my_cmd += '{} ip pim drpriority {} \n'.format(config_cmd, kwargs['drpriority'])

            if 'use_source' in kwargs:
                my_cmd += '{} ip pim use-source {} \n'.format(config_cmd, kwargs['use_source'])

            if 'bfd_enable' in kwargs:
                my_cmd += '{} ip pim bfd\n'.format(config_cmd)

            if 'bfd_profile' in kwargs:
                my_cmd += '{} ip pim bfd profile {}\n'.format(config_cmd, kwargs['bfd_profile'])

            if not use_batch:
                my_cmd += "exit\n"
                output = output + st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error, max_time=maxtime)

    elif cli_type == 'klish':
        my_cmd = list()
        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        intf_list = port_hash_list['intf_list_all']
        for intf in intf_list:
            if not is_a_single_intf(intf):
                my_cmd.append("interface range {}".format(intf))
            else:
                intf_details = get_interface_number_from_name(intf)
                if not intf_details:
                    st.log("Interface data not found for {} ".format(intf))
                my_cmd.append("interface {} {}".format(intf_details["type"], intf_details["number"]))

            if 'pim_enable' in kwargs:
                my_cmd.append('{} ip pim sparse-mode'.format(config_cmd))

            if 'hello_intv' in kwargs:
                if 'hold_time' in kwargs:
                    my_cmd.append('{} ip pim hello {} {}'.format(config_cmd, kwargs['hello_intv'], kwargs['hold_time']))
                else:
                    if not config_cmd:
                        my_cmd.append('{} ip pim hello {}'.format(config_cmd, kwargs['hello_intv']))
                    else:
                        my_cmd.append('no ip pim hello')
            if 'drpriority' in kwargs:
                if not config_cmd:
                    my_cmd.append('ip pim drpriority {}'.format(kwargs['drpriority']))
                else:
                    my_cmd.append('no ip pim drpriority')

            if 'bfd_enable' in kwargs:
                my_cmd.append('{} ip pim bfd'.format(config_cmd))

            if 'bfd_profile' in kwargs:
                if config_cmd != 'no':
                    my_cmd.append('ip pim bfd profile {}\n'.format(kwargs['bfd_profile']))
                else:
                    my_cmd.append('{} ip pim bfd profile\n'.format(config_cmd))

            my_cmd.append('exit')
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = 'default' if vrf == 'default' else vrf
        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        intf_list = port_hash_list['intf_list_all']
        for ifname in intf_list:
            if config == 'yes':
                url = rest_urls['pim_sparse'].format(name=vrf, identifier='PIM', name1='pim')
                temp = {"interface-id": ifname}
                bfd_temp = {}
                if 'pim_enable' in kwargs:
                    temp.update(mode="PIM_MODE_SPARSE")
                if 'hello_intv' in kwargs:
                    temp.update({"hello-interval": int(kwargs['hello_intv'])})
                if 'drpriority' in kwargs:
                    temp.update({"dr-priority": int(kwargs['drpriority'])})
                if 'bfd_enable' in kwargs:
                    bfd_temp.update({"enabled": True})
                if 'bfd_profile' in kwargs:
                    bfd_temp.update({"enabled": True})
                    bfd_temp.update({"bfd-profile": kwargs['bfd_profile']})
                config_data = {"openconfig-network-instance:interfaces": {"interface": [{"interface-id": ifname, "config": temp, "enable-bfd": {"config": bfd_temp}}]}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to enable PIM config on Interface {}".format(ifname))
                    return False
            else:
                rest_urls = st.get_datastore(dut, 'rest_urls')
                if 'pim_enable' in kwargs:
                    url = rest_urls['delete_pim_sparse'].format(name=vrf, identifier='PIM', name1='pim', ifname=ifname)
                    if not delete_rest(dut, rest_url=url, http_method=cli_type):
                        st.error("Failed to Clean up PIM Configuration on {}".format(dut))
                        return False
                if 'hello_intv' in kwargs:
                    url = rest_urls['delete_pim_hello'].format(name=vrf, identifier='PIM', name1='pim', ifname=ifname)
                    if not delete_rest(dut, rest_url=url, http_method=cli_type):
                        st.error("Failed to Clean up PIM Configuration on {}".format(dut))
                        return False
                if 'bfd_enable' in kwargs:
                    bfd_url = rest_urls['delete_pim_bfd'].format(name=vrf, identifier='PIM', name1='pim', ifname=ifname)
                    prof_url = rest_urls['delete_pim_bfd_profile'].format(name=vrf, identifier='PIM', name1='pim', ifname=ifname)
                    for url in [prof_url, bfd_url]:
                        if not delete_rest(dut, rest_url=url, http_method=cli_type):
                            st.error("Failed to Clean up PIM Configuration on {}".format(dut))
                            return False
                if 'bfd_profile' in kwargs:
                    url = rest_urls['delete_pim_bfd_profile'].format(name=vrf, identifier='PIM', name1='pim', ifname=ifname)
                    if not delete_rest(dut, rest_url=url, http_method=cli_type):
                        st.error("Failed to Clean up PIM Configuration on {}".format(dut))
                        return False
                if 'drpriority' in kwargs:
                    url = rest_urls['delete_pim_drpriority'].format(name=vrf, identifier='PIM', name1='pim', ifname=ifname)
                    if not delete_rest(dut, rest_url=url, http_method=cli_type):
                        st.error("Failed to Clean up PIM Configuration on {}".format(dut))
                        return False
        return True
    else:
        st.log('Unsupported CLI -- {}'.format(cli_type), dut)

    if cli_type in ['vtysh', 'klish']:
        output = st.config(dut, my_cmd, type=cli_type, skip_error_check=skip_error)

    return output

def config_ip_mroute(dut, **kwargs):
    """
    Configure global or interface mroute configurations
    :param dut:
    :param dest_ip:
    :param dest_ip_mask:
    :param next_hop:
    :param distance: (OPTIONAL Parameter)
    :return:
    config_ip_mroute('dut1',dest_ip='232.1.1.1',dest_ip_mask='8',next_hop='Ethernet24',distance=10) - global
    config_ip_mroute('dut1',intf='Etherent24',oif='Ethernet32',group='232.1.1.1',source='10.1.1.2') - interface scope
    """
    if 'config' in kwargs:
        config = kwargs.get('config')
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    if 'intf' in kwargs:
        kwargs['intf'] = convert_intf_name_to_component(dut, intf_list=kwargs['intf'])
        kwargs['oif'] = convert_intf_name_to_component(dut, intf_list=kwargs['oif'])
        #kwargs['intf'] = st.get_other_names(dut, [kwargs['intf']])[0] if st.get_ifname_type(dut) == 'alias' else kwargs['intf']
        #kwargs['oif'] = st.get_other_names(dut, [kwargs['oif']])[0] if st.get_ifname_type(dut) == 'alias' else kwargs['oif']
        my_cmd = 'interface {}\n'.format(kwargs['intf'])
        my_cmd += '{} ip mroute {} {} {}\n'.format(config_cmd,kwargs['oif'],kwargs['group'],kwargs['source'])
        my_cmd += 'exit\n'
    else:
        my_cmd = ''
        kwargs['next_hop'] = convert_intf_name_to_component(dut, intf_list=kwargs['next_hop'])
        #kwargs['next_hop'] = st.get_other_names(dut, [kwargs['next_hop']])[0] if st.get_ifname_type(dut) == 'alias' else kwargs['next_hop']
        if 'distance' in kwargs:
            my_cmd += '{} ip mroute {}/{} {} {}\n'.format(config_cmd,kwargs['dest_ip'],kwargs['dest_ip_mask'],kwargs['next_hop'],kwargs['distance'])
        else:
            my_cmd += '{} ip mroute {}/{} {}\n'.format(config_cmd,kwargs['dest_ip'], kwargs['dest_ip_mask'], kwargs['next_hop'])

    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)


def config_ip_multicast_rpf_lookup(dut, **kwargs):
    """
    config_ip_multicast_rpf_lookup(dut=data.dut1,rpf_lookup_mode ='longer-prefix'config='yes')

    Configure multicast RPF lookup mode
    :param dut:
    :param rpf_lookup_mode:
    :return:
    """
    my_cmd = ''
    if 'config' in kwargs:
        config = kwargs.get('config')
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    if 'rpf_lookup_mode' in kwargs:
        my_cmd = '{} ip multicast rpf-lookup-mode {}\n'.format(config_cmd,kwargs['rpf_lookup_mode'])

    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)


def config_intf_multicast(dut, **kwargs):
    """
    config_intf_multicast(dut=data.dut1,intf =['Ethernet10','Ethernet11'],config='yes')

    Configure interface with pim configurations
    :param dut:
    :param intf:
    :return:
    """
    if 'intf' not in kwargs:
        st.error("Interface is mandatory parameter")
        return False

    skip_error = bool(kwargs.get('skip_error', False))
    config = kwargs.get('config', "yes").lower()
    config_cmd = "" if config == 'yes'  else "no"

    output = ""
    for intf in make_list(kwargs['intf']):
        my_cmd = 'interface {}\n'.format(intf)
        my_cmd += '{} multicast \n'.format(config_cmd)
        my_cmd += 'exit \n'
        output += st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)
    return output

def config_ip_multicast_boundary(dut, **kwargs):
    """
    config_ip_multicast_boundary(dut=data.dut1,rpf_lookup_mode ='longer-prefix'config='yes')

    Configure multicast RPF lookup mode
    :param dut:
    :param intf:
    :param oil_prefix_list:
    :return:
    """
    if 'config' in kwargs:
        config = kwargs.get('config')
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    my_cmd = 'interface {}\n'.format(kwargs['intf'])
    my_cmd += '{} ip multicast boundary oil {}\n'.format(config_cmd,kwargs['oil_prefix_list'])
    my_cmd += 'exit\n'

    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)


def verify_ip_mroute(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param source:
    :type string or list
    :param group:
    :type string or list
    :param proto:
    :type protocol type in string or list
    :param iif:
    :type incoming interface as string or list
    :param oif:
    :type outgoing interface as list or string
    :param ttl:
    :type ttl value as list or string
    :param uptime
    :type uptime in list or string
    :param vrf
    :type vrfname as list or string
    :return:

    Usage
    pim.verify_ip_mroute(data.dut1,source='10.10.10.1',group='225.1.1.1',proto='STATIC',iif='Ethernet10',
                                       oif='Ethernet12',ttl='1',vrf='default')
    pim.verify_ip_mroute(data.dut1,source=['10.10.10.1','20.20.20.1'],group=['225.1.1.1','232.0.0.1'],proto=['STATIC','STATIC']
                                    ,iif=['Ethernet10','Ethernet5'] , oif=['Ethernet12','Ethernet12'],ttl=['1','1'],vrf=['default','RED'])
    """
    st.log('API_NAME: verify_ip_mroute, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    ret_val = True
    cmd = ''
    if 'vrf' in kwargs:
        vrf = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf = 'default'

    skip_tmpl = kwargs.pop('skip_tmpl', False)

    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False
    if cli_type in get_supported_ui_type_list():
        if vrf == 'all' or 'return_output' in kwargs:
            cli_type = 'klish'
        if 'proto' in kwargs or 'ttl' in kwargs:
            cli_type='klish'
    if cli_type in get_supported_ui_type_list():
        installed = make_list(kwargs.get('installed',None))
        source = make_list(kwargs.get('source',None))
        group = make_list(kwargs.get('group',None))
        iif = make_list(kwargs.get('iif',None))
        oif = make_list(kwargs.get('oif',None))
        uptime = make_list(kwargs.get('uptime',None))
        if not source or not group:
            st.error("'source' and 'group' must be provided for 'show ip mroute' validation through gnmi")
            return False
        mroute_attr_dict = {'iif':['IncomingInterface',iif],
                              'installed':['Installed',installed],
                            'oif':['OutgoingInterface',oif],'uptime':['Uptime',uptime]}
        i = 0
        for ea_grp, ea_src in zip(group,source):
            ni_obj = umf_ni.NetworkInstance(Name=vrf)
            ipv4_entries_obj = umf_ni.Ipv4MulticastIpv4Entry(GroupAddress=ea_grp,NetworkInstance=ni_obj)
            ipv4_src_entries_obj = umf_ni.Ipv4MulticastSrcEntry(SourceAddress=ea_src,Ipv4MulticastIpv4Entry=ipv4_entries_obj)
            ipv4_OifInfo_obj = None
            for key, attr_value in mroute_attr_dict.items():
                attr_val = None if attr_value[1][i] == 'none' else attr_value[1][i]
                if key in kwargs and attr_val is not None:
                    if key == 'iif':
                        setattr(ipv4_src_entries_obj, attr_value[0], attr_value[1][i])
                    if key == 'installed':
                        attr_val = 'True' if attr_value[1][i] == '*' else None
                        setattr(ipv4_src_entries_obj, attr_value[0], attr_val)
                    if key in ['oif','uptime']:
                        ipv4_OifInfo_obj = umf_ni.OifInfo(OutgoingInterface=attr_value[1][i],Ipv4MulticastSrcEntry=ipv4_src_entries_obj)
                        setattr(ipv4_OifInfo_obj, attr_value[0], attr_value[1][i])
            i += 1
            result1 = ipv4_src_entries_obj.verify(dut, target_path='state', match_subset=True, cli_type=cli_type)
            if not result1.ok():
                st.log('test_step_failed: Verify show ip pim interface output {}'.format(result1.data))
                ret_val = False
            if ipv4_OifInfo_obj:
                result2 = ipv4_OifInfo_obj.verify(dut, target_path='state', match_subset=True, cli_type=cli_type)
                if not result2.ok():
                    st.log('test_step_failed: Verify show ip pim interface output {}'.format(result2.data))
                    ret_val = False

    if cli_type in ['rest-patch', 'rest-put'] and vrf == 'all':
        cli_type = 'klish'

    if cli_type in ['click', 'klish']:
        if vrf != 'default':
            cmd = 'show ip mroute vrf {}'.format(vrf)
        else:
            cmd = 'show ip mroute'

    elif cli_type in ['rest-patch', 'rest-put']:
        vrf_command = 'default' if vrf == 'default' else '{}'.format(vrf)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['pim_mroute'].format(name=vrf_command)
        res = get_rest(dut, http_method=cli_type, rest_url=url)
        if res:
            if 'return_output' in kwargs:
                output = res['output']
            else:
                if len(res['output']) == 0 or "ietf-restconf:errors" in res['output']:
                    st.error("DUT Failed to display the Output")
                    return False
                else:
                    output = convert_pim_rest_output(res['output'], type='mroute')
    if cli_type == 'click':
        cli_type = 'vtysh'

    if cli_type in ['vtysh', 'klish']:
        output = st.show(dut, cmd, skip_error_check=skip_error, skip_tmpl=skip_tmpl, type=cli_type)

    if cli_type in ['vtysh', 'klish','rest-patch', 'rest-put']:
        if 'return_output' in kwargs:
            return output

        if len(output) == 0:
            st.error("Output is Empty")
            return False

        #Converting all kwargs to list type to handle single or list of mroute instances
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        input_dict_list =[]
        if cli_type in ['klish']:
            kwargs.pop('proto', None)
            kwargs.pop('installed', None)
            if 'iif' in kwargs:
                for i in range(0, len(kwargs['iif'])):
                    if kwargs['iif'][i] == 'none':
                        kwargs['iif'][i] = '-'
        if cli_type in ['rest-patch', 'rest-put']:
            kwargs.pop('proto', None)
            kwargs.pop('installed', None)
            if 'iif' in kwargs:
                for i in range(0, len(kwargs['iif'])):
                    if kwargs['iif'][i] == 'none':
                        kwargs['iif'].remove('none')
                if len(kwargs['iif']) == 0:
                    del kwargs['iif']
        for i in range(len(kwargs[list(kwargs.keys())[0]])):
            temp_dict = {}
            for key in list(kwargs.keys()):
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if not entries:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False
    return ret_val


def verify_pim_show(dut, **kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut
    :type string
    :param cmd_type
    :type string (CLI type)


    :API type: "show ip pim neighbor"
    :arg_list: interface,neighbor,dr_priority,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,interface=['Ethernet24','Ethernet10'],neighbor=['10.10.10.2','10.10.10.3'],dr_priority=['10','20'],vrf='RED',cmd_type='neighbor')
    pim.verify_pim_show(dut1,interface='Ethernet24',neighbor='10.10.10.2',dr_priority='10',vrf='RED',cmd_type='neighbor')



    :API type: "show ip pim interface"
    :arg_list: interface,state,address,nbr_count,dr,fhrif_channels,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='interface',interface=['Ethernet24','pimreg'],state=['up']*2,address=['10.10.10.1','0.0.0.0'],
                                nbr_count=[1,0],dr=['10.10.10.2','local'],fhr=[0,0],if_channels=[0,0],vrf='default')
    pim.verify_pim_show(dut1,cmd_type='interface',interface='Ethernet24',state='up',address='10.10.10.1',nbr_count=1,dr='10.10.10.2',fhr=0,if_channels=0)



    :API type: "show ip pim state "
    :arg_list:source,group,iif,flag,installed'
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,type='state',source='10.10.10.2',group='232.1.1.2',iif='Ethernet24',oif=[['Ethernet10','Vlan100']],flag=[['IJ'],['J']])



    :API type: "show ip pim interface traffic "
    :arg_list:interface,vrf,hello_rx,hello_tx,join_rx,join_tx,prune_rx,prune_tx,register_rx,register_tx,register_stop_tx,register_stop_rxassert_rxassert_tx,vrf
    :arg_type: String or list
    :Usage:
     pim.verify_pim_show(dut1,cmd_type='interface traffic',interface='Ethernet24',vrf='default',hello_rx=32,hello_tx=32,join_rx=0,join_tx=0,
                                      prune_rx=0,prune_tx=0,register_rx=0,register_tx=0,register_stop_tx=0,
                                      register_stop_rx=0,assert_rx=0,assert_tx=0)


    :API type: "show ip pim nexthop"
    :arg_list: source,interface,nexthop,registered_count,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='nexthop',source=['10.10.10.2'],interface=['Ethernet24'],nexthop=['10.10.10.2'],registered_count=1)



    :API type: "show ip pim assert "
    :arg_list: interface,address,source,group,state,winner,uptime,timer,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='assert',interface=[],address=[],source=[],group=[],state=[],winner=[],uptime=[],timer=[])
    pim.verify_pim_show(dut1,cmd_type='assert',interface='',address='',source='',group='',state='',winner='',uptime='',timer='')


    :API type: "show ip pim assert-internal "
    :arg_list: interface,address,source,group,ca,eca,atd,eatd,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='assert-internal',interface=[],address=[],source=[],group=[],ca=[],eca=[],atd=[],eatd=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='assert-internal',interface='',address='',source='',group='',ca='',eca='',atd='',eatd='')


    :API type: "show ip pim assert-metric "
    :arg_list: interface,address,source,group,rpt,pref,metric,address2,vrf
    :arg_type:
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='assert-metric',interface='',address='',source='',group='',rpt='',pref='',metric='',address2='',vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='assert-metric',interface=[],address=[],source=[],group=[],rpt=[],pref=[],metric=[],address2=[],vrf='RED')



    :API type: "show ip pim assert-winner-metric "
    :arg_list: interface,address,source,group,rpt,pref,metric,address2,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='assert-winner-metric',interface='',address='',source='',group='',rpt='',pref='',metric='',address2='',vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='assert-winner-metric',interface=[],address=[],source=[],group=[],rpt=[],pref=[],metric=[],address2=[],vrf='RED')


    :API type: "show ip pim upstream "
    :arg_list: iif,source,group,state,uptime,jointimer,rstimer,katimer,refcnt,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='upstream',source=[],group=[],state=[],uptime=[],jointimer=[],rstimer=[],katimer=[],refcnt=[],vrf='default')
    pim.verify_pim_show(dut1,cmd_type='upstream',source='',group='',state='',uptime='',jointimer='',rstimer='',katimer='',refcnt='',vrf='RED')


    :API type: "show ip pim upstream-join-desired "
    :arg_list: interface,source,group,lostassert,joins,piminclude,joindesired,evaljd,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='upstream-join-desired',interface=[],source=[],group=[],lostassert=[],joins=[],piminclude=[],joindesired=[],evaljd=[],vrf='default')
    pim.verify_pim_show(dut1,cmd_type='upstream-join-desired',interface='',source='',group='',lostassert='',joins='',piminclude='',joindesired='',evaljd='',vrf='RED')


    :API type: "show ip pim upstream-rpf "
    :arg_list: source,group,rpfiface,ribnexthop,rpfaddress,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='upstream-rpf',source=[],group=[],rpfiface=[],ribnexthop=[],rpfaddress=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='upstream-rpf',source='',group='',rpfiface='',ribnexthop='',rpfaddress='',vrf='default')

    :API type: "show ip pim join "
    :arg_list: interface,address,source,group,state,uptime,expire,prune,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='join',interface=[],address=[],source=[],group=[],state=[],uptime=[],expire=[],prune=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='join',interface='',address='',source='',group='',state='',uptime='',expire='',prune='',vrf='RED')

    :API type: "show ip pim secondary "
    :arg_list: interface,address,neighbor,secondary,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='secondary',interface=[],address=[],neighbor=[],secondary=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='secondary',interface='',address='',neighbor='',secondary='',vrf='RED')

    :API type: "show ip pim local-membership "
    :arg_list: interface,address,source,group,membership,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='local-membership',interface=[],address=[],source=[],group=[],membership=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='local-membership',interface='',address='',source='',group='',membership='',vrf='RED')

    :API type: "show ip pim rpf"
    :arg_list: cache_ref_delay,cache_ref_timer,cache_ref_reqs,cache_ref_events,cache_ref_last,nexthop_lookup,nexthop_lookup_avoid,
                source,group,rpfiface,ribnexthop,rpfaddress,metric,pref,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='rpf',cache_ref_delay='',cache_ref_timer='',cache_ref_reqs=''
                        ,cache_ref_events='',cache_ref_last='',nexthop_lookup='',nexthop_lookup_avoid=''
                         source=[],group=[],rpfiface=[],ribnexthop=[],rpfaddress=[],metric=[],pref=[],vrf='RED')

    :API type: "show ip pim rp mapping "
    :arg_list: rp_address,group_prefix_list,rp_mode,rp_version,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='rp mapping',rp_address=[],rp_mode=[],rp_version=[],group_prefix_list=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='rp mapping',rp_address='',rp_mode='',rp_version='',group_prefix_list='',vrf='RED')

    :API type: "show ip pim rp"
    :arg_list: rp,group,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='rp',rp=[],group=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='rp',rp='',group='',vrf='RED')

    :API type: "show ip pim rp-info "
    :arg_list: rp_address,group_prefix_list,oif,i_am_rp,source,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='rp-info',rp_address=[],group_prefix_list=[],oif=[],i_am_rp=[],source=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='rp-info',rp_address='',group_prefix_list='',oif='',i_am_rp='',source='',vrf='RED')

    """
    st.log('API_NAME: verify_pim_show, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    ret_val = True
    cmd = ''
    if 'cmd_type' in kwargs:
        cmd_type = kwargs['cmd_type']
        del kwargs['cmd_type']
    else:
        cmd_type = 'neighbor'



    if cli_type in get_supported_ui_type_list():
        vrf_name = kwargs.get('vrf', 'default')
        if cmd_type == 'interface traffic':
            cli_type = 'click'
        if vrf_name == 'all' or cmd_type == 'rpf' or 'return_output' in kwargs or 'interface' not in kwargs:
            cli_type = 'klish'
        if cmd_type in ['state', 'upstream', 'join']:
            return verify_topology(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        interface = make_list(kwargs.get('interface', None))
        neighbor = make_list(kwargs.get('neighbor', None))
        uptime = make_list(kwargs.get('uptime', None))
        holdtime = make_list(kwargs.get('holdtime', None))
        dr_priority = make_list(kwargs.get('dr_priority', None))
        bfd_status = make_list(kwargs.get('bfd_status', None))
        neighbr_attr_dict = {'uptime': ['NeighborEstablished', uptime],'dr_priority': ['DrPriority', dr_priority],
                           'bfd_status': ['BfdSessionStatus', bfd_status],'holdtime':['NeighborExpires',holdtime]}
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        pim_obj = umf_ni.Protocol(ProtoIdentifier='PIM', Name='pim', NetworkInstance=ni_obj)
        if cmd_type == 'neighbor':
            pass
        elif len(cmd_type) > 0 and 'neighbor' in cmd_type:
            neighbor = make_list(cmd_type.split(' ')[1])
        i=0
        for ea_intf,ea_neighbr in zip(interface,neighbor):
            PimInterface_obj = umf_ni.PimInterface(InterfaceId=ea_intf,Protocol=pim_obj)
            InterfaceNeighbor_obj = umf_ni.InterfaceNeighbor(NeighborAddress=ea_neighbr,PimInterface=PimInterface_obj)
            for key, attr_value in neighbr_attr_dict.items():
                if key in kwargs and attr_value[1] is not None:
                    if key == 'bfd_status':
                        bfd_attr_val = (attr_value[1][i].replace(' ', '_')).upper() if re.search(r' ',attr_value[1][i]) else attr_value[1][i].upper()
                        setattr(InterfaceNeighbor_obj, attr_value[0], bfd_attr_val)
                    else:
                        setattr(InterfaceNeighbor_obj, attr_value[0], attr_value[1][i])
            i += 1
            result1 = InterfaceNeighbor_obj.verify(dut, target_path='state', match_subset=True, cli_type=cli_type)
            if not result1.ok():
                st.log('test_step_failed: Verify show ip pim output {}'.format(result1.data))
                ret_val = False

    cli_type = 'click' if cmd_type == 'interface traffic' else cli_type

    if cli_type in ['rest-patch', 'rest-put'] and kwargs.get('vrf') == 'all':
        cli_type = 'klish'

    if cli_type in ['klish', 'rest-patch', 'rest-put'] and cmd_type in ['state', 'upstream', 'join']:
        return verify_topology(dut, **kwargs)

    if cli_type in ['rest-patch', 'rest-put'] and cmd_type == 'rpf':
        cli_type='klish'

    kwargs.pop('cli_type', None)

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

    if cli_type in ['click', 'klish']:
        if 'interface' in kwargs and cli_type =='click':
            if type(kwargs['interface']) is list:
                kwargs['interface'] = [get_intf_short_name(item) for item in kwargs['interface']]
            else:
                kwargs['interface'] = get_intf_short_name(kwargs['interface'])
        if vrf_name != 'default':
            cmd = 'show ip pim vrf {} {}'.format(vrf_name, cmd_type)
        else:
            cmd = "show ip pim {}".format(cmd_type)

    elif cli_type in ['rest-patch', 'rest-put']:
        vrf_command = 'default' if vrf_name == 'default' else '{}'.format(vrf_name)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        output = []
        if cmd_type == 'neighbor':
            url = rest_urls['pim_neighbor'].format(name=vrf_command, identifier='PIM', name1='pim')
            res = get_rest(dut, http_method=cli_type, rest_url=url)
            if res:
                if 'return_output' in kwargs:
                    output = res['output']
                else:
                    if len(res['output']) == 0 or "ietf-restconf:errors" in res['output']:
                        st.error("DUT Failed to display the Output")
                        return False
                    else:
                        output = convert_pim_rest_output(res['output'], type='neighbor')
        elif len(cmd_type) > 0:
            intf = kwargs.pop('interface')
            ip = cmd_type.split(' ')[1]
            url = rest_urls['pim_neighbor_lvl'].format(name=vrf_command, identifier='PIM', name1='pim', ifname=intf, neighborip=ip)
            res = get_rest(dut, http_method=cli_type, rest_url=url)
            if res:
                if len(res['output']) == 0 or "ietf-restconf:errors" in res['output']:
                    st.error("DUT Failed to display the Output")
                    return False
                else:
                    output = convert_pim_rest_output(res['output'], type='neighbor_lvl')

    if cli_type == 'click':
        cli_type = 'vtysh'

    if cli_type in ['vtysh', 'klish']:
        output = st.show(dut, cmd, type=cli_type, skip_error_check=skip_error, skip_tmpl=skip_tmpl)

    if cli_type in ['vtysh', 'click', 'klish', 'rest-patch', 'rest-put']:
        if 'return_output' in kwargs:
            return output

        if len(output) == 0:
            st.error("Output is Empty")
            return False

        common_param = ['registered_count', 'cache_ref_delay', 'cache_ref_timer', 'cache_ref_reqs', 'cache_ref_events',\
                        'cache_ref_last', 'nexthop_lookup', 'nexthop_lookup_avoid']
        for key in common_param:
            if key in kwargs:
                if str(kwargs[key]) != str(output[0][key]):
                    st.error("Match not Found for {}: Expected - {} Actual- {}".format(key, kwargs[key], output[0][key]))
                    ret_val = False
                else:
                    st.log("Match Found for {}: Expected - {} Actual- {}".format(key, kwargs[key], output[0][key]))
                del kwargs[key]

        if cmd_type == 'state':
            for entry in output:
                entry_index = output.index(entry)
                if entry['oif'] != '':
                    pattern = re.compile(r'\w+')
                    result = pattern.findall(entry['oif'])
                    res = result[::2] + result[1::2]
                    oif_list = [str(oif) for oif in res[:len(res) / 2]]
                    flag_list = [str(flag) for flag in res[len(res) / 2:]]
                    output[entry_index]['oif'] = oif_list
                    output[entry_index]['flag'] = flag_list
        #Converting all kwargs to list type to handle single or list of mroute instances
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        input_dict_list =[]
        if cli_type in ['rest-patch', 'rest-put']:
            if 'bfd_status' in kwargs:
                if kwargs['bfd_status'] == ['Admin Down']:
                    kwargs['bfd_status'] = ['Admin_down']

        if len(kwargs.keys()) == 0:
            return True

        for i in range(len(kwargs[list(kwargs.keys())[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if not entries:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val

def verify_pim_neighbor_detail(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param interface:
    :type string or list of PIM interfaces
    :param neighbor
    :type string or list of neighbors
    :param:uptime
    :type string or list
    :param holdtime
    :type string or list
    :param dr_priority
    :type string or list
    :param gen_id
    :type string or list
    :param override_interval
    :type string or list
    :param propogation delay
    :type string or list
    :param hello_addr_list
    :type string or list
    :param hello_dr_priority
    :type string or list
    :param hello_gen_id
    :type string or list
    :param hello_holdtime
    :type string or list
    :param hello_lan_prune_delay
    :type string or list
    :param hello_t_bit
    :type string or list
    :param vrf
    :type string
    :return:

    Usage
    pim.verify_pim_neighbor_detail(dut1,neighbor=['10.10.10.2','20.20.20.2'],interface=['Ethernet24','Ethernet32'])
    pim.verify_pim_neighbor_detail(dut1,neighbor='10.10.10.2',interface='Ethernet24')
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    ret_val = True
    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    #Converting all kwargs to list type to handle single or list of mroute instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    if len(kwargs['neighbor']) > 1:
        if vrf_name == 'default':
            cmd = "show ip pim neighbor detail"
        else:
            cmd = "show ip pim vrf {} neighbor detail".format(vrf_name)
    else:
        if cli_type in ['click', 'klish', 'rest-patch', 'rest-put']:
            if vrf_name == 'default':
                cmd = "show ip pim neighbor {}".format(kwargs['neighbor'][0])
            else:
                cmd = "show ip pim vrf {} neighbor {}".format(vrf_name, kwargs['neighbor'][0])

    skip_tmpl = kwargs.pop('skip_tmpl', False)
    if 'skip_error' in kwargs:
        skip_error = kwargs.get('skip_error')
    else:
        skip_error = False
    if cli_type == 'click':
        cli_type = 'vtysh'
    output = st.show(dut, cmd, skip_error_check=skip_error, skip_tmpl=skip_tmpl, type='vtysh')

    if 'return_output' in kwargs:
        return output
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    for i in range(len(kwargs['neighbor'])):
        nbr_index = None
        st.log("Validation for PIM neighbor : {}".format(kwargs['neighbor'][i]))
        for peer_info in output:
            if str(peer_info['neighbor']) == str(kwargs['neighbor'][i]):
                nbr_index = output.index(peer_info)
        if nbr_index is not None:
            #Iterate through the user parameters
            for k in kwargs.keys():
                if str(output[nbr_index][k]) == str(kwargs[k][i]):
                    st.log('Match Found for {} :: Expected: {}  Actual : {}'.format(k,kwargs[k][i],output[nbr_index][k]))
                    ret_val=True
                else:
                    st.error('Match Not Found for {} :: Expected: {}  Actual : {}'.format(k,kwargs[k][i],output[nbr_index][k]))
                    return False
        else:
            st.error(" PIM neighbor {} not in output".format(kwargs['neighbor'][i]))
            return False

    return ret_val


def verify_pim_interface_detail(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param interface:
    :type  String or list
    :param state
    :type String or list
    :param primary_addr
    :type String or list
    :param secondary_addr
    :type list of list
    :param pim_nbr
    :type String or list
    :param nbr_state
    :type String or list
    :param nbr_uptime
    :type String or list
    :param nbr_expiry_timer
    :type String or list
    :param dr_addr
    :type String or list
    :param dr_priority
    :type String or list
    :param dr_priority_local
    :type String or list
    :param dr_changes
    :type String or list
    :param period
    :type String or list
    :param timer
    :type String or list
    :param stat_start
    :type String or list
    :param receive
    :type String or list
    :param receive_failed
    :type String or list
    :param send
    :type String or list
    :param send_failed
    :type String or list
    :param gen_id
    :type String or list
    :param all_multicast
    :type String or list
    :param broadcast
    :type String or list
    :param deleted
    :type String or list
    :param ifindex
    :type String or list
    :param multicast
    :type String or list
    :param multicast_loop
    :type String or list
    :param promiscuous
    :type String or list
    :param lan_delay
    :type String or list
    :param eff_propogation_delay
    :type String or list
    :param eff_override_interval
    :type String or list
    :param join_prune_override_interval
    :type String or list
    :param propogation_delay
    :type String or list
    :param propogation_delay_high
    :type String or list
    :param override_interval
    :type String or list
    :param override_interval_high
    :type String or list
    :param vrf
    :type String
    :return:

    Usage
    pim.verify_pim_interface_detail(dut1,interface=['Ethernet24','Ethernet32'],state=['up','up'],primar_addr=['10.10.10.1','20.20.20.1'],
                                    secondary_addr=[['fe80::3e2c:99ff:fea6:fba0/64'],['fe80::3e2c:99ff:fea6:fba0/64']])
    pim.verify_pim_interface_detail(dut1,interface='Ethernet24',primary_addr='10.10.10.1',secondary_addr=[['fe80::3e2c:99ff:fea6:fba0/64']])
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    ret_val = True
    cmd = ''
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

    skip_tmpl = kwargs.pop('skip_tmpl', False)

    #Converting all kwargs to list type to handle single or list of mroute instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    cli_type= 'click' if kwargs.get('interface') == ['detail'] else cli_type
    if len(kwargs['interface']) > 1:
        if vrf_name == 'default':
            cmd = "show ip pim interface detail"
        else:
            cmd = "show ip pim vrf {} interface detail".format(vrf_name)
    else:
        if vrf_name == 'default':
            cmd = "show ip pim interface {}".format(kwargs['interface'][0])
        else:
            cmd = "show ip pim vrf {} interface {}".format(vrf_name, kwargs['interface'][0])

    if cli_type in ['rest-patch', 'rest-put']:
        rest_urls=st.get_datastore(dut, 'rest_urls')
        url = rest_urls['pim_intf_lvl'].format(name=vrf_name, identifier='PIM', name1='pim', ifname=kwargs['interface'][0])
        res =get_rest(dut, http_method=cli_type, rest_url=url)
        if res:
            if len(res['output']) == 0 or "ietf-restconf:errors" in res['output']:
                st.error("DUT Failed to display the Output")
                return False
            else:
                output = convert_pim_rest_output(res['output'], type='intflvl')
    if cli_type in get_supported_ui_type_list():
        if 'state' in kwargs:
            cli_type = 'klish'
        if 'return_output' in kwargs:
            cli_type = 'klish'
    if cli_type in get_supported_ui_type_list():
        address = kwargs.get('address',None)
        nbr_count = kwargs.get('nbr_count',None)
        dr = kwargs.get('dr',None)
        hello_intvl = kwargs.get('hello_intvl',None)
        dr_priority = kwargs.get('dr_priority',None)
        pim_intf_attr_dict = {'address':['LocalAddress', address],'nbr_count':['NbrsCount',nbr_count],
                              'dr':['DrAddress',dr],'hello_intvl':['HelloInterval',hello_intvl],'dr_priority':['DrPriority',dr_priority]}
        port_hash_list = segregate_intf_list_type(intf=kwargs['interface'], range_format=False)
        intf_list = port_hash_list['intf_list_all']
        i=0
        for ifname in intf_list:
            ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
            pim_obj = umf_ni.Protocol(ProtoIdentifier='PIM', Name='pim', NetworkInstance=ni_obj)
            intf_pim_obj = umf_ni.PimInterface(InterfaceId=ifname, Protocol=pim_obj)
            for key, attr_value in pim_intf_attr_dict.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(intf_pim_obj, attr_value[0], attr_value[1][i])
            i+=1
            result=intf_pim_obj.verify(dut,target_path='state',match_subset=True,cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Verify show ip pim interface output {}'.format(result.data))
                return False
    if cli_type == 'click':
        cli_type='vtysh'
    if cli_type in ['vtysh', 'klish']:
        output = st.show(dut, cmd, type=cli_type, skip_error_check=skip_error,skip_tmpl=skip_tmpl)

    if cli_type in ['vtysh', 'klish','rest-patch', 'rest-put']:
        if 'return_output' in kwargs:
            return output
        if len(output) == 0:
            st.error("Output is Empty")
            return False

        for i in range(len(kwargs['interface'])):
            nbr_index = None
            st.log("Validation for PIM interface : {}".format(kwargs['interface'][i]))
            for peer_info in output:
                if str(peer_info['interface']) == str(kwargs['interface'][i]):
                    nbr_index = output.index(peer_info)
            if nbr_index is not None:
                #Iterate through the user parameters
                for k in kwargs.keys():
                    if str(output[nbr_index][k]) == str(kwargs[k][i]):
                        st.log('Match Found for {} :: Expected: {}  Actual : {}'.format(k,kwargs[k][i],output[nbr_index][k]))
                        ret_val=True
                    else:
                        st.error('Match Not Found for {} :: Expected: {}  Actual : {}'.format(k,kwargs[k][i],output[nbr_index][k]))
                        return False
            else:
                st.error(" PIM Interface {} not in output".format(kwargs['interface'][i]))
                return False

    return ret_val


def verify_pim_nexthop_lookup(dut,**kwargs):
    """

    :param dut:
    :param source
    :type string
    :param group
    :type string
    :param interface
    :type string
    :param vrf
    :type string
    :return:
    """
    ret_val = True
    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    if 'source' not in kwargs or 'group' not in kwargs:
        st.error("Mandatory arguments -source or -group Missing")
        return False

    if vrf_name != 'default':
        cmd = 'show ip pim vrf {} nexthop-lookup {} {}'.format(vrf_name,kwargs['source'],kwargs['group'])
    else:
        cmd = "show ip pim nexthop-lookup {} {}".format(kwargs['source'],kwargs['group'])

    output = st.show(dut,cmd, type='vtysh')
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for key in kwargs:
        if str(kwargs[key]) != str(output[0][key]):
            st.error("Match not found for {} : Expected- {} Actual - {}".format(key,kwargs[key],output[0][key]))
            ret_val = False
        else:
            st.log("Match found for {} : Expected- {} Actual - {}".format(key, kwargs[key], output[0][key]))
    return ret_val

def verify_pim_ssm_range(dut,group_range='232.0.0.0/8',vrf='default',return_output='no'):
    """
    :param dut:
    :param group_range:
    :param vrf:
    :return:

    Usage:
    pim.verify_pim_ssm_range(dut1,group_range='224.0.0.0/8')
    """

    if vrf == 'default':
        cmd = 'show ip pim group-type'
    else:
        cmd = 'show ip pim vrf {} group-type'.format(vrf)

    output = st.show(dut,cmd, type='vtysh')
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if return_output == 'yes':
        return output

    if str(output[0]['ssm_group_range']) == group_range:
        st.log("Match Found for SSM group range :Expected- {} Actual-{}".format(group_range,output[0]['ssm_group_range']))
    else:
        st.error("Match Not Found for SSM group range: Expected- {} Actual-{}".format(group_range,output[0]['ssm_group_range']))
        return False

def verify_pim_group_type(dut,group,group_type,vrf='default',return_output='no'):
    """
    :param dut:
    :param group_id:
    :param vrf_name:
    :param return_output:
    :return:

    Usage:
    pim.verify_pim_group_type(dut1,group='224.1.1.1',group_type='ASM')
    """

    if vrf == 'default':
        cmd = 'show ip pim group-type {}'.format(group)
    else:
        cmd = 'show ip pim vrf {} group-type {}'.format(vrf,group)

    output = st.show(dut,cmd, type='vtysh')
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if return_output == 'yes':
        return output

    if output[0]['group_type'] == group_type:
        st.log("Match Found for Group Type for {} :Expected- {} Actual-{}".format(group,group_type,output[0]['group_type']))
    else:
        st.error("Match Not Found for Group Type for {} :Expected- {} Actual-{}".format(group,group_type,output[0]['group_type']))
        return False


def clear_mroute(dut, vrf='default', cli_type=''):
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
            cmd = "clear ip mroute"
        else:
            cmd = "clear ip mroute vrf {}".format(vrf)

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['clear_pim_mroute']
        config_data= {"sonic-ipmroute-clear:input": {"vrf-name": vrf, "address-family": "IPV4_UNICAST", "config-type": "ALL-MROUTES", "all-mroutes": True}}
        if not config_rest(dut, rest_url=url, http_method='post', json_data=config_data):
            st.error("Failed to Clear the Mroute")
            return False
        return True

    if cli_type == 'click':
        cli_type = 'vtysh'
    if cli_type in ['vtysh', 'klish']:
        st.config(dut, cmd, type=cli_type, conf=False)


def clear_pim_traffic(dut,vrf='default'):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param vrf:
    :return:
    """

    if vrf == 'default':
        cmd = "clear ip pim interface traffic"
    else:
        cmd = "clear ip pim vrf {} interface traffic".format(vrf)

    st.config(dut, cmd, type='vtysh', conf=False)

def clear_pim_interfaces(dut, vrf='default', cli_type=''):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param vrf:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in ['click', 'klish']:
        if vrf == 'default':
            cmd = "clear ip pim interfaces"
        else:
            cmd = "clear ip pim vrf {} interfaces".format(vrf)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['clear_pim_intf']
        config_data = {"sonic-pim-clear:input": {"vrf-name": vrf, "address-family": "IPV4_UNICAST",
                                             "config-type": "ALL-INTERFACES", "all-interfaces": True,
                                             "all-oil": True}}
        if not config_rest(dut, rest_url=url, http_method='post', json_data=config_data):
            st.error("Failed to Clear the interfaces")
            return False
        return True

    if cli_type == 'click':
        cli_type = 'vtysh'
    if cli_type in ['vtysh', 'klish']:
        st.config(dut, cmd, type=cli_type, conf=False)


def clear_pim_oil(dut,vrf='default', cli_type= ''):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param vrf:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in ['click', 'klish']:
        if vrf == 'default':
            cmd = "clear ip pim oil"
        else:
            cmd = "clear ip pim vrf {} oil".format(vrf)

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['clear_pim_intf']
        config_data = {"sonic-pim-clear:input": {"vrf-name": vrf, "address-family": "IPV4_UNICAST","config-type": "ALL-INTERFACES", "all-interfaces": True,"all-oil": True}}
        if not config_rest(dut, rest_url=url, http_method='post', json_data=config_data):
            st.error("Failed to Clear the interfaces")
            return False
        return True
    if cli_type == 'click':
        cli_type = 'vtysh'
    if cli_type in ['vtysh', 'klish']:
        st.config(dut, cmd, type=cli_type, conf=False)

def debug_pim(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :return:

    Usage:
    +++++
    debug_pim('dut1',type_list=['events','nht','packet_dump','packets','trace','trace_detail','zebra'],direction='both',pkt_type='all')
    debug_pim(dut1)
    """


    if 'config' in kwargs:
        config = kwargs.get('config')
    else:
        config = 'yes'

    if config == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    cmd = ''

    if 'type_list' in kwargs:
        for type in kwargs['type_list']:
            if type == 'events':
                cmd +='{} debug pim events\n'.format(config_cmd)
            elif type == 'nht':
                cmd += '{} debug pim nht\n'.format(config_cmd)
            elif type == 'packet_dump':
                if 'direction' in kwargs:
                    direction = kwargs.get('direction')
                else:
                    direction = 'both'
                if direction != 'both':
                    cmd += '{} debug pim packet-dump {}\n'.format(config_cmd,direction)
                else:
                    cmd += '{0} debug pim packet-dump send\n{0} debug pim packet-dump receive\n'.format(config_cmd)
                    cmd += '{} debug pim packet-dump send\n'.format(config_cmd)
                    cmd += '{} debug pim packet-dump receive\n'.format(config_cmd)
            elif type == 'packets':
                if 'pkt_type' in kwargs:
                    pkt_type = kwargs.get('pkt_type')
                else:
                    pkt_type = 'all'
                if pkt_type != 'all':
                    cmd += '{} debug pim packets {}\n'.format(config_cmd,pkt_type)
                else:
                    cmd += '{0} debug pim packets hello\n{0} debug pim packets joins\n{0} debug pim packets register\n'.format(config_cmd)
                    cmd += '{} debug pim packets hello\n'.format(config_cmd)
                    cmd += '{} debug pim packets joins\n'.format(config_cmd)
                    cmd += '{} debug pim packets register\n'.format(config_cmd)
            elif type == 'trace':
                cmd += '{} debug pim trace\n'.format(config_cmd)
            elif type == 'trace_detail':
                cmd += '{} debug pim trace detail\n'.format(config_cmd)
            elif type == 'zebra':
                cmd += '{} debug pim zebra\n'.format(config_cmd)
    else:
        cmd += '{} debug pim'.format(config_cmd)
    st.config(dut,cmd, type='vtysh',conf=False)


def debug_mroute(dut,type=None):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param type:
    :return:
    """
    if type is None:
        cmd = 'debug mroute'
    else:
        cmd = 'debug mroute detail'

    st.config(dut,cmd, type='vtysh', conf=False)

def verify_ip_mroute_appdb(dut, source, group, **kwargs):
    """
    Author : Kiran Kumar K
    :param : source:
    :type : address
    :param : group:
    :type : address
    :type : interface name
    :return:
    :type: bool
    """
    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    if vrf_name != 'default':
        key = "IPMC_ROUTE_TABLE:{}|{}|{}".format(vrf_name, source, group)
    else:
        key = "IPMC_ROUTE_TABLE:{}|{}".format(source, group)
    print(key)
    command = redis.build(dut, redis.APPL_DB, "hgetall \"{}\"".format(key))
    print(command)
    output = st.show(dut, command)
    print(output)
    st.debug(output)

    if len(output) == 0:
        return False

    for each in kwargs.keys():
        print(each)
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def verify_intf_mcast_mode_in_appdb(dut, in_intf, **kwargs):
    """
    Author : Kiran Kumar K
    :param : in_intf:
    :type : interface name
    :return:
    :type: bool
    """

    key = "INTF_TABLE:{}".format(in_intf)
    print(key)
    command = redis.build(dut, redis.APPL_DB, "hgetall {}".format(key))
    print(command)
    output = st.show(dut, command)
    print(output)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def verify_asic_mroute(dut, **kwargs):
    """
    Author :Priyanka Gupta
    :return:
    :type: bool
    """
    output = asic_show(dut, 'ipmc table show')
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def verify_mroute_debugcommand(dut, **kwargs):
    """
    Author :Priyanka Gupta
    :return:
    :type: bool
    """
    command = "show debug ipmcorch all"
    output = st.show(dut, command)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def mtrace(dut,**kwargs):
    """
    Author : Sooriya G
    :param dut:
    :param source:
    :param group
    :return:
    """

    if 'source' not in kwargs or 'group' not in kwargs:
        st.error("Mandatory argument -source or -group is missing")
        return False
    source = kwargs['source']
    group = kwargs['group']
    cmd = 'mtrace {} {}'.format(source, group)
    output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True, type='vtysh')
    return output

def verify_ip_multicast(dut,**kwargs):
    """
    Author: Nagappa
    email : nagappa.chincholi@broadcom.com
    :param dut:
    :param source:
    :param vrf
    :type vrfname as list or string
    :return:

    Usage
    pim.verify_ip_multicast(data.dut1,tot_dyn_mcast_routes='10',join_prune_holdtime='150',upstream_join_timer='70',vrf='default')
    """

    ret_val = True
    if 'vrf' in kwargs:
        vrf = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf = 'default'

    if vrf != 'default':
        cmd = 'show ip multicast vrf {}'.format(vrf)
    else:
        cmd = 'show ip multicast'

    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False

    output = st.show(dut, cmd, skip_error_check=skip_error, type='vtysh')

    if 'return_output' in kwargs:
        return output

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    #Converting all kwargs to list type to handle single or list of mroute instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[list(kwargs.keys())[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val


def grep_total_count(dut,**kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    ret_val = True
    grep_val = kwargs['grep']
    cmd = kwargs['cmd']
    output = st.show(dut,"sudo vtysh -c '{}' | grep {} | wc -l".format(cmd,grep_val),skip_tmpl=True)
    actual_count = int(output.split('\n')[0])
    exp_count = int(kwargs['exp_count'])

    if actual_count != exp_count:
        st.error("Count Mismatch:  Expected-{} Actual-{}".format(exp_count,actual_count))
        ret_val = False
    return ret_val

def verify_topology(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    st.log('API_NAME: verify_topology, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    ret_val = True
    cmd = ''
    vrf = kwargs.pop('vrf', 'default')
    skip_error = kwargs.pop('skip_error', False)
    kwargs.pop('state', None)
    kwargs.pop('flag', None)
    kwargs.pop('installed', None)
    if cli_type in get_supported_ui_type_list():
        if vrf == 'all' or 'return_output' in kwargs:
            cli_type = 'klish'
    if cli_type in get_supported_ui_type_list():
        iif = make_list(kwargs.get('iif',None))
        rpf_nbr = make_list(kwargs.get('rpf_nbr',None))
        source = make_list(kwargs.get('source', None))
        group = make_list(kwargs.get('group', None))
        uptime = make_list(kwargs.get('uptime',None))
        expires = make_list(kwargs.get('expires',None))
        oif = make_list(kwargs.get('oif', None))
        route_type = kwargs.get('route_type','SG')
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        pim_obj = umf_ni.Protocol(ProtoIdentifier='PIM', Name='pim', NetworkInstance=ni_obj)
        if not source or not group:
            st.error("'source' and 'group' must be provided for 'show ip pim topology' validation through gnmi")
            return False
        topo_attr_dict = {'iif':['IncomingInterface',iif],'rpf_nbr':['RpfNeighborAddress',rpf_nbr],
                          'uptime': ['Uptime', uptime],'expires':['Expiry',expires],
                          'oif':['OutgoingInterface',oif]}
        i = 0
        for ea_grp, ea_src in zip(group, source):
            TibIpv4Entry_obj = umf_ni.TibIpv4Entry(GroupAddress=ea_grp, Protocol=pim_obj)
            TibSrcEntry_obj = umf_ni.TibSrcEntry(SourceAddress=ea_src, RouteType=route_type,TibIpv4Entry=TibIpv4Entry_obj)
            OilInfoEntry_obj = None
            for key, attr_value in topo_attr_dict.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(TibSrcEntry_obj, attr_value[0], attr_value[1][i])
                    if key in ['oif','uptime','expires']:
                        oif_s = attr_value[1][i][0] if type(attr_value[1][i]) is list else attr_value[1][i]
                        OilInfoEntry_obj = umf_ni.OilInfoEntry(OutgoingInterface=oif_s, TibSrcEntry=TibSrcEntry_obj)
                        if key in ['uptime','expires']:
                            setattr(OilInfoEntry_obj, attr_value[0], attr_value[1][i])
            i += 1
            result1 = TibSrcEntry_obj.verify(dut, target_path='state', match_subset=True, cli_type=cli_type)
            if not result1.ok():
                st.log('test_step_failed: Verify show ip pim interface output {}'.format(result1.data))
                ret_val = False
            if OilInfoEntry_obj:
                result2 = OilInfoEntry_obj.verify(dut, target_path='state', match_subset=True, cli_type=cli_type)
                if not result2.ok():
                    st.log('test_step_failed: Verify show ip pim interface output {}'.format(result2.data))
                    ret_val = False

    if cli_type in ['rest-patch', 'rest-put'] and vrf == 'all':
        cli_type= 'klish'
    if cli_type == 'klish':
        if vrf != 'default':
            cmd = 'show ip pim vrf {} topology'.format(vrf)
        else:
            cmd = 'show ip pim topology'
        output = st.show(dut, cmd, type=cli_type, skip_error_check=skip_error)
    elif cli_type in ['rest-patch', 'rest-put']:
        vrf = 'default' if vrf == 'default' else '{}'.format(vrf)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['pim_topology'].format(name=vrf, identifier='PIM', name1='pim')
        res = get_rest(dut, http_method=cli_type, rest_url=url)
        if res:
            if 'return_output' in kwargs:
                return res['output']
            else:
                if len(res['output']) == 0 or "ietf-restconf:errors" in res['output']:
                    st.error("DUT Failed to display the Output")
                    return False
                else:
                    output = convert_pim_rest_output(res['output'], type='topology')
    if cli_type in ['vtysh', 'click', 'klish', 'rest-patch', 'rest-put']:
        if 'return_output' in kwargs:
            return output

        if len(output) == 0:
            st.error("Output is Empty")
            return False
        if 'interface' in kwargs:
            kwargs['oif'] = kwargs['interface']
        kwargs.pop('interface', None)

        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        input_dict_list =[]
        for i in range(len(kwargs[list(kwargs.keys())[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                if isinstance(kwargs[key][i], list):
                    temp_dict[key] = kwargs[key][i][0]
                else:
                    temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if not entries:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False
            else:
                st.log("DUT {} -> Match Found for {}".format(dut,input_dict))

    return ret_val


def convert_pim_rest_output(response, type):

    if type == 'neighbor':
        needed_output = response["openconfig-network-instance:interfaces"]['interface']
        output = list()
        for entry in needed_output:
            if entry.get("state"):
                temp = dict()
                if 'neighbors' in entry:
                    temp['interface'] = entry['state']['interface-id']
                    nbr_info = entry['neighbors']['neighbor']
                    for key in nbr_info:
                        temp['neighbor'] = key['neighbor-address'] if key.get('neighbor-address') else ''
                        temp['uptime'] = key['state']['neighbor-established'] if key['state'].get(
                            'neighbor-established') else ''
                        temp['holdtime'] = key['state']['neighbor-expires'] if key['state'].get('neighbor-expires') else ''
                        temp['dr_priority'] = str(key['state']['openconfig-pim-ext:dr-priority']) if key['state'].get(
                            'openconfig-pim-ext:dr-priority') else ''
                        output.append(temp)

    elif type == 'mroute':
        needed_output = response["openconfig-network-instance:ipv4-entries"]['ipv4-entry']
        output = list()
        for entry in needed_output:
            temp1 = entry['src-entries']['src-entry']
            for item in temp1:
                if item.get("state"):
                    temp = dict()
                    temp['group'] = entry['group-address'] if entry.get('group-address') else ''
                    temp['source'] = item['source-address']
                    temp['iif'] = item['state']['incoming-interface'] if item['state'].get('incoming-interface') else ''
                    temp['oif'] = item['oil-info-entries']['oif-info'][0]['outgoing-interface']
                    output.append(temp)

    elif type == 'topology':
        needed_output = response["openconfig-network-instance:tib"]['ipv4-entries']['ipv4-entry']
        output = []
        for entry in needed_output:
            if entry.get("state"):
                temp = dict()
                temp['group'] = entry['state']['group-address'] if entry['state'].get('group-address') else ''
                temp1 = entry['src-entries']['src-entry']
                for item in temp1:
                    temp2 = temp.copy()
                    temp2['source'] = item['state']['source-address'] if item['state'].get('source-address') else ''
                    temp2['iif'] = item['state']['incoming-interface'] if item['state'].get('incoming-interface') else ''
                    oil_info = item['oil-info-entries']['oil-info-entry']
                    for key in oil_info:
                        temp3 = temp2.copy()
                        temp3['oif'] = key['state']['outgoing-interface'] if key['state'].get('outgoing-interface') else ''
                        temp3['rpf_nbr'] = item['rpf-info']['state']['rpf-neighbor-address'] if item['rpf-info'][
                            'state'].get('rpf-neighbor-address') else ''

                        output.append(temp3)

    elif type == 'intflvl':
        needed_output = response['openconfig-network-instance:interface']
        output = list()
        for entry in needed_output:
            if entry.get("state"):
                temp = dict()
                temp['hello_intvl'] = str(entry['state']['hello-interval']) if entry['state'].get('hello-interval') else ''
                temp['interface'] = entry['state']['interface-id'] if entry['state'].get('interface-id') else ''
                temp['dr_priority_local'] = str(entry['state']['dr-priority']) if entry['state'].get('dr-priority') else ''
                temp['primary_addr'] = str(entry['state']['openconfig-pim-ext:local-address']) if entry['state'].get(
                    'openconfig-pim-ext:local-address') else ''
                temp['dr_addr'] = str(entry['state']['openconfig-pim-ext:dr-address']) if entry['state'].get(
                    'openconfig-pim-ext:dr-address') else ''
                temp['state'] = str(entry['state']['enabled']) if entry['state'].get('enabled') else ''
                output.append(temp)

    elif type == 'neighbor_lvl':
        needed_output = response['openconfig-network-instance:neighbor']
        output = list()
        temp = dict()
        for item in needed_output:
            if 'state' in item:
                temp['neighbor'] = item['neighbor-address'] if item.get("neighbor-address") else ""
                temp['dr_priority'] = str(item['state']['dr-priority']) if item['state'].get('dr-priority') else ''
                temp['uptime'] = item['state']['neighbor-established'] if item['state'].get('neighbor-established') else ''
                temp['holdtime'] = item['state']['neighbor-expires'] if item['state'].get('neighbor-expires') else ''
                temp['bfd_status'] = (item['state']['bfd-session-status']).capitalize() if item['state'].get('bfd-session-status') else ''
                output.append(temp)

    return output


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def verify_mroute_summary(dut,**kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    ret_val = True
    cmd = ''
    vrf = kwargs.pop('vrf', 'default')
    skip_error = kwargs.pop('skip_error', False)
    skip_tmpl = kwargs.pop('skip_tmpl', False)

    if cli_type in ['rest-patch', 'rest-put'] and vrf == 'all':
        cli_type = 'klish'

    if cli_type in ['click', 'klish']:
        if vrf != 'default':
            cmd = 'show ip mroute vrf {} summary'.format(vrf)
        else:
            cmd = 'show ip mroute summary'

    if cli_type == 'click':cli_type = 'vtysh'

    if cli_type in ['vtysh', 'klish']:
        output = st.show(dut, cmd, skip_error_check=skip_error, skip_tmpl=skip_tmpl, type=cli_type)

    if 'return_output' in kwargs:
        return output

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    for key in kwargs:
        if str(kwargs[key]) != str(output[0][key]):
            st.error("Match not found for {} : Expected- {} Actual - {}".format(key,kwargs[key],output[0][key]))
            ret_val = False
        else:
            st.log("Match found for {} : Expected- {} Actual - {}".format(key, kwargs[key], output[0][key]))
    return ret_val


