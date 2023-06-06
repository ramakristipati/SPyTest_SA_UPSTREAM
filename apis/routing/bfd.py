
import datetime
import ipaddress

from spytest import st
import apis.common.asic as asicapi
from apis.system.interface import clear_interface_counters, show_interface_counters_all
from apis.routing.arp import show_arp, show_ndp
from apis.system.rest import config_rest, get_rest, delete_rest
from apis.routing import ip as ip_api
from apis.routing.bgp import config_bgp_neighbor_properties
from apis.routing.ip_bgp import verify_bgp_neighbor
from utilities.common import filter_and_select, make_list, exec_all, is_valid_ipv4, get_query_params
from utilities.utils import get_intf_short_name, get_supported_ui_type_list

try:
    import apis.yang.codegen.messages.bfd as umf_bfd
    import apis.yang.codegen.messages.network_instance as umf_ni
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    from apis.yang.utils.common import Operation
except ImportError:
    pass

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type

def verify_bfd_counters(dut,**kwargs):
    """
    Author:gangadhara.sahu@broadcom.com
    :param peeraddress:
    :type bfd-peer-address
    :param localaddr:
    :type bfd-local-address
    :param interface:
    :type interface
    :param cntrlpktOut:
    :type control-packet-out
    :param cntrlpktIn:
    :type control-acket-in
    :param echopktin:
    :type echo-packet-in
    :param echopktout:
    :type echo-packet-out
    :param sessionupev:
    :type session-up-event
    :param sessiondownev:
    :type session-down-event
    :param zebranotifys:
    :type Zebra-notifications
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    bfd.verify_bfd_counters(dut1,cntrlpktout="100",cntrlpktin="100",peeraddress="5000::2")
    bfd.verify_bfd_counters(dut1,cntrlpktout="200",cntrlpktin="200",peeraddress="50.1.1.2")
    """
    result = False

    if not kwargs.get('peeraddress', ''):
        st.error("Mandatory parameter - peer address not found")
        return False

    st.log("verify show bfd peers counters")

    if 'interface' not in kwargs: kwargs['peer'] = 'all'
    else: kwargs['peer'] = kwargs['peeraddress']

    output = get_bfd_peer_counters(dut, **kwargs)

    if len(output) == 0:
        st.error("OUTPUT is Empty")
        return False

    match_dict = {}
    if 'peeraddress' in kwargs:
        match_dict['peeraddress'] = kwargs['peeraddress']
    else:
        st.error("Mandatory parameter peeraddress is not found")
        return result

    out_param = []
    for key in kwargs:
        out_param.append(key)
    entries = filter_and_select(output,out_param, match_dict)

    if bool(entries):
        if 'cntrlpktout' in out_param:
            if int(entries[0]['cntrlpktout']) >= int(kwargs['cntrlpktout']):
                result = True
                st.log("Number of output BFD Control packet is {} for peer {} Test Passed".format(int(entries[0]['cntrlpktout']),kwargs['peeraddress']))
            else:
                result = False
                st.error("Number of output BFD Control packet is {} for peer {} Test Failed as less than expected".format(int(entries[0]['cntrlpktout']),kwargs['peeraddress']))
        if 'cntrlpktin' in out_param:
            if int(entries[0]['cntrlpktin']) >= int(kwargs['cntrlpktin']):
                result = True
                st.log("Number of input BFD Control packet is {} for peer {} Test Passed".format(int(entries[0]['cntrlpktin']),kwargs['peeraddress']))
            else:
                result = False
                st.error("Number of input BFD Control packet is {} for peer {} Test Failed as less than expected".format(int(entries[0]['cntrlpktin']),kwargs['peeraddress']))
        if 'cntrlpktout' not in out_param and 'cntrlpktin' not in out_param:
            result = True
            st.log("BFD Peer IP {} exist in the output - Test Passed".format(kwargs['peeraddress']))
        if 'SessionUpEv' in out_param:
            if int(entries[0]['SessionUpEv']) == int(kwargs['SessionUpEv']):
                result = True
                st.log("Number of BFD UP event is {} for peer {} Test Passed".format(int(entries[0]['SessionUpEv']), kwargs['peeraddress']))
            else:
                result = False
                st.log("Number of BFD UP event is {} for peer {} Test Failed".format(int(entries[0]['SessionUpEv']), kwargs['peeraddress']))
        if 'SessionDownEv' in out_param:
            if int(entries[0]['SessionDownEv']) == int(kwargs['SessionDownEv']):
                result = True
                st.log("Number of BFD Down event is {} for peer {} Test Passed".format(int(entries[0]['SessionDownEv']), kwargs['peeraddress']))
            else:
                result = False
                st.log("Number of BFD Down event is {} for peer {} Test Failed".format(int(entries[0]['SessionDownEv']), kwargs['peeraddress']))
    else:
        st.error("Either BFD Peer IP {} or other passed arguments does not exist".format(kwargs['peeraddress']))

    return result


def configure_bfd(dut, **kwargs):
    """
    Author:gangadhara.sahu@broadcom.com
    :param local_asn:
    :type local-as-number:
    :param interface:
    :type interface:
    :param config:
    :type yes-or-no:
    :param neighbor_ip:
    :type neighbor-ip:
    :param multiplier:
    :type detect-multiplier:
    :param rx_intv:
    :type rx-interval:
    :param tx_intv:
    :type tx-interval:
    :param bfd_profile:
    :type Name of the BFD profile:
    :param no_bfd_profile:
    :type Name of the BFD profile:
    :param passive_mode:
    :type True or False:
    :param min_ttl:
    :type minimum-ttl value or None/False to remove min_ttl from static peer:
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    configure_bfd(dut1, local_asn="10",neighbor_ip="50.1.1.2",config="yes")
    configure_bfd(dut1, local_asn="10",neighbor_ip="50.1.1.2",config="no")
    configure_bfd(dut1, local_asn="10",neighbor_ip="5000::2",config="yes")
    configure_bfd(dut1, interface="Ethernet0",neighbor_ip="50.1.1.2",multiplier="100",rx_intv="200",tx_intv="300" )
    configure_bfd(dut1, interface="Ethernet0",local_address="5000::1",neighbor_ip="5000::2",multiplier="100",rx_intv="200",tx_intv="300")
    configure_bfd(dut1, interface="Ethernet0",local_address="5000::1",neighbor_ip="5000::2",multiplier="100",rx_intv="200",tx_intv="300",multihop="yes")
    configure_bfd(dut1,local_address="10.1.1.1",neighbor_ip="20.1.1.1",multihop="yes",noshut="yes",label="abcd")
    configure_bfd(dut1,local_address="10.1.1.1",neighbor_ip="20.1.1.1",multihop="yes",shutdown="yes")
    configure_bfd(dut1, local_asn="10",neighbor_ip="50.1.1.2",bfd_profile='test',config="yes")
    configure_bfd(dut1, local_asn="10",neighbor_ip="50.1.1.2",bfd_profile='test',config="no")
    configure_bfd(dut1, local_asn="10",bfd_profile=None,config="no")
    configure_bfd(dut1, interface="Ethernet0",neighbor_ip="50.1.1.2",multiplier="100",rx_intv="200",tx_intv="300",bfd_profile='test')
    configure_bfd(dut1, interface="Ethernet0",neighbor_ip="50.1.1.2",multiplier="100",rx_intv="200",tx_intv="300",bfd_profile=None)
    configure_bfd(dut1, interface="Ethernet0",neighbor_ip="50.1.1.2",multiplier="100",rx_intv="200",tx_intv="300",bfd_profile='')
    """

    if 'vrf_name' in kwargs:
        vrf = kwargs['vrf_name']
        if vrf == 'default':
            vrf = 'default-vrf'
        del kwargs['vrf_name']
    else:
        vrf = 'default-vrf'

    cli_type = st.get_ui_type(dut, **kwargs)
    operation = kwargs.pop('operation', Operation.UPDATE)

    if 'neighbor_ip' not in kwargs:
        st.error("Mandatory parameter - neighbor_ip not found")
        return False

    peergroup = kwargs.get('peergroup', None)
    nbr_cmd = 'peer-group' if peergroup else 'neighbor'

    if 'config' in kwargs and kwargs['config'] == 'no':
        config=kwargs['config']
        del kwargs['config']
    else:
        config=''

    if 'multihop' in kwargs:
        multihop_cmd = 'multihop'
        del kwargs['multihop']
    else:
        multihop_cmd = ''

    #Converting all kwargs to list type to handle single or multiple peers
    kwargs = convert_kwargs_list(**kwargs)
    if cli_type == 'click' and 'interface' in kwargs:
        kwargs['interface'] = [get_intf_short_name(i) for i in kwargs['interface']]

    if cli_type == 'click':
        if 'bfd_profile' in kwargs and 'shutdown' not in kwargs or 'noshut' not in kwargs:
            kwargs['noshut'] = [True] * len(kwargs['neighbor_ip'])

    #if 'local_asn' in kwargs and 'interface' not in kwargs:
    if 'local_asn' in kwargs:
        st.log("Entering router BGP..")
        if cli_type in get_supported_ui_type_list():
            local_asn = kwargs.pop('local_asn')
            nbr_list = kwargs.pop('neighbor_ip')
#            if peergroup:
#                nbr_list = kwargs.pop('peergroup')
            bfd_profile_list = kwargs.pop('bfd_profile', None)
            kwargs.pop('cli_type', None)
            bfd_kwargs = kwargs.copy()
            bfd_kwargs['vrf'] = 'default' if vrf == 'default-vrf' else vrf
            bfd_kwargs['config'] = 'no' if config == 'no' else 'yes'
            for index, nbr in enumerate(nbr_list):
                if bfd_profile_list:
                    bfd_kwargs.pop('bfd', None)
                    bfd_kwargs['bfd_profile'] = bfd_profile_list[index]
                else:
                    bfd_kwargs.pop('bfd_profile', None)
                    if config == 'no':
                        bfd_kwargs['bfd_profile'] = True
                    bfd_kwargs['bfd'] = True
                if peergroup:
                    bfd_kwargs['peergroup'] = nbr
                result = config_bgp_neighbor_properties(dut, local_asn=local_asn, neighbor_ip=nbr, family=None, mode='unicast', **bfd_kwargs)
                if not result: return False
        elif cli_type in ['click', 'klish']:
            if vrf == 'default-vrf':
                cmd = "router bgp {}\n".format(kwargs['local_asn'])
            else:
                cmd = "router bgp {} vrf {}\n".format(kwargs['local_asn'], vrf)
            if cli_type in ['click']:
                cmd += "no bgp ebgp-requires-policy\n"
            for index, nbr in enumerate(kwargs['neighbor_ip']):
                if cli_type == 'click':
                    if 'bfd_profile' in kwargs:
                        if (config == 'no'):
                            cmd1 = cmd + "{} neighbor {} bfd profile \n".format(config, nbr)
                        else:
                            cmd1 = cmd + "{} neighbor {} bfd profile {} \n".format(config, nbr, kwargs['bfd_profile'][index])
                    else:
                        cmd1 = cmd + "{} neighbor {} bfd \n".format(config, nbr)
                    st.config(dut, cmd1, type='vtysh')
                elif cli_type == 'klish':
                    if 'interface' in kwargs:
                        nbr_cmd += ' interface'
                    if 'bfd_profile' in kwargs:
                        if (config == 'no'):
                            cmd1 = cmd + "{} {} \n {} bfd profile \n exit \n exit \n".format(nbr_cmd, nbr, config)
                        else:
                            cmd1 = cmd + "{} {} \n {} bfd profile {} \n exit \n exit \n".format(nbr_cmd, nbr, config, kwargs['bfd_profile'][index])
                    else:
                        cmd1 = cmd + "{} {} \n {} bfd \n exit \n exit \n".format(nbr_cmd, nbr, config)
                    st.config(dut, cmd1, type=cli_type)
        elif cli_type in ['rest-patch', 'rest-put']:
            vrf_str = 'default' if vrf == 'default-vrf' else vrf
            rest_urls = st.get_datastore(dut, "rest_urls")
            neigh_list = []
            for index, nbr in enumerate(kwargs['neighbor_ip']):
                if not config:
                    neighbor_cmd = "neighbor-address" if nbr_cmd == 'neighbor' else "peer-group-name"
                    temp = dict()
                    temp[neighbor_cmd] = nbr
                    temp["openconfig-bfd:enable-bfd"] = dict()
                    temp["openconfig-bfd:enable-bfd"]['config'] = dict()
                    temp["openconfig-bfd:enable-bfd"]['config'].update({"enabled": True})
                    if 'bfd_profile' in kwargs:
                        temp["openconfig-bfd:enable-bfd"]['config'].update({'bfd-profile': kwargs['bfd_profile'][index]})
                    neigh_list.append(temp)
                else:
                    if nbr_cmd == 'neighbor':
                        neighbor_url = ["delete_bgp_neighbor_bfd_enabled", "delete_bgp_neighbor_bfd_profile"]
                    else:
                        neighbor_url = ["delete_bgp_peergroup_bfd_enabled", "delete_bgp_peergroup_bfd_profile"]
                    if 'bfd_profile' in kwargs:
                        neighbor_url = neighbor_url[-1:]
                    for url in neighbor_url:
                        url = rest_urls[url].format(vrf_str, nbr)
                        if not delete_rest(dut, http_method='delete', rest_url=url):
                            return False
            if not config:
                neighbor_url = "config_bgp_neighbor_list" if nbr_cmd == 'neighbor' else "config_bgp_peergroup_list"
                url = rest_urls[neighbor_url].format(vrf_str)
                data = {"openconfig-network-instance:{}".format(nbr_cmd): neigh_list}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False
    else:
        st.log("Entering BFD..")
        if cli_type in get_supported_ui_type_list():
            peer_type = 'multi' if multihop_cmd else 'single'
            vrf_str = 'default' if vrf == 'default-vrf' else vrf
            intf = kwargs.get('interface', 'null')
            config = 'no' if config == 'no' else 'yes'
            vrf_obj = umf_ni.NetworkInstance(Name=vrf_str)
            for peer_index,nbr in zip(range(len(kwargs['neighbor_ip'])),kwargs['neighbor_ip']):
                local_address = kwargs['local_address'][peer_index] if 'local_address' in kwargs else 'null'
                intf_obj = umf_intf.Interface(Name=intf[peer_index]) if intf != 'null' else 'null'
                if peer_type == 'single':
                    bfd_obj = umf_bfd.SingleHop(RemoteAddress=nbr, Vrf=vrf_obj, Interface=intf_obj, LocalAddress=local_address)
                else:
                    bfd_obj = umf_bfd.MultiHop(RemoteAddress=nbr, Vrf=vrf_obj, Interface=intf_obj, LocalAddress=local_address)

                bfd_attr_list = {
                    'multiplier': ['DetectionMultiplier', int(kwargs['multiplier'][peer_index]) if 'multiplier' in kwargs else None],
                    'rx_intv': ['RequiredMinimumReceive', int(kwargs['rx_intv'][peer_index]) if 'rx_intv' in kwargs else None],
                    'tx_intv': ['DesiredMinimumTxInterval', int(kwargs['tx_intv'][peer_index]) if 'tx_intv' in kwargs else None],
                    'echo_intv': ['DesiredMinimumEchoReceive', int(kwargs['echo_intv'][peer_index]) if 'echo_intv' in kwargs else None],
#                    'noshut': ['Enabled', True if 'noshut' in kwargs else None],
                    'noshut': ['Enabled', 'true' if 'noshut' in kwargs else None],
                    'shutdown': ['Enabled', False if 'shutdown' in kwargs else None],
                    'echo_mode_enable': ['EchoActive', True if 'echo_mode_enable' in kwargs else None],
                    'echo_mode_disable': ['EchoActive', False if 'echo_mode_disable' in kwargs else None],
                    'bfd_profile': ['ProfileName', kwargs['bfd_profile'][peer_index] if 'bfd_profile' in kwargs else None],
                    'no_bfd_profile': ['ProfileName', None if 'no_bfd_profile' in kwargs else None],
                    'passive_mode': ['PassiveMode', kwargs['passive_mode'][peer_index] if 'passive_mode' in kwargs else False],
                }

                if 'min_ttl' in kwargs and peer_type == 'multi':
                    if bool(kwargs['min_ttl'][peer_index]):
                        bfd_attr_list['min_ttl'] = ['MinimumTtl',int(kwargs['min_ttl'][peer_index])]
                    else:
                        bfd_attr_list['min_ttl'] = ['MinimumTtl', 254]

                def_val = {'min_ttl': 254, 'rx_intv': 300, 'tx_intv': 300, 'multiplier': 3}
                if config == 'yes':
                    for key, attr_value in  bfd_attr_list.items():
                        if key in kwargs and attr_value[1] is not None:
                            if key in list(def_val.keys()) and int(attr_value[1]) == int(def_val[key]):
                                target_attr = getattr(bfd_obj, attr_value[0])
                                result = bfd_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                            else:
                                setattr(bfd_obj, attr_value[0], attr_value[1])
                    st.log('***IETF_JSON: {}'.format(bfd_obj.get_ietf_json()))
                    result = bfd_obj.configure(dut, operation=operation, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Config BFD {}'.format(result.data))
                        return False
                    if 'no_bfd_profile' in kwargs:
                        result = bfd_obj.unConfigure(dut, target_attr=bfd_obj.ProfileName, cli_type=cli_type)
                        if not result.ok():
                            st.log('test_step_failed: Config BFD {}'.format(result.data))
                            return False
                else:
                    #for key, attr_value in  bfd_attr_list.items():
                    #    if key in kwargs:
                    #        target_attr = getattr(bfd_obj, attr_value[0])
                    result = bfd_obj.unConfigure(dut, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Config BFD {}'.format(result.data))
                        return False

            return True
        elif cli_type in ['click', 'klish']:
            cmd_list = list()
            cmd_list.append('bfd')
            for peer_index,nbr in zip(range(len(kwargs['neighbor_ip'])),kwargs['neighbor_ip']):
                cmd = ''
                if not multihop_cmd:
                    cmd += "{} peer {} ".format(config, nbr)
                else:
                    cmd += "{} peer {} {} ".format(config, nbr, multihop_cmd)

                if vrf == 'default-vrf':
                    if 'interface' in kwargs and "local_address" not in kwargs:
                        cmd += "interface {}".format(kwargs['interface'][peer_index])
                    elif 'interface' not in kwargs and "local_address" in kwargs:
                        cmd += "local-address {}".format(kwargs['local_address'][peer_index])
                    elif 'interface' in kwargs and "local_address" in kwargs:
                        cmd += "local-address {} interface {}".format(kwargs['local_address'][peer_index], kwargs['interface'][peer_index])
                else:
                    if 'interface' in kwargs and "local_address" not in kwargs:
                        cmd += "interface {} vrf {}".format(kwargs['interface'][peer_index], vrf)
                    elif 'interface' not in kwargs and "local_address" in kwargs:
                        cmd += "local-address {} vrf {}".format(kwargs['local_address'][peer_index], vrf)
                    elif 'interface' in kwargs and "local_address" in kwargs:
                        cmd += "local-address {} interface {} vrf {}".format(kwargs['local_address'][peer_index], kwargs['interface'][peer_index], vrf)
                cmd_list.append(cmd)
                if 'multiplier' in kwargs and config != 'no':
                    cmd_list.append("detect-multiplier {}".format(kwargs['multiplier'][peer_index]))
                if 'rx_intv' in kwargs and config != 'no':
                    cmd_list.append("receive-interval {}".format(kwargs['rx_intv'][peer_index]))
                if 'tx_intv' in kwargs and config != 'no':
                    cmd_list.append("transmit-interval {}".format(kwargs['tx_intv'][peer_index]))
                if 'noshut' in kwargs and config != 'no':
                    cmd_list.append("no shutdown")
                if 'shutdown' in kwargs and config != 'no':
                    cmd_list.append("shutdown")
                if 'echo_mode_enable' in kwargs and config != 'no':
                    cmd_list.append("echo-mode")
                if 'echo_mode_disable' in kwargs and config != 'no':
                    cmd_list.append("no echo-mode")
                if 'echo_intv' in kwargs and config != 'no':
                    cmd_list.append("echo-interval {}".format(kwargs['echo_intv'][peer_index]))
                if 'label' in kwargs and config != 'no':
                    cmd_list.append("label {}".format(kwargs['label'][peer_index]))
                if 'bfd_profile' in kwargs and config != 'no':
                    cmd_list.append("profile {}".format(kwargs['bfd_profile'][peer_index]))
                if 'no_bfd_profile' in kwargs and config != 'no':
                    if cli_type == 'click':
                        cmd_list.append("no profile {}".format(kwargs['no_bfd_profile'][peer_index]))
                    else:
                        cmd_list.append("no profile")
                if 'passive_mode' in kwargs and config != 'no':
                    mode = '' if kwargs['passive_mode'][peer_index] else 'no'
                    cmd_list.append("{} passive-mode".format(mode))
                if 'min_ttl' in kwargs and multihop_cmd and config != 'no':
                    if kwargs['min_ttl'][peer_index]:
                        cmd_list.append("minimum-ttl {}".format(kwargs['min_ttl'][peer_index]))
                    else:
                        cmd_list.append("no minimum-ttl")
                if config != 'no':
                    cmd_list.append('exit')
            cmd_list.append('exit')
            if cli_type == 'click':
                st.config(dut, cmd_list, type='vtysh')
            elif cli_type == 'klish':
                st.config(dut, cmd_list, type=cli_type)
        elif cli_type in ['rest-patch', 'rest-put']:
            rest_urls = st.get_datastore(dut, "rest_urls")
            peer_type = 'multi' if multihop_cmd else 'single'
            hop_type = 'mhop' if peer_type == 'multi' else 'shop'
            vrf_str = 'default' if vrf == 'default-vrf' else vrf
            peer_list = []
            for peer_index, nbr in enumerate(kwargs['neighbor_ip']):
                temp = dict()
                temp['remote-address'] = nbr
                if 'interface' in kwargs: temp['interface'] = kwargs['interface'][peer_index]
                if 'multiplier' in kwargs: temp['detection-multiplier'] = int(kwargs['multiplier'][peer_index])
                if 'rx_intv' in kwargs: temp['required-minimum-receive'] = int(kwargs['rx_intv'][peer_index])
                if 'tx_intv' in kwargs: temp['desired-minimum-tx-interval'] = int(kwargs['tx_intv'][peer_index])
                if 'echo_mode_enable' in kwargs: temp['echo-active'] = True
                if 'echo_mode_disable' in kwargs: temp['echo-active'] = False
                if 'echo_intv' in kwargs: temp['desired-minimum-echo-receive'] = int(kwargs['echo_intv'][peer_index])
                if 'shutdown' in kwargs: temp['enabled'] = False
                if 'noshut' in kwargs: temp['enabled'] = True
                if 'min_ttl' in kwargs and peer_type == 'multi':
                    if bool(kwargs['min_ttl'][peer_index]):
                        temp['minimum-ttl'] = int(kwargs['min_ttl'][peer_index])
                    else:
                        temp['minimum-ttl'] = 254
                if 'passive_mode' in kwargs:
                    temp['passive-mode'] = True if kwargs['passive_mode'][peer_index] else False
                if 'bfd_profile' in kwargs:
                    temp['profile-name'] = kwargs['bfd_profile'][peer_index]
                if 'local_address' in kwargs:
                    temp['local-address'] = kwargs['local_address'][peer_index]
                else:
                    temp['local-address'] = 'null'
                temp['vrf'] = vrf_str
                temp['enabled'] = temp.get('enabled', True)
                data = dict()

                data["remote-address"] = temp["remote-address"]
                data["vrf"] = temp["vrf"]
                data["interface"] = temp.get("interface", 'null')
                data["local-address"] = temp["local-address"]
                data['config'] = temp
                peer_list.append(data)
                if 'no_bfd_profile' in kwargs:
                    url = rest_urls['del_bfd_profile_name'].format(hop_type, peer_type, data["remote-address"],
                                                              data["interface"], data['vrf'], data["local-address"])
                    if not delete_rest(dut, http_method='delete', rest_url=url):
                        return False
                if config == 'no':
                    url = rest_urls['delete_bfd_peer'].format(hop_type, peer_type, data["remote-address"], data["interface"], data['vrf'], data["local-address"])
                    if not delete_rest(dut, http_method='delete', rest_url=url):
                        return False
            if not config:
                url = rest_urls['config_bfd_shop_peer_list'] if peer_type == 'single' else rest_urls['config_bfd_mhop_peer_list']
                data = {"openconfig-bfd-ext:{}-hop".format(peer_type): peer_list}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False


def verify_bfd_peers_brief(dut,**kwargs):
    """
    Author:gangadhara.sahu@broadcom.com
    :param peeraddress:
    :type bfd-peer-address
    :param ouraddress:
    :type bfd-local-address
    :param status:
    :type up-or-down
    :param scount:
    :type session-count
    :param sessionid:
    :type bfd-session-id
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    bfd.verify_bfd_peers_brief(dut1,peeraddress="50.1.1.2",ouraddress="50.1.1.1",status="Up")
    bfd.verify_bfd_peers_brief(dut1,peeraddress="50.1.1.2",ouraddress="50.1.1.1",status="Shutdown")
    bfd.verify_bfd_peers_brief(dut1,peeraddress="5000::2",ouraddress="5000::1",status="Up")
    bfd.verify_bfd_peers_brief(dut1,peeraddress="5000::2",ouraddress="5000::1",status="Down")
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'vtysh' if cli_type == 'click' else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    result = False
    st.log("Verify show bfd peers brief")
    output = get_bfd_peers_brief(dut, cli_type=cli_type)

    if len(output) == 0:
        st.error("Show OUTPUT is Empty")
        return result

    match_dict = {}
    if 'ouraddress' not in kwargs or 'peeraddress' not in kwargs:
        st.error("Mandatory parameters like ouraddress or/and peeraddress not passed")
        return result
    else:
        if ipaddress.ip_address(u"{}".format(kwargs['peeraddress'])).version == 6:
            kwargs['peeraddress'] = ipaddress.ip_address(u"{}".format(kwargs['peeraddress'])).compressed
            kwargs['ouraddress'] = ipaddress.ip_address(u"{}".format(kwargs['ouraddress'])).compressed
        match_dict['peeraddress'] = kwargs['peeraddress']

    out_param = ['sessionid','status','scount','ouraddress']
    entries = filter_and_select(output,out_param, match_dict)

    if bool(entries):
        if 'status' in kwargs:
            if entries[0]['status'].lower() == kwargs['status'].lower() and entries[0]['ouraddress'] == kwargs['ouraddress']:
                result = True
                st.log("BFD session status is {} for peer {} Test Passed".format(entries[0]['status'],kwargs['peeraddress']))
            else:
                result = False
                st.error("BFD session status is not matching for src {} & peer {} Test Failed".format(kwargs['ouraddress'],kwargs['peeraddress']))
        if 'scount' in kwargs:
            if entries[0]['scount'] == kwargs['scount'] and entries[0]['ouraddress'] == kwargs['ouraddress']:
                result = True
                st.log("BFD session scount is {} for peer {} Test Passed".format(entries[0]['scount'],kwargs['peeraddress']))
            else:
                result = False
                st.error("BFD session scount is not matching for src {} & peer {} Test Failed".format(kwargs['ouraddress'],kwargs['peeraddress']))
        if 'status' not in kwargs and 'scount' not in kwargs:
            st.error("No arguments passed to be verified..")
    else:
        st.error("BFD session does not exist for peer address {} Test Failed".format(kwargs['peeraddress']))

    return result


def verify_bfd_peer(dut,**kwargs):
    """
    author:sooriya.gajendrababu@broadcom.com
    :param  :peer
    :type   :peer_ip address (list or string)
    :param  :local_addr
    :type   :local_address (list or string)
    :param  :interface
    :type   :bfd interface (list or string)
    :param  :local_id
    :type   :bfd local session-id (list or string)
    :param  :remote_id
    :type   :bfd remote session-d (list or string)
    :param  :status
    :type   :bfd session status (list or string)
    :param  :uptimeday
    :type   :uptime value in days (list or string)
    :param  :uptimehr
    :type   :uptime value in hours (list or string)
    :param  :uptimemin
    :type   :uptime value in minutes (list or string)
    :param  :uptimesec
    :type   :uptime value  in seconds (list or string)
    :param  :diagnostics
    :type   :diagnostics state (list or string)
    :param  :remote_diagnostics
    :type   :remote_diagnostics_state (list or string)
    :param  :rx_interval
    :type   :list of local_rx and remote_rx interval (list (or) list of lists)
    :param  :tx_interval
    :type   :list of local_rx and remote_tx interval (list (or) list of lists)
    :param  :echo_tx_interval
    :type   :list of local_echo_tx and remote_echo_tx interval (list (or) list of lists)
    :param  :minimum_ttl
    :type   :minimum-ttl value
    :param  :passive_mode
    :type   :Enabled or Disabled
    :param  :profile_name
    :type   :string
    :return :true/false
    :rtype  : boolean

    :Usage:
    bfd.verify_bfd_peer(dut1,peer='10.10.10.2',interface='Ethernet0',rx_interval=[['300','300']])
    bfd.verify_bfd_peer(dut1,peer=['10.10.10.2','20.20.20.2'],interface=['Ethernet0','Ethernet4'],status=['up','up'],diagnostics=['ok','nok'],rx_interval=[['300','300'],['300','300']])

    """
    if 'peer' not in kwargs:
        st.log("Mandatory parameter -peer not found")
        return False

    if 'vrf_name' in kwargs:
        vrf = kwargs['vrf_name']
        if vrf == 'default-vrf':
            vrf = 'default'
        del kwargs['vrf_name']
    else:
        vrf = 'default'

    cli_type = st.get_ui_type(dut, **kwargs)
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if 'multihop' in kwargs:
        is_mhop = True
        del kwargs['multihop']
        if 'local_addr' not in kwargs:
            st.error("-local_addr argument missing")
            return False
    else:
        is_mhop = False

    ping_verify = kwargs['ping_verify'] if 'ping_verify' in kwargs else True
    enable_debug = kwargs['enable_debug'] if 'enable_debug' in kwargs else False
    kwargs.pop('ping_verify', '')
    kwargs.pop('enable_debug', '')

    rv = False
    #Converting all kwargs to list type to handle single or multiple peers
    kwargs = convert_kwargs_list(**kwargs)
    if 'interface' in kwargs:
        if cli_type == 'click':
            kwargs['interface'] = [get_intf_short_name(i)  for i in kwargs['interface']]
    #handling for multiple peers or single peer
    if len(kwargs['peer']) == 1:
        if is_mhop is False:
            if vrf == 'default':
                if 'local_addr' in kwargs and 'interface' in kwargs :
                    for peer_ip,local_addr,intf in zip(kwargs['peer'],kwargs['local_addr'],kwargs['interface']):
                        cmd = "show bfd peer " + peer_ip + " local-address "+ local_addr + " interface " + intf
                elif 'interface' in kwargs and 'local_addr' not in kwargs:
                    for peer_ip,intf in zip(kwargs['peer'],kwargs['interface']):
                        cmd = "show bfd peer " + peer_ip + " interface " + intf
                else:
                    for peer_ip,local_addr in zip(kwargs['peer'],kwargs['local_addr']):
                        cmd = "show bfd peer " + peer_ip + " local-address "+ local_addr
            else:
                if 'local_addr' in kwargs and 'interface' in kwargs :
                    if cli_type == 'click':
                        for peer_ip,local_addr,intf in zip(kwargs['peer'],kwargs['local_addr'],kwargs['interface']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " local-address "+ local_addr + " interface " + intf
                    else:
                        for peer_ip,local_addr,intf in zip(kwargs['peer'],kwargs['local_addr'],kwargs['interface']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " local-address "+ local_addr + " interface " + intf
                elif 'interface' in kwargs and 'local_addr' not in kwargs:
                    if cli_type == 'click':
                        for peer_ip,intf in zip(kwargs['peer'],kwargs['interface']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " interface " + intf
                    else:
                        for peer_ip, intf in zip(kwargs['peer'], kwargs['interface']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " interface " + intf
                else:
                    if cli_type == 'click':
                        for peer_ip,local_addr in zip(kwargs['peer'],kwargs['local_addr']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " local-address "+ local_addr
                    else:
                        for peer_ip, local_addr in zip(kwargs['peer'], kwargs['local_addr']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " local-address " + local_addr
        else:
            if vrf == 'default':
                for peer_ip, localaddress in zip(kwargs['peer'], kwargs['local_addr']):
                    cmd = "show bfd peer " + peer_ip + " multihop local-address " + localaddress
            else:
                if 'interface' not in kwargs and 'local_addr' in kwargs:
                    if cli_type == 'click':
                        for peer_ip, localaddress in zip(kwargs['peer'], kwargs['local_addr']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " multihop local-address " + localaddress
                    else:
                        for peer_ip, localaddress in zip(kwargs['peer'], kwargs['local_addr']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " multihop local-address " + localaddress
                elif 'interface' in kwargs and 'local_addr' in kwargs:
                    if cli_type == 'click':
                        for peer_ip, localaddress, intf in zip(kwargs['peer'], kwargs['local_addr'], kwargs['interface']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " multihop local-address " + localaddress + " interface " + intf
                    else:
                        for peer_ip, localaddress, intf in zip(kwargs['peer'], kwargs['local_addr'], kwargs['interface']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " multihop local-address " + localaddress + " interface " + intf
    else:
        if vrf == 'default':
            cmd = "show bfd peers"
        else:
            if cli_type == 'click':
                cmd = "show bfd" + " vrf " + vrf + " peers"
            else:
                cmd = "show bfd" + " peers" + " vrf " + vrf
    #Execute appropriate BFD CLI
    parsed_output = []
    ping_intf = kwargs['interface'] if 'interface' in kwargs else ''
    bfd_type = 'multi' if is_mhop else 'single'
    if cli_type in get_supported_ui_type_list()+['rest-patch', 'rest-put']:
        if 'local_addr' not in kwargs: cli_type='klish'
        if 'interface' not in kwargs: cli_type='klish'
    if cli_type in get_supported_ui_type_list():
        st.banner('BFD GNMI VERIFICATION')
        local_addr = kwargs['local_addr'] if kwargs.get('local_addr') else 'null'
        interface = kwargs['interface'] if 'interface' in kwargs else 'null'
        parsed_output = rest_get_bfd_peer_info(dut, 'peers', bfd_type=bfd_type, vrf=vrf, peer=kwargs['peer'], local_addr=local_addr, interface=interface)
    elif cli_type in ['click', 'klish', 'vtysh']:
        cli_type = "vtysh" if cli_type == "click" else cli_type
        try:
            parsed_output = st.show(dut, cmd, type=cli_type)
        except Exception as e:
            st.error("The BFD session is not exist either deleted or not configured: exception is {} ".format(e))
            if ping_verify: debug_bfd_ping(dut, kwargs['peer'], vrf_name=vrf, interface=ping_intf, enable_debug=enable_debug)
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        # st.show(dut, cmd, type='klish')
        if len(kwargs['peer']) > 1:
            parsed_output = rest_get_bfd_peer_info(dut, 'peers', bfd_type=bfd_type)
        else:
            st.log('Verifying single peer info')
            peer_ip = kwargs['peer'][0] if 'peer' in kwargs else ''
            local_addr = kwargs['local_addr'][0] if 'local_addr' in kwargs else ''
            st.log('peer_ip: {}, local_addr: {}'.format(peer_ip, local_addr))
            interface = kwargs['interface'][0] if 'interface' in kwargs else ''
            parsed_output = rest_get_bfd_peer_info(dut, 'peers', bfd_type=bfd_type, peer_list=False, vrf=vrf,
                                                   peer=peer_ip, local_addr=local_addr, interface=interface)
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

    if is_mhop: kwargs.pop('local_addr', '')

    if cli_type in ['klish', 'rest-patch', 'rest-put']:
        if 'status' in kwargs:
            kwargs['status'] = ['admin_down' if status == 'shutdown' else status for status in kwargs['status']]
    if cli_type == 'vtysh':
        if 'profile_name' in kwargs:
            kwargs['profile_name'] = ['(null)' if not profile else profile for profile in kwargs['profile_name']]
    if 'return_dict' in kwargs:
        return parsed_output

    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        if ping_verify: debug_bfd_ping(dut, kwargs['peer'], vrf_name=vrf, interface=ping_intf, enable_debug=enable_debug)
        return False
    #Get the index of peer from list of parsed output
    for i in range(len(kwargs['peer'])):
        peer_index = None
        st.log("Validation for BFD Peer : %s"%kwargs['peer'][i])
        for peer_info in parsed_output:
            if (peer_info['peer'] == kwargs['peer'][i]) and (peer_info['vrf_name'] == vrf and peer_info['status'] != ''):
                peer_index = parsed_output.index(peer_info)
        if peer_index is not None:
            #Iterate through the user parameters
            if cli_type == 'vtysh':
                if 'passive_mode' in parsed_output[peer_index]:
                    parsed_output[peer_index]['passive_mode'] = 'Disabled' if parsed_output[peer_index]['passive_mode'] == 'Active' else 'Enabled'
            for k in kwargs.keys():
                if parsed_output[peer_index][k] == kwargs[k][i]:
                    st.log('Match Found for %s :: Expected: %s  Actual : %s'%(k,kwargs[k][i],parsed_output[peer_index][k]))
                    rv=True
                else:
                    st.error('Match Not Found for %s :: Expected: %s  Actual : %s'%(k,kwargs[k][i],parsed_output[peer_index][k]))
                    if ping_verify: debug_bfd_ping(dut, kwargs['peer'][i], vrf_name=vrf, enable_debug=False, interface=ping_intf)
                    return False
        else:
            st.error(" BFD Peer %s not in output"%kwargs['peer'][i])
            if ping_verify: debug_bfd_ping(dut, kwargs['peer'], vrf_name=vrf, interface=ping_intf, enable_debug=enable_debug)
            return False
    return rv


def get_bfd_peer_counters(dut,**kwargs):
    """
    author:sooriya.gajendrababu@broadcom.com
    :param  :peer
    :type   :peer_ip address (list or string)
    :param  :local_addr
    :type   :local_address (list or string)
    :param  :interface
    :type   :bfd interface (list or string)
    """

    cli_type = st.get_ui_type(dut, **kwargs)

    if 'vrf_name' in kwargs:
        vrf = kwargs['vrf_name']
        if vrf == 'default-vrf':
            vrf = 'default'
        del kwargs['vrf_name']
    else:
        vrf = 'default'

    if 'peer' not in kwargs:
        kwargs['peer'] = 'all'

    if 'multihop' in kwargs:
        is_mhop = True
        if 'local_addr' not in kwargs:
            st.error("-local_addr argument missing")
            return False
    else:
        is_mhop = False

    if kwargs['peer'] == 'all' and vrf == 'default':
        cmd = "show bfd peers counters"
    elif kwargs['peer'] == 'all' and vrf != 'default':
        if cli_type == 'click':
            cmd = "show bfd vrf {} peers counters".format(vrf)
        else:
            cmd = "show bfd peers vrf {} counters".format(vrf)
    else:
        if is_mhop is False:
            if vrf == 'default':
                if 'local_addr' in kwargs and 'interface' in kwargs :
                    if cli_type == 'click':
                        cmd = "show bfd peer " + kwargs['peer'] + " local-address "+ kwargs['local_addr'] + " interface " + kwargs['interface'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " local-address " + kwargs['local_addr'] + " interface " + kwargs['interface']
                elif 'interface' in kwargs and 'local_addr' not in kwargs:
                    if cli_type == 'click':
                        cmd = "show bfd peer " + kwargs['peer'] + " interface " + kwargs['interface'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " interface " + kwargs['interface']
                else:
                    if cli_type == 'click':
                        cmd = "show bfd peer " + kwargs['peer'] + " local-address "+ kwargs['local_addr'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " local-address " + kwargs['local_addr']
            else:
                if 'local_addr' in kwargs and 'interface' in kwargs :
                    if cli_type == 'click':
                        cmd = "show bfd vrf {} peer ".format(vrf) + kwargs['peer'] + " local-address "+ kwargs['local_addr'] + " interface " + kwargs['interface'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " vrf " + vrf + " local-address " + kwargs['local_addr'] + " interface " + kwargs['interface']
                elif 'interface' in kwargs and 'local_addr' not in kwargs:
                    if cli_type == 'click':
                        cmd = "show bfd vrf {} peer ".format(vrf) + kwargs['peer'] + " interface " + kwargs['interface'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " vrf " + vrf + " interface " + kwargs['interface']
                else:
                    if cli_type == 'click':
                        cmd = "show bfd vrf {} peer ".format(vrf) + kwargs['peer'] + " local-address "+ kwargs['local_addr'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " vrf " + vrf + " local-address " + kwargs['local_addr']

        else:
            if vrf == 'default':
                if cli_type == 'click':
                    cmd = "show bfd peer " + kwargs['peer'] + " multihop local-address " + kwargs['local_addr'] + " counters"
                else:
                    cmd = "show bfd peer counters " + kwargs['peer'] + " multihop local-address " + kwargs['local_addr']
            else:
                if cli_type == 'click':
                    cmd = "show bfd vrf {} peer ".format(vrf) + kwargs['peer'] + " multihop local-address " + kwargs['local_addr'] + " counters"
                else:
                    cmd = "show bfd peer counters " + kwargs['peer'] + " vrf " + vrf + " multihop local-address " + kwargs['local_addr']

    bfd_type = 'multi' if is_mhop else 'single'
    if cli_type in get_supported_ui_type_list():
        if 'interface' not in kwargs: cli_type = 'klish'
    if cli_type in get_supported_ui_type_list():
        st.banner('BFD GNMI VERIFICATION')
        local_addr = kwargs['local_addr'] if kwargs.get('local_addr') else 'null'
        interface = kwargs['interface'] if 'interface' in kwargs else 'null'
        parsed_output = rest_get_bfd_peer_info(dut, 'counters', bfd_type=bfd_type, vrf=vrf, peer=kwargs['peer'],
                                               local_addr=local_addr, interface=interface)
    elif cli_type in ['click', 'klish']:
        cli_type = "vtysh" if cli_type == "click" else cli_type
        try:
            parsed_output = st.show(dut, cmd, type=cli_type)
        except Exception as e:
            st.error("The BFD session is not existing either deleted or not configured: exception is {} ".format(e))
            return []
    elif cli_type in ['rest-patch', 'rest-put']:
        parsed_output = rest_get_bfd_peer_info(dut, 'counters', bfd_type=bfd_type)
        if kwargs['peer'] == 'all':
            return parsed_output
        else:
            return filter_and_select(parsed_output, None, {'peeraddress': kwargs['peer'], 'vrfname': vrf})
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False
    return parsed_output


def verify_bgp_bfd_down(dut, neighbor, interface, check_reason='no', vrf_name='default-vrf', family='ipv4', cli_type=''):
    """
    author:sooriya.gajendrababu@broadcom.com
    :param  :neighbor
    :type   :neighbor address (string)
    :param  :check_reason
    :type   : str
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'

    ret_val=True
    output = verify_bgp_neighbor(dut, neighborip=neighbor, vrf=vrf_name, family=family, return_output=True)
    if len(output) == 0:
        st.error("OUTPUT is Empty")
        return False
    bgp_state = output[0]['state']
    bgp_down_reason = output[0]['bgpdownreason']

    bfd_state = ''
    output = verify_bfd_peer(dut, peer=neighbor, interface=interface, status='down', vrf_name=vrf_name, return_dict=True)
    if not bool(output) or output[0]['status'] != 'up':
        bfd_state = 'Down'

    if check_reason == 'yes':
        if bgp_state != 'Established' and bfd_state == 'Down' and  bgp_down_reason == "BFD down received":
            st.log('BGP state and BFD state went down as expected for {}'.format(neighbor))
        else:
            st.error('BGP or BFD state did not go down for {}. Actual BGP state :{} ,BFD state: {}'.format(neighbor, bgp_state,bfd_state))
            ret_val = False
    else:
        if bgp_state != 'Established' and bfd_state == 'Down':
            st.log('BGP state and BFD state went down as expected for {}'.format(neighbor))
        else:
            st.error('BGP or BFD state did not go down for {}. Actual BGP state :{} ,BFD state: {}'.format(neighbor,bgp_state,bfd_state))
            ret_val=False
    return ret_val


def clear_bfd_peer_counters(dut,**kwargs):
    """
    author:vishnuvardhan.talluri@broadcom.com
    :param  :peer
    :type   :peer_ip address (list or string)
    :param  :local_addr
    :type   :local_address (list or string)
    :param  :interface
    :type   :bfd interface (list or string)
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'vtysh' if cli_type == 'click' else cli_type
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if 'multihop' in kwargs:
        cmd_mhop = " multihop"
    else:
        cmd_mhop = ""

    if 'vrf_name' in kwargs:
        if kwargs['vrf_name'] in ['default-vrf', 'default']:
            cmd_vrf = ""
        else:
            cmd_vrf = ' vrf {}'.format(kwargs['vrf_name'])
    else:
        cmd_vrf = ""

    cmd = "clear bfd"
    if cli_type == 'vtysh':
        cmd += cmd_vrf + " peer " + kwargs['peer']
    else:
        cmd += " peer " + kwargs['peer'] + cmd_vrf
    if cmd_mhop:
        cmd += cmd_mhop

    if 'local_addr' in kwargs and 'interface' in kwargs :
        cmd += " local-address "+ kwargs['local_addr'] + " interface " + kwargs['interface'] + " counters"
    elif 'interface' in kwargs and 'local_addr' not in kwargs:
        cmd += " interface " + kwargs['interface'] + " counters"
    else:
        cmd += " local-address "+ kwargs['local_addr'] + " counters"
    cmd = 'do ' + cmd
    st.config(dut, cmd, type=cli_type)


def get_bfd_peers_brief(dut, cli_type=''):
    """
    :param dut: DUT name where the CLI needs to be executed
    :type dut: string
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'vtysh' if cli_type == 'click' else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in ['vtysh', 'klish']:
        return st.show(dut, "show bfd peers brief", type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        # st.show(dut, "show bfd peers brief", type='klish')
        return rest_get_bfd_peer_info(dut, 'brief')
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def debug_bfd_ping(dut, addresses, vrf_name='default', interface='', enable_debug=True, cli_type=''):
    st.banner("********* Ping Dubug commands starts ************")
    addresses = make_list(addresses)
    interface = make_list(interface) if interface else ''
    for index, addr in enumerate(addresses):
        family = 'ipv4' if is_valid_ipv4(addr) else 'ipv6'
        if vrf_name in ['default', 'default-vrf'] and not addr.startswith('fe80:'):
            ip_api.ping(dut, addr, family, cli_type=cli_type)
        else:
            intf = interface[index] if interface and addr.startswith('fe80:') else vrf_name
            ip_api.ping(dut, addr, family, interface=intf, cli_type=cli_type)
    if enable_debug: debug_bgp_bfd(dut)


def debug_bgp_bfd(dut):
    dut_list = make_list(dut)
    st.banner("********* Dubug commands starts ************")
    func_list = [clear_interface_counters, show_arp, show_ndp, show_interface_counters_all,
                 asicapi.dump_l3_ip6route, asicapi.dump_l3_defip]
    for func in func_list:
        api_list = [[func, dut] for dut in dut_list]
        exec_all(True, api_list)
    st.banner(" ******** End of Dubug commands ************")


def rest_get_bfd_peer_info(dut, type, bfd_type=None, peer_list=True, **kwargs):
    """
    Author: Lakshminarayana D(lakshminarayana.d@broadcom.com)
    :param dut:
    :type bfd_type: None, single, multi
    :param type: brief, counters, peers
    :param peer_list: True: get all peer info, False: get particular peer info
    :return:
    """

    rest_urls = st.get_datastore(dut, "rest_urls")
    bfd_peer_state=[]
    cli_type = st.get_ui_type(dut, cli_type=kwargs.get('cli_type', ''))
    if cli_type in get_supported_ui_type_list():
        def get_bfd_state(bfd_obj, bfd_type):
            result = bfd_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
            if result.ok():
                state = result.payload.get('openconfig-bfd-ext:{}-hop'.format(bfd_type), '')
                if not state:
                    return []
                return state
            else:
                return []

        yang_data_type = kwargs.get("filter_type", "ALL")
        query_params_obj = get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
        vrf_obj = umf_ni.NetworkInstance(Name=kwargs.get('vrf', 'default'))
        if not kwargs.get('peer'):
            st.error('Mandatory params not provided to perform a rest operation')
            return []
        remote_addr = make_list(kwargs.get('peer'))
        intf = make_list(kwargs['interface']) if kwargs.get('interface') != 'null' else ['null'] * len(remote_addr)
        local_address = make_list(kwargs['local_addr']) if kwargs.get('local_addr') != 'null' else ['null'] * len(remote_addr)

        for index, nbr in enumerate(make_list(remote_addr)):
            intf_obj = umf_intf.Interface(Name=intf[index]) if intf[index] else 'null'
            local_addr = local_address[index] if local_address[index] else 'null'
            if bfd_type == 'single':
                bfd_obj = umf_bfd.SingleHop(RemoteAddress=nbr, Vrf=vrf_obj, Interface=intf_obj, LocalAddress=local_addr)
                rv = get_bfd_state(bfd_obj, bfd_type)
                if rv: bfd_peer_state.extend(rv)
            elif bfd_type == 'multi':
                bfd_obj = umf_bfd.MultiHop(RemoteAddress=nbr, Vrf=vrf_obj, Interface=intf_obj, LocalAddress=local_addr)
                rv = get_bfd_state(bfd_obj, bfd_type)
                if rv: bfd_peer_state.extend(rv)
            else:
                bfd_obj = umf_bfd.SingleHop(RemoteAddress=nbr, Vrf=vrf_obj, Interface=intf_obj, LocalAddress=local_addr)
                rv = get_bfd_state(bfd_obj, 'single')
                if rv: bfd_peer_state.extend(rv)
                bfd_obj = umf_bfd.MultiHop(RemoteAddress=nbr, Vrf=vrf_obj, Interface=intf_obj, LocalAddress=local_addr)
                rv = get_bfd_state(bfd_obj, 'multi')
                if rv: bfd_peer_state.extend(rv)
    elif peer_list:
        if not bfd_type:
            uri = rest_urls['config_bfd_peer_list']
            result = get_rest(dut, rest_url=uri)
            if not result or not result.get('output'): return []
            if result['output']['openconfig-bfd:bfd'].get('openconfig-bfd-ext:bfd-shop-sessions', ''):
                shop_state = result['output']['openconfig-bfd:bfd']['openconfig-bfd-ext:bfd-shop-sessions'].get('single-hop', '')
                if shop_state: bfd_peer_state.extend(shop_state)
            if result['output']['openconfig-bfd:bfd'].get('openconfig-bfd-ext:bfd-mhop-sessions', ''):
                mhop_state = result['output']['openconfig-bfd:bfd']['openconfig-bfd-ext:bfd-mhop-sessions'].get('multi-hop', '')
                if mhop_state: bfd_peer_state.extend(mhop_state)
        elif bfd_type == 'single':
            uri = rest_urls['config_bfd_shop_peer_list']
            result = get_rest(dut, rest_url=uri)
            if not result or not result.get('output'): return []
            if result['output'].get('openconfig-bfd-ext:single-hop', ''):
                shop_state = result['output'].get('openconfig-bfd-ext:single-hop', '')
                if shop_state: bfd_peer_state.extend(shop_state)
        elif bfd_type == 'multi':
            uri = rest_urls['config_bfd_mhop_peer_list']
            result = get_rest(dut, rest_url=uri)
            if not result or not result.get('output'): return []
            if result['output'].get('openconfig-bfd-ext:multi-hop', ''):
                mhop_state = result['output'].get('openconfig-bfd-ext:multi-hop', '')
                if mhop_state: bfd_peer_state.extend(mhop_state)
    else:
        if type == 'peers':
            peer_data = dict()
            hop_type = 'shop' if bfd_type == 'single' else 'mhop'
            if not kwargs.get('peer', '') or not kwargs.get('vrf', ''):
                st.error('Mandatory params not provided to perform a rest operation')
                return []

            intf = kwargs['interface'] if kwargs.get('interface', '') else 'null'
            local_addr = kwargs['local_addr'] if kwargs.get('local_addr', '') else 'null'
            peer_data['vrf'] = kwargs.get('vrf', 'default')
            peer_data['remote-address'] = kwargs.get('peer')
            peer_data['interface'] = kwargs.get('interface', '')
            peer_data['local-address'] = kwargs.get('local_addr', '')

            key_map = {'uptime': 'last-up-time', 'downtime': 'last-failure-time', 'local_id': 'local-discriminator',
                        'remote_id': 'remote-discriminator', 'status': 'session-state',
                        'diagnostics': 'local-diagnostic-code',
                        'remote_diagnostics': 'remote-diagnostic-code', 'peer_type': 'session-type',
                        'multiplier_local': 'detection-multiplier', 'multiplier_remote': 'remote-multiplier',
                        'tx_interval_local': 'desired-minimum-tx-interval',
                        'tx_interval_remote': 'remote-desired-transmission-interval',
                        'rx_interval_local': 'required-minimum-receive',
                        'rx_interval_remote': 'remote-minimum-receive-interval',
                        'echo_tx_interval_local': 'desired-minimum-echo-receive',
                        'echo_tx_interval_remote': 'remote-echo-receive-interval',
                        'passive_mode': 'passive-mode', 'bfd_profile': 'active-profile'}
            if bfd_type == 'multi':
                key_map.pop('echo_tx_interval_local', '')
                key_map.pop('echo_tx_interval_remote', '')
                key_map.update({'min_ttl': 'minimum-ttl'})

            peer_data['state'] = dict()
            for key, map in key_map.items():
                cmd = 'get_bfd_peer_state_{}'.format(key)
                uri = rest_urls[cmd].format(hop_type, bfd_type, peer_data['remote-address'], intf, peer_data['vrf'], local_addr)
                result = get_rest(dut, rest_url=uri)
                if result and result.get('output'):
                    peer_data['state'][map] = result['output'].get('openconfig-bfd-ext:{}'.format(map), '')
                else:
                    st.error('Rest response failed for uri type: {}'.format(map))
                    peer_data['state'][map] = ''
            bfd_peer_state.append(peer_data)

    if not bfd_peer_state: return []

    bfd_rest_data = []
    for peer_info in bfd_peer_state:
        temp=dict()
        if not peer_info.get('state'): continue
        if type == 'brief':
            temp['scount'] = str(len(bfd_peer_state))
            temp['sessionid'] = peer_info['state'].get('local-discriminator', '')
            temp['ouraddress'] = peer_info.get('local-address') if peer_info.get('local-address') != 'null' else 'unknown'
            temp['peeraddress'] = peer_info.get('remote-address', '')
            temp['status'] = peer_info['state'].get('session-state', '').lower()
            temp['vrf'] = peer_info.get('vrf', '')
            bfd_rest_data.append(temp)
        elif type == 'counters':
            temp['peeraddress'] = peer_info.get('remote-address', '')
            temp['vrfname'] = peer_info.get('vrf', '')
            temp['localaddr'] = peer_info.get('local-address', '')
            temp['interface'] = peer_info.get('interface', '')
            temp['cntrlpktin'] = peer_info['state']['async'].get('received-packets', '')
            temp['cntrlpktout'] = peer_info['state']['async'].get('transmitted-packets', '')
            temp['sessionupev'] = peer_info['state']['async'].get('up-transitions', '')
            temp['echopktin'] = peer_info['state']['echo'].get('received-packets', '0') if 'echo' in peer_info['state'] else ''
            temp['echopktout'] = peer_info['state']['echo'].get('transmitted-packets', '0') if 'echo' in peer_info['state'] else ''
            temp['zebranotifys'] = '0'
            temp['sessiondownev'] = peer_info['state'].get('failure-transitions', '')
            bfd_rest_data.append(temp)
        elif type == 'peers':
            temp['peer'] = peer_info.get('remote-address', '')
            temp['vrf_name'] = peer_info.get('vrf', '')
            temp['local_addr'] = peer_info.get('local-address') if peer_info.get('local-address') != 'null' else ''
            temp['interface'] = peer_info.get('interface', '')
            temp['label'] = ''
            uptime = peer_info['state'].get('last-up-time', '')
            uptime = calc_date_time(uptime)
            temp['uptimeday'] = uptime[0]
            temp['uptimehr'] = uptime[1]
            temp['uptimemin'] = uptime[2]
            temp['uptimesec'] = uptime[3]
            downtime = peer_info['state'].get('last-failure-time', '')
            downtime = calc_date_time(downtime)
            temp['downtimeday'] = downtime[0]
            temp['downtimehr'] = downtime[1]
            temp['downtimemin'] = downtime[2]
            temp['downtimesec'] = downtime[3]
            temp['local_id'] = peer_info['state'].get('local-discriminator', '')
            temp['remote_id'] = peer_info['state'].get('remote-discriminator', '')
            temp['status'] = peer_info['state'].get('session-state', '').lower()
            temp['diagnostics'] = peer_info['state'].get('local-diagnostic-code', '')
            temp['remote_diagnostics'] = peer_info['state'].get('remote-diagnostic-code', '')
            temp['peer_type'] = peer_info['state'].get('session-type', '').lower()
            temp['multiplier'] = [str(peer_info['state'].get('detection-multiplier', '')), str(peer_info['state'].get('remote-multiplier', ''))]
            temp['tx_interval'] = [str(peer_info['state'].get('desired-minimum-tx-interval', '')), str(peer_info['state'].get('remote-desired-transmission-interval', ''))]
            temp['rx_interval'] = [str(peer_info['state'].get('required-minimum-receive', '')), str(peer_info['state'].get('remote-minimum-receive-interval', ''))]
            temp['echo_tx_interval'] = [str(peer_info['state'].get('desired-minimum-echo-receive', '')), str(peer_info['state'].get('remote-echo-receive-interval', ''))]
            temp['min_ttl'] = str(peer_info['state'].get('minimum-ttl', ''))
            p_mode = peer_info['state'].get('passive-mode', '')
            temp['passive_mode'] = 'Enabled' if p_mode else 'Disabled'
            temp['profile_name'] = peer_info['state'].get('active-profile', '')
            temp['err'] = ''
            bfd_rest_data.append(temp)
    st.banner("Rest Output")
    st.log('REST OUTPUT: {}'.format(bfd_rest_data))
    return bfd_rest_data


def calc_date_time(val):
    if not val:
        return [''] * 4
    data = str(datetime.timedelta(seconds=int(val)))
    days = '0'
    if 'days' in data:
        days, _, data = data.split(' ')
    hour, minute, second = data.split(':')
    return (days, str(int(hour)), str(int(minute)), str(int(second)))


def config_bfd_profile(dut, **kwargs):
    """
    Author: lakshminarayana.d@broadcom.com
    :param :multiplier
    :type :detect-multiplier
    :param :rx_intv
    :type :rx-interval
    :param :tx_intv
    :type :tx-interval
    :param :min_ttl
    :type :minimum-ttl
    :param :passive_mode
    :type :True or False
    :param :echo_mode
    :type :True or False
    :param :shutdown
    :type :True or False
    :param :echo_intv
    :type :echo-interval
    :param :profile_name
    :type :string
    :param :config
    :type :yes(default) or no
    :param :dut
    :type :dut
    :return:
    :rtype:

    usage:
    config_bfd_profile(dut1, profile_name='test', config='yes')
    config_bfd_profile(dut1, profile_name='test', multiplier='10', rx_intv="200",tx_intv="300")
    config_bfd_profile(dut1, profile_name='test', multiplier='10', rx_intv="200",tx_intv="300", passive_mode=True, echo_mode=True, echo_intv='100')
    config_bfd_profile(dut1, profile_name='test', multiplier='10', rx_intv="200",tx_intv="300", passive_mode=False, echo_mode=False, echo_intv='100')
    config_bfd_profile(dut1, profile_name='test', config='no')
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.pop('skip_error', False)
    operation = kwargs.pop('operation', Operation.CREATE)

    if 'config' in kwargs and kwargs['config'] == 'no':
        config=kwargs['config']
        del kwargs['config']
    else:
        config=''

    if not kwargs.get('profile_name'):
        st.error('Mandatory arguments not provided to create a profile')
        return  False

    #Converting all kwargs to list type to handle single or multiple peers
    kwargs = convert_kwargs_list(**kwargs)



    if cli_type in get_supported_ui_type_list():
        config = 'no' if config == 'no' else 'yes'
        # operation = Operation.CREATE
        for index, profile in enumerate(kwargs['profile_name']):
            bfd_profile_obj = umf_bfd.Profile(ProfileName=profile)
            bfd_profile_attr_list = {
                'multiplier': ['DetectionMultiplier', int(kwargs['multiplier'][index]) if 'multiplier' in kwargs else None],
                'rx_intv': ['RequiredMinimumReceive', int(kwargs['rx_intv'][index]) if 'rx_intv' in kwargs else None],
                'tx_intv': ['DesiredMinimumTxInterval', int(kwargs['tx_intv'][index]) if 'tx_intv' in kwargs else None],
                'passive_mode': ['PassiveMode', True if 'passive_mode' in kwargs and kwargs['passive_mode'][index] else False],
                'min_ttl': ['MinimumTtl', int(kwargs['min_ttl'][index]) if 'min_ttl' in kwargs else False],
                'echo_mode': ['EchoActive', True if 'echo_mode' in kwargs and kwargs['echo_mode'][index] else False],
                'shutdown': ['Enabled',  False if 'shutdown' in kwargs and kwargs['shutdown'][index] else 'true'],
                'echo_intv': ['DesiredMinimumEchoReceive', int(kwargs['echo_intv'][index]) if 'echo_intv' in kwargs else None],
            }
            if config == 'yes':
                for key, attr_value in  bfd_profile_attr_list.items():
                    if key in kwargs and attr_value[1] is not None:
                        setattr(bfd_profile_obj, attr_value[0], attr_value[1])
                result = bfd_profile_obj.configure(dut, operation=operation, cli_type=cli_type)
            else:
                result = bfd_profile_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config BFD Profile {}'.format(result.data))
                return False

        return True
    if cli_type == 'click':
        if 'shutdown' not in kwargs and config != 'no':
            kwargs['shutdown'] = [False] * len(kwargs['profile_name'])

    if cli_type in ['click', 'klish']:
        st.log("Entering BFD..")
        my_cmd = list()
        my_cmd.append('bfd')
        for index, profile in enumerate(kwargs['profile_name']):
            my_cmd.append('{} profile {}'.format(config, profile))
            if config != 'no':
                if 'multiplier' in kwargs:
                    my_cmd.append("detect-multiplier {}".format(kwargs['multiplier'][index]))
                if 'rx_intv' in kwargs:
                    my_cmd.append("receive-interval {}".format(kwargs['rx_intv'][index]))
                if 'tx_intv' in kwargs:
                    my_cmd.append("transmit-interval {}".format(kwargs['tx_intv'][index]))
                if 'passive_mode' in kwargs:
                    config_mode = '' if kwargs['passive_mode'][index] else 'no'
                    my_cmd.append("{} passive-mode".format(config_mode))
                if 'min_ttl' in kwargs:
                    my_cmd.append("minimum-ttl {}".format(kwargs['min_ttl'][index]))
                if 'echo_mode' in kwargs:
                    config_mode = '' if kwargs['echo_mode'][index] else 'no'
                    my_cmd.append("{} echo-mode".format(config_mode))
                if 'shutdown' in kwargs:
                    config_mode = '' if kwargs['shutdown'][index] else 'no'
                    my_cmd.append("{} shutdown".format(config_mode))
                if 'echo_intv' in kwargs:
                    my_cmd.append("echo-interval {}".format(kwargs['echo_intv'][index]))
                my_cmd.append('exit')
        my_cmd.append('exit')
        if cli_type == 'click':
            st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)
        elif cli_type == 'klish':
            st.config(dut, my_cmd, type=cli_type, skip_error_check=skip_error)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        peer_list = []
        for index, profile in enumerate(kwargs['profile_name']):
            temp = dict()
            temp['profile-name'] = profile
            if 'multiplier' in kwargs: temp['detection-multiplier'] = int(kwargs['multiplier'][index])
            if 'rx_intv' in kwargs: temp['required-minimum-receive'] = int(kwargs['rx_intv'][index])
            if 'tx_intv' in kwargs: temp['desired-minimum-tx-interval'] = int(kwargs['tx_intv'][index])
            if 'min_ttl' in kwargs: temp['minimum-ttl'] = int(kwargs['min_ttl'][index])
            if 'echo_mode' in kwargs:
                temp['echo-active'] = True if kwargs['echo_mode'][index] else False
            if 'passive_mode' in kwargs:
                temp['passive-mode'] = True if kwargs['passive_mode'][index] else False
            if 'shutdown' in kwargs:
                temp['enabled'] = False if kwargs['shutdown'][index] else True
            if 'echo_intv' in kwargs: temp['desired-minimum-echo-receive'] = int(kwargs['echo_intv'][index])
            temp['enabled'] = temp.get('enabled', True)

            data = dict()
            data['profile-name'] = profile
            data['config'] = temp
            peer_list.append(data)
            if config == 'no':
                url = rest_urls['delete_bfd_profile_list'].format(profile)
                if not delete_rest(dut, http_method='delete', rest_url=url):
                    return False
        if not config:
            url = rest_urls['config_bfd_profile_list']
            data = {"openconfig-bfd-ext:bfd-profile": {"profile": peer_list}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def verify_bfd_profile(dut,**kwargs):
    """
    Author:lakshminarayana.d@broadcom.com
    :param  :profile_name
    :type   :profile-name
    :param  :multiplier
    :type   :detect-multiplier
    :param  :rx_interval
    :type   :receive-interval
    :param  :tx_interval
    :type   :transmit-interval
    :param  :echo_tx_interval
    :type   :echo transmission interval
    :param  :minimum_ttl
    :type   :minimum-ttl (list or string)
    :param  :passive_mode
    :type   :Enabled (list or string)
    :param  :echo_mode
    :type   :Enabled (list or string)
    :param  :echo_intv
    :type   :echo-interval (list or string)
    :param  :dut
    :type   :dut
    :return:
    :rtype: True or False

    usage:
    bfd.verify_bfd_profile(dut1,profile_name='test',rx_interval='300',tx_interval='300',minimum_ttl='253')
    bfd.verify_bfd_profile(dut1,profile_name=['test1', 'test2'],rx_interval=['300','300'],tx_interval=['300','300'],echo_intv=['100','200'])
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'vtysh' if cli_type == 'click' else cli_type

    result = False
    kwargs = convert_kwargs_list(**kwargs)
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        profile_data = dict()
        verify_res=list()
        attr_mapping = {"multiplier":"DetectionMultiplier", "rx_interval":"RequiredMinimumReceive", "tx_interval":"DesiredMinimumTxInterval","minimum_ttl":"MinimumTtl", "passive_mode":"PassiveMode",
                        "echo_mode":"EchoActive", "echo_intv":"DesiredMinimumEchoReceive"}
        for index, profile in enumerate(kwargs.get("profile_name")):
            for key,value in attr_mapping.items():
                if key in kwargs and key in ['echo_mode', 'passive_mode']:
                    kwargs[key][index] = True if kwargs[key][index] == 'Enabled' else False
                if kwargs.get(key):
                    profile_data.update({value:kwargs[key][index]})
                else:
                    profile_data.update({value: None})
            st.debug("PROFILE DATA for {} profile is {}:".format(profile, profile_data))
            bfd_profile_obj = umf_bfd.Profile(ProfileName=profile, **profile_data)
            rv = bfd_profile_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
            verify_res.append(True if rv.ok() else False)
        return all(verify_res)

    profile = None if len(kwargs['profile_name']) > 1 else kwargs['profile_name'][0]
    st.log("Verify show bfd profile")
    output = get_bfd_profile(dut, profile_name=profile, cli_type=cli_type)

    if cli_type == 'vtysh': return True
    if bool(output) == 0:
        st.error("Show bfd profile OUTPUT is Empty")
        return result

    for i in range(len(kwargs['profile_name'])):
        profile_index = None
        st.log("Validation for BFD Profiles : %s" % kwargs['profile_name'][i])
        for profile_info in output:
            if profile_info['profile_name'] == kwargs['profile_name'][i]:
                profile_index = output.index(profile_info)
        if profile_index is not None:
            for k in kwargs.keys():
                if output[profile_index][k] == kwargs[k][i]:
                    st.log('Match Found for %s :: Expected: %s  Actual : %s' % (k,kwargs[k][i],output[profile_index][k]))
                    result=True
                else:
                    st.error('Match Not Found for %s :: Expected: %s  Actual : %s' % (k,kwargs[k][i],output[profile_index][k]))
                    return False
        else:
            st.error("BFD profile %s not in output"%kwargs['profile_name'][i])
            return False
    return True


def get_bfd_profile(dut, **kwargs):
    """
    :param dut: DUT name where the CLI needs to be executed
    :type dut: string
    :param profile_name
    :type None (display all profiles), profile_name (to display particular profile)
    """
    cli_type = st.get_ui_type(dut, cli_type=kwargs.get('cli_type'))
    cli_type = 'vtysh' if cli_type == 'click' else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    profile = kwargs.get('profile_name', None)

    if cli_type == 'vtysh':
        st.log("'show bfd profile' command is not available in vtysh mode")
        return list()
    if cli_type == 'klish':
        if profile is None:
            return st.show(dut, "show bfd profile", type=cli_type)
        else:
            return st.show(dut, "show bfd profile {}".format(profile), type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        profile_list = True if not profile else False
        return rest_get_bfd_profile(dut, profile_list=profile_list, **kwargs)
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return list()


def convert_kwargs_list(**kwargs):
    for key in kwargs:
        if key != 'local_asn':
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]
    return kwargs


def rest_get_bfd_profile(dut, profile_list=True, **kwargs):
    """
    Author: Lakshminarayana D(lakshminarayana.d@broadcom.com)
    :param dut:
    :param profile_list: True: get all profile info, False: get particular profile info
    :return:
    """
    rest_urls = st.get_datastore(dut, "rest_urls")
    profile_info = []
    if profile_list:
        uri = rest_urls['config_bfd_profile_list']
        result = get_rest(dut, rest_url=uri)
        if not result or not result.get('output'): return []
        if result['output'].get("openconfig-bfd-ext:bfd-profile", ''):
            profile_data = result['output'].get("openconfig-bfd-ext:bfd-profile", '')
            if profile_data: profile_info.extend(profile_data['profile'])
    else:
        profile_data = dict()
        if not kwargs.get('profile_name', ''):
            st.error('Mandatory params not provided to perform a rest operation')
            return []

        key_map = {'multiplier': 'detection-multiplier', 'echo_mode': 'echo-active',
                   'tx_interval': 'desired-minimum-tx-interval',
                   'rx_interval': 'required-minimum-receive',
                   'echo_tx_interval': 'desired-minimum-echo-receive',
                   'profile_status': 'enabled', 'minimum_ttl': 'minimum-ttl',
                   'passive_mode': 'passive-mode', 'profile_name': 'profile-name'}

        profile_data['state'] = dict()
        profile = kwargs['profile_name']
        uri = rest_urls['get_bfd_profile_bfd_profile_state'].format(profile)
        result = get_rest(dut, rest_url=uri)
        if result and not result["status"] in [200, 201, 204]:
            return []
        for key, map in key_map.items():
            cmd = 'get_bfd_profile_{}'.format(key)
            uri = rest_urls[cmd].format(profile)
            result = get_rest(dut, rest_url=uri)
            if result:
                profile_data['state'][map] = result['output'].get('openconfig-bfd-ext:{}'.format(map), '')
            else:
                st.error('Rest response failed for uri type: {}'.format(map))
                profile_data['state'][map] = ''
        profile_info.append(profile_data)

    bfd_rest_data = []
    for peer_info in profile_info:
        if not peer_info.get('state'): continue
        temp=dict()
        temp['profile_status'] = str(peer_info['state'].get('enabled', ''))
        temp['multiplier'] = str(peer_info['state'].get('detection-multiplier', ''))
        temp['tx_interval'] = str(peer_info['state'].get('desired-minimum-tx-interval', ''))
        temp['rx_interval'] = str(peer_info['state'].get('required-minimum-receive', ''))
        temp['echo_tx_interval'] = str(peer_info['state'].get('desired-minimum-echo-receive', ''))
        temp['minimum_ttl'] = str(peer_info['state'].get('minimum-ttl', ''))
        echo_mode = peer_info['state'].get('echo-active', '')
        temp['echo_mode'] = 'Enabled' if echo_mode is True else 'Disabled'
        passive_mode = peer_info['state'].get('passive-mode', '')
        temp['passive_mode'] = 'Enabled' if passive_mode is True else 'Disabled'
        temp['profile_name'] = peer_info['state'].get('profile-name', '')
        bfd_rest_data.append(temp)
    st.banner("Rest Output")
    st.log('REST OUTPUT: {}'.format(bfd_rest_data))

    return bfd_rest_data
