import re
from spytest import st
import apis.common.asic as asicapi
import apis.routing.vrrp as vrrp_api
from apis.system.rest import config_rest, delete_rest,get_rest
from apis.routing.ip_rest import get_subinterface_index
from utilities.common import filter_and_select
from utilities.utils import get_interface_number_from_name, get_intf_short_name, get_supported_ui_type_list
#from utilities.utils import get_intf_short_name

get_phy_port = lambda intf: re.search(r"(\S+)\.\d+", intf).group(1) if re.search(r"(\S+)\.\d+", intf) else intf

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type

def verify_vrrpv3(dut,**kwargs):
    """
    Author:raghukumar.thimmareddy@broadcom.com

    :param interface:
    :type string
    :param vrid:
    :type string or integer
    :param version:
    :type string or interger
    :param vip:
    :type virtual-ip in string
    :param vmac:
    :type virtual-mac as string
    :param state:
    :type vrrp state as string
    :param config_prio:
    :type configured vrrp priority as integer or string
    :param current_prio:
    :type Current vrrp priority as integer or string
    :param adv_interval:
    :type  advertrisement interval as integer or string
    :param track_interface_list:
    :type List of uplink track interfaces
    :param track_priority_list
    :type List of priorities for uplink tracking ports
    :param track_state_list
    :type List of states for uplink tracking ports
    :param preempt
    :type preempt state as string

    usage:
     verify_vrrpv3(dut1,vrid='1',interface='Vlan1000',state='Master',vip='10.0.0.10',track_interface_list=['Vlan10'],track_state_list=['Up'],
     track_priority_list=['10'],adv_interval=1,vmac='0000.5e00.0201',config_prio=90,current_prio=100,version=3,preempt='disabled')
    """
    if 'interface' not in kwargs or 'vrid' not in kwargs:
        st.error("Mandatory arguments \'interface\' or \'vrid \' missing")
        return False

    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    
    cli_type='klish' if cli_type in get_supported_ui_type_list() and ('vmac' in kwargs) else cli_type
    if cli_type in get_supported_ui_type_list():
        return vrrp_api.verify_vrrp(dut, addr_family='ipv6', **kwargs)
    
    if cli_type == 'click':
        kwargs['interface'] = get_intf_short_name(kwargs['interface'])
        if 'track_interface_list' in kwargs:
            kwargs['track_interface_list'] = [ get_intf_short_name(i) for i in kwargs['track_interface_list']]
        cmd = "show vrrp6 {} {}".format(kwargs['interface'],kwargs['vrid'])
        parsed_output = st.show(dut,cmd,type=cli_type)

    elif cli_type == 'klish':
        cmd = "show vrrp6 interface {} vrid {}".format(kwargs['interface'],kwargs['vrid'])
        parsed_output = st.show(dut,cmd,type=cli_type)

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        index = get_subinterface_index(dut, kwargs['interface'])
        if not index:
            st.error("Failed to get index for interface: {}".format(kwargs['interface']))
            index = 0
        interface_name = get_phy_port(kwargs['interface'])
        interface_ip ='1::1'
        track_priority_list =[]
        vmac_01 ='0000.5e00.02'
        track_state_list =[]
        preempt =''
        track_interface_list =[]
        vrid =''
        config_prio =''
        vip =''
        current_prio =''
        adv_interval =''
        state =''
        version =''
        interface =kwargs['interface']
        track_state =''
        multi_var =[]

        if "PortChannel" in interface_name or "Eth" in interface_name:
            rest_url = rest_urls['show_vrrpv3_sub_interface'].format(interface_name,index,interface_ip,kwargs['vrid'])
        elif "Vlan" in interface_name:
            rest_url = rest_urls['show_vrrpv3'].format(interface_name,interface_ip,kwargs['vrid'])

        out = get_rest(dut, rest_url=rest_url)
        config_prio = str(out['output']['openconfig-if-ip:vrrp-group'][0]['state']['priority'])
        adv_interval = str(out['output']['openconfig-if-ip:vrrp-group'][0]['state']['advertisement-interval'])
        preempt = str(out['output']['openconfig-if-ip:vrrp-group'][0]['state']['preempt'])
        if preempt == 'True':
            preempt ='enabled'
        else:
            preempt ='disabled'

        version =str(out['output']['openconfig-if-ip:vrrp-group'][0]['state']['openconfig-interfaces-ext:version'])
        vrid = str(out['output']['openconfig-if-ip:vrrp-group'][0]['virtual-router-id'])
        if 'virtual-address' in out['output']['openconfig-if-ip:vrrp-group'][0]['state']:
            vip = str(out['output']['openconfig-if-ip:vrrp-group'][0]['state']['virtual-address'][0])

        state = str(out['output']['openconfig-if-ip:vrrp-group'][0]['state']['openconfig-interfaces-ext:status'])
        if state == '2':
            state = 'Master'
        elif state == '1':
            state = 'Backup'
        else:
            state = 'Down'
        b =hex(int(vrid))
        c =b[2:]
        if len(b) <4:
            vmac = "".join([vmac_01, '0', c])
        else:
            vmac = "".join([vmac_01, c])

        if 'openconfig-interfaces-ext:vrrp-track' in out['output']['openconfig-if-ip:vrrp-group'][0]:
            len_entries =len(out['output']['openconfig-if-ip:vrrp-group'][0]['openconfig-interfaces-ext:vrrp-track']['vrrp-track-interface'])
            for i in range(len_entries):
                entry = out['output']['openconfig-if-ip:vrrp-group'][0]['openconfig-interfaces-ext:vrrp-track']['vrrp-track-interface'][i]
                track_intf =str(entry['track-intf'])
                track_prio =str(entry['config']['priority-increment'])
                track_state =str(entry['state']['priority-increment'])
                if track_state != '0':
                    track_state ='Up'
                else:
                    track_state ='Down'
                track_interface_list.append(track_intf);track_priority_list.append(track_prio);track_state_list.append(track_state)
            total = 0
            for element,track_st in zip (track_priority_list,track_state_list):
                if track_st != 'Down':
                    total += int(element)
            current_prio =int(config_prio)+total
            single_var = {'vmac': vmac,'current_prio': current_prio,'config_prio':config_prio, 'adv_interval' :adv_interval, 'preempt': preempt, 'version': version, 'vrid': vrid, 'vip': vip, 'state': state, 'interface': interface,'track_priority_list': track_priority_list,'track_state_list': track_state_list,'track_interface_list': track_interface_list  }
            multi_var.append(single_var)
        else:
            current_prio = config_prio
            single_var = {'vmac': vmac,'current_prio': current_prio,'config_prio':config_prio, 'adv_interval' :adv_interval, 'preempt': preempt, 'version': version, 'vrid': vrid, 'vip': vip, 'state': state, 'interface': interface,'track_priority_list': [],'track_state_list': [],'track_interface_list': [] }
            multi_var.append(single_var)

        parsed_output =multi_var
        st.banner(parsed_output)

    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return parsed_output
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each],parsed_output[0][each]))
            return False
    return True


def configure_vrrpv3(dut,config="yes",addr_family='ipv6',skip_error = False, **kwargs):
    """
    author:raghukumar.thimmareddy@broadcom.com
    :param vrid:
    :type virtual router id:
    :param interface:
    :type interface:
    :param adv_interval:
    :type advertisement interval:
    :param priority:
    :type vrrp priority:
    :param pre_empt:
    :type pre_empt:
    :param version:
    :type version:
    :param vip:
    :type virtual ip:
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    configure_vrrpv3(dut1, vrid="10",vip="50.1.1.2",interface="Ethernet0",config="yes",version ="3")
    configure_vrrpv3(dut1, vrid="11",vip="60.1.1.2",interface="Ethernet10",adv_interval="10",priority="101",track_interface_list=["Ethernet0",Ethernet4"],track_priority_list=[10,20])
    """

    if 'interface' not in kwargs or 'vrid' not in kwargs:
        st.error("Mandatory parameter - interface or vrid is missing")
        return False

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if cli_type in get_supported_ui_type_list():
        return vrrp_api.configure_vrrp(dut, config=config, addr_family='ipv6', skip_error=skip_error, **kwargs)
    cmd =''
    if cli_type == 'click':
        VRRP_CMD = 'sudo config interface vrrp6'
        if config.lower() == "yes":
            if 'version' in kwargs:
                cmd = "sudo config interface vrrp version {} {} {}\n".format(kwargs['interface'],kwargs['vrid'], kwargs['version'])
            if 'enable' in kwargs:
                cmd = "{} add {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'])

            if  'adv_interval' in kwargs:
                cmd = " {} adv_interval {} {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'], kwargs['adv_interval'])

            if  'priority' in kwargs:
                cmd += "{} priority {} {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'], kwargs['priority'])

            if  'preempt' in kwargs:
                cmd += "{} pre_empt enable {} {} \n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'])

            if  'vip' in kwargs:
                cmd += "{} vip add {} {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'], kwargs['vip'])

            if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                    st.error("Please check the track interface list and track priority list, number of entries should be same")
                    return False
                for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):
                    cmd += "{} track_interface add {} {} {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'],track_intf,track_prio)

        elif config.lower() == "no":
            if 'disable' in kwargs:
                cmd = "{} remove {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'])

            if 'vip' in kwargs:
                cmd += "{} vip remove {} {} {}\n".format(VRRP_CMD, kwargs['interface'], kwargs['vrid'], kwargs['vip'])

            if 'adv_interval' in kwargs or 'priority' in kwargs:
                st.log("Cannot remove/delete the adv_interval or priority, please set it to default value")

            if  'preempt' in kwargs:
                cmd += "{} pre_empt disable {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'])

            if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                    st.error("Please check the track interface list and track priority list, number of entries should be same")
                    return False
                for track_intf, track_prio in zip(kwargs['track_interface_list'], kwargs['track_priority_list']):
                    cmd += "{} track_interface remove {} {} {} \n".format(VRRP_CMD, kwargs['interface'],kwargs['vrid'], track_intf )
        output = st.config(dut, cmd, skip_error_check=skip_error,type=cli_type)
        return output
    elif cli_type == "klish":
        pintf = get_interface_number_from_name(kwargs['interface'])
        cmd ="interface {} {}".format(pintf['type'], pintf['number'])
        if config.lower() == "yes":
            if 'vrid' in kwargs:
                cmd += "\n" +  " vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)
            if 'priority' in kwargs:
                cmd += "priority {}\n".format(kwargs['priority'])
            if 'adv_interval' in kwargs:
                cmd += "advertisement-interval {}\n".format(kwargs['adv_interval'])
            if  'vip' in kwargs:
                cmd += "vip {}\n".format(kwargs['vip'])
            if  'preempt' in kwargs:
                cmd +=  "preempt\n"
            if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                    st.error("lease check the track interface list and track priority list, number of entries should be same")
                    return False
                for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):
                    cmd += "track-interface {} weight {}\n".format(track_intf,track_prio)
            cmd += "exit\n"
        elif config.lower() == "no":
            if  'vip' in kwargs:
                cmd += "\n" +  " vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)
                cmd += "no vip {}\n".format(kwargs['vip'])
            if  'preempt' in kwargs:
                cmd += "\n" +  " vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)
                cmd +=  "no preempt\n"
            if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                    st.error("Please check the track interface list and track priority list, number of entries should be same")
                    return False
                cmd += "\n" +  " vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)
                for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):
                    cmd += "no track-interface {}\n".format(track_intf)
            if 'vrid' in kwargs and 'disable' in kwargs:
                cmd += "\n" + "no vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)
        cmd += " exit\n"
        output =st.config(dut, cmd, skip_error_check=skip_error, type=cli_type)
        return output
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        index = get_subinterface_index(dut, kwargs['interface'])
        if not index:
            st.error("Failed to get index for interface: {}".format(kwargs['interface']))
            index = 0
        interface_name = get_phy_port(kwargs['interface'])
        interface_ip ='1::1'
        if config.lower() == "yes":
            if "PortChannel" in interface_name or "Eth" in interface_name:
                if 'vrid' in kwargs:
                    rest_url = rest_urls['vrrp_config_sub_interface'].format(interface_name,index,addr_family,interface_ip)
                    payload ={"openconfig-if-ip:vrrp": {"vrrp-group": [{"config": {"virtual-router-id": kwargs['vrid']}, "virtual-router-id": kwargs['vrid']}]}}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if 'priority' in kwargs:
                    if kwargs['priority'] != 100:
                        rest_url = rest_urls['vrrp_priority_sub_interface'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'])
                        payload = {"openconfig-if-ip:priority":kwargs['priority']}
                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                    else:
                        rest_url = rest_urls['vrrp_priority_sub_interface'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'])
                        payload = {"openconfig-if-ip:priority":kwargs['priority']}
                        if not delete_rest(dut, rest_url=rest_url, timeout=100):
                            st.error("Failed to delete priority ")
                            return False
                if 'version' in kwargs:
                    rest_url = rest_urls['vrrp_version_sub_interface'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'])
                    payload ={"openconfig-interfaces-ext:version": kwargs['version']}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if 'adv_interval' in kwargs:
                    rest_url = rest_urls['vrrp_advt_interval_sub_interface'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'])
                    payload ={"openconfig-if-ip:advertisement-interval": kwargs['adv_interval']}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if  'vip' in kwargs:
                    rest_url = rest_urls['vrrp_vip_sub_interface'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'])
                    payload ={"openconfig-if-ip:virtual-address": [kwargs['vip']]}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if  'preempt' in kwargs:
                    rest_url = rest_urls['vrrp_preempt_sub_interface'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'])
                    payload ={"openconfig-if-ip:preempt":bool(1)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                    if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                        st.error("lease check the track interface list and track priority list, number of entries should be same")
                        return False
                    for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):
                        rest_url = rest_urls['vrrp_track_interface_sub_interface'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'])
                        payload ={"openconfig-interfaces-ext:vrrp-track":{"vrrp-track-interface":[{"track-intf":track_intf,"config":{"track-intf":track_intf,"priority-increment":track_prio}}]}}
                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

            elif "Vlan" in interface_name:
                if 'vrid' in kwargs:
                    rest_url = rest_urls['vrrpv3_config_all'].format(interface_name,interface_ip)
                    payload ={"openconfig-if-ip:vrrp": {"vrrp-group": [{"config": {"virtual-router-id": kwargs['vrid']}, "virtual-router-id": kwargs['vrid']}]}}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if 'priority' in kwargs:
                    if kwargs['priority'] != 100:
                        rest_url = rest_urls['vrrpv3_priority'].format(interface_name,interface_ip,kwargs['vrid'])
                        payload = {"openconfig-if-ip:priority":kwargs['priority']}
                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                    else:
                        rest_url = rest_urls['vrrpv3_priority'].format(interface_name,interface_ip,kwargs['vrid'])
                        payload = {"openconfig-if-ip:priority":kwargs['priority']}
                        if not delete_rest(dut, rest_url=rest_url, timeout=100):
                            st.error("Failed to delete priority ")
                            return False
                if 'adv_interval' in kwargs:
                    rest_url = rest_urls['vrrpv3_advt_interval'].format(interface_name,interface_ip,kwargs['vrid'])
                    payload ={"openconfig-if-ip:advertisement-interval": kwargs['adv_interval']}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if  'vip' in kwargs:
                    rest_url = rest_urls['vrrpv3_vip'].format(interface_name,interface_ip,kwargs['vrid'])
                    payload ={"openconfig-if-ip:virtual-address": [kwargs['vip']]}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if  'preempt' in kwargs:
                    rest_url = rest_urls['vrrpv3_preempt'].format(interface_name,interface_ip,kwargs['vrid'])
                    payload ={"openconfig-if-ip:preempt":bool(1)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                    if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                        st.error("lease check the track interface list and track priority list, number of entries should be same")
                        return False
                    for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):
                        rest_url = rest_urls['vrrpv3_track_interface'].format(interface_name,interface_ip,kwargs['vrid'])
                        payload ={"openconfig-interfaces-ext:vrrp-track":{"vrrp-track-interface":[{"track-intf":track_intf,"config":{"track-intf":track_intf,"priority-increment":track_prio}}]}}
                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

        if config.lower() == "no":
            if "Vlan" in interface_name:
                if  'vip' in kwargs:
                    rest_url = rest_urls['vrrp_vip_delete'].format(interface_name,addr_family,interface_ip,kwargs['vrid'],kwargs['vip'])
                    if not delete_rest(dut, rest_url=rest_url, timeout=100):
                        st.error("Failed to delete vip ")
                        return False
                if  'preempt' in kwargs:
                    rest_url = rest_urls['vrrpv3_preempt'].format(interface_name,interface_ip,kwargs['vrid'])
                    payload ={"openconfig-if-ip:preempt":bool(0)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                    if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                        st.error("Please check the track interface list and track priority list, number of entries should be same")
                        return False
                    for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):
                        rest_url = rest_urls['vrrpv3_track_interface_delete'].format(interface_name,interface_ip,kwargs['vrid'],track_intf)
                        if not delete_rest(dut, rest_url=rest_url, timeout=100):
                            st.error("Failed to delete track-interface ")
                            return False
                if 'vrid' in kwargs and 'disable' in kwargs:
                    rest_url = rest_urls['vrrpv3_delete'].format(interface_name,interface_ip,kwargs['vrid'])
                    if not delete_rest(dut, rest_url=rest_url, timeout=100):
                        st.error("Failed to delete vrrp config ")
                        return False
            elif "PortChannel" in interface_name or "Eth" in interface_name:
                if  'vip' in kwargs:
                    rest_url = rest_urls['vrrp_vip_sub_interface_delete'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'],kwargs['vip'])
                    if not delete_rest(dut, rest_url=rest_url, timeout=100):
                        st.error("Failed to delete vip ")
                        return False
                if  'preempt' in kwargs:
                    rest_url = rest_urls['vrrp_preempt_sub_interface'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'])
                    payload ={"openconfig-if-ip:preempt":bool(0)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                    if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                        st.error("Please check the track interface list and track priority list, number of entries should be same")
                        return False
                    for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):
                        rest_url = rest_urls['vrrp_track_interface_sub_interface_delete'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'],track_intf)
                        if not delete_rest(dut, rest_url=rest_url, timeout=100):
                            st.error("Failed to delete track-interface ")
                            return False
                if 'vrid' in kwargs and 'disable' in kwargs:
                    rest_url = rest_urls['vrrp_delete_sub_interface'].format(interface_name,index,addr_family,interface_ip,kwargs['vrid'])
                    if not delete_rest(dut, rest_url=rest_url, timeout=100):
                        st.error("Failed to delete vrrp config ")
                        return False

    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False



def debug_vrrpv3(dut_list):
    """
    Author : Raghukumar Rampur
    email : raghukumar.thimmareddy@broadcom.com
    :param dut_list:
    :return:
    """
    st.log("### Start of Debug commands #####")
    def f1(dut):
        st.show(dut, 'show vrrp6', skip_tmpl=True)
        st.show(dut, 'teamshow', skip_tmpl=True)
        st.show(dut, 'show mac', skip_tmpl=True)
        st.show(dut, 'show ip route', skip_tmpl=True)
        st.show(dut, 'show ipv6 route', skip_tmpl=True)
        st.show(dut, 'show vlan brief', skip_tmpl=True)
        asicapi.bcm_show(dut, "l2 show")
        asicapi.bcm_show(dut, "l3 defip show")
        asicapi.bcm_show(dut, "l3 l3table show")
    st.exec_each(dut_list, f1)
    st.log(" End of Dubug commands")



def verify_vrrpv3_summary(dut,**kwargs):
    """
    Author: Raghukumar Rampur
    email : raghukumar.thimmareddy@broadcom.com
    :param dut:
    :param interface:
    :type string or list
    :param vrid:
    :type string or list
    :param vip:
    :type virtual-ip in string or list
    :param state:
    :type vrrp state as string or list
    :param config_prio:
    :type configured vrrp priority as list or string
    :param current_prio:
    :type Current vrrp priority as list or string
    :return:

    Usage
    verify_vrrpv3_summary(dut1,vrid=['49','85'],state=['Master','Backup'],
                             interface=['Vlan2996','Vlan2998'],vip=['73.73.73.66','85.85.85.71'],
                             config_prio=[222,97],current_prio=[222,99])
    verify_vrrpv3_summary(dut1,vrid='49',state='Master')
    """

    ret_val = True

    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    output = st.show(dut,'show vrrp6',type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    #Converting all kwargs to list type to handle single or list of vrrp instances
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
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val

