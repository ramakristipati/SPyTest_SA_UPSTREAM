import pytest
import random
import re

from random import randrange as randomnumber
from datetime import datetime

from spytest import st, tgapi, SpyTestDict

import apis.switching.portchannel as portchannel_obj
import apis.switching.vlan as vlan_obj
import apis.system.interface as intf_obj
import apis.system.logging as slog
from apis.system.reboot import config_save, config_save_reload
import apis.system.lldp as lldp_obj
import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.routing.arp as arp_obj
import apis.system.port as port_obj
import apis.system.rest as rest_obj
import apis.system.reboot as reboot_obj
import apis.debug.knet as knet_api

from utilities.utils import report_tc_fail, retry_api, validate_link_events
from utilities.utils import convert_intf_name_to_component
from utilities.parallel import exec_all, exec_parallel, ExecAllFunc
from utilities.common import random_vlan_list, poll_wait, filter_and_select, make_list
from utilities.common import parse_integer

vars = dict()
data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def portchannel_module_hooks(request):
    # add things at the start of this module
    global vars
    data.module_unconfig = False
    data.portchannel_name = "PortChannel7"
    data.portchannel_name2 = "PortChannel8"
    data.queue_id = {'PKT_TYPE_LACP': 23}
    data.vlan = (random_vlan_list(count=2))
    data.vid = data.vlan[0]
    data.vlan_id = data.vlan[1]
    data.cli_type_click = "click"
    vars = st.ensure_min_topology("D1D2:5", "D1T1:1", "D2T1:1")
    data.lag_up = 'Up'
    data.lag_down = 'Dw'
    data.ip_src_count = 1000
    data.ip_dst_count = 1000
    data.tcp_src_port_count = 1000
    data.tcp_dst_port_count = 1000
    data.ip41 = '10.1.1.1'
    data.ip42 = '30.1.1.1'
    data.ip43 = '40.1.1.1'
    data.src_ip = '10.1.1.2'
    data.dst_ip = '30.1.1.3'
    data.src_port = '123'
    data.dst_port = '234'
    data.graceful_restart_config = False
    data.dut1_rt_int_mac = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    data.my_dut_list = st.get_dut_names()[0:2]
    data.dut1 = st.get_dut_names()[0]
    data.dut2 = st.get_dut_names()[1]
    data.counters_threshold = 15
    data.members_dut1 = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]
    data.members_dut2 = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4]
    data.rest_url = "/restconf/data/sonic-portchannel:sonic-portchannel"
    exec_all(True, [[tg_config], [dut_config]], first_on_main=True)
    yield
    module_unconfig()

def tg_config():
    st.log("Getting TG handlers")
    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg3, data.tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    data.tg = data.tg1
    st.log("Reset and clear statistics of TG ports")
    data.tg.tg_traffic_control(action='reset', port_handle=[data.tg_ph_1, data.tg_ph_3])
    data.tg.tg_traffic_control(action='clear_stats', port_handle=[data.tg_ph_1, data.tg_ph_3])
    data.h1 = data.tg.tg_interface_config(port_handle=data.tg_ph_1, mode='config', intf_ip_addr=data.ip41,
                                          gateway=data.src_ip, arp_send_req='1')
    st.log("INTFCONF: " + str(data.h1))
    data.h2 = data.tg.tg_interface_config(port_handle=data.tg_ph_3, mode='config', intf_ip_addr=data.ip42,
                                          gateway=data.dst_ip, arp_send_req='1')
    st.log("INTFCONF: " + str(data.h2))
    data.streams = {}


def dut_config():
    st.log('Creating port-channel and adding members in both DUTs')
    portchannel_obj.config_portchannel(data.dut1, data.dut2, data.portchannel_name, data.members_dut1,
                                           data.members_dut2, "add")
    st.log('Creating random VLAN in both the DUTs')
    if False in create_vlan_using_thread([vars.D1, vars.D2], [[data.vid], [data.vid]]):
        st.report_fail('vlan_create_fail', data.vid)
    st.log('Adding Port-Channel and TGen connected ports as tagged members to the random VLAN')
    if False in add_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid],
                                        [[data.portchannel_name, vars.D1T1P1],[data.portchannel_name, vars.D2T1P1]]):
        st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)


def module_unconfig():
    if not data.module_unconfig:
        data.module_unconfig = True
        st.log('Module config Cleanup')
        vlan_obj.clear_vlan_configuration([data.dut1, data.dut2])
        portchannel_obj.clear_portchannel_configuration([data.dut1, data.dut2])



@pytest.fixture(scope="function", autouse=True)
def portchannel_func_hooks(request):
    data.tg.tg_traffic_control(action='reset', port_handle=data.tg_ph_1)
    if st.get_func_name(request) == 'test_ft_portchannel_behavior_with_tagged_traffic':
        verify_portchannel_status()
    elif st.get_func_name(request) == 'test_member_status_after_portch_down':
        st.log("for reference")
        verify_portchannel_status()
    elif st.get_func_name(request) == 'test_ft_untagged_traffic_on_portchannel':
        config_test_ft_portchannel_with_new_member_and_untagged_traffic()
        verify_portchannel_status()
    elif st.get_func_name(request) == 'test_ft_lag_l3_hash_sip_dip_l4port':
        config_test_ft_lag_l3_hash_sip_dip_l4port()
        verify_portchannel_status()
    elif st.get_func_name(request) == 'test_ft_portchannel_with_vlan_variations':
        dict1 = {"portchannel": data.portchannel_name, "members": [data.members_dut1[2],
                                            data.members_dut1[3]], "flag": 'del'}
        dict2 = {"portchannel": data.portchannel_name, "members": [data.members_dut2[2],
                                            data.members_dut2[3]], "flag": 'del'}
        exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_del_portchannel_member, [dict1, dict2])
    elif st.get_func_name(request) == 'test_ft_verify_min_links_after_dynamic_lag_creation_001':
        dict1 = {'portchannel': data.portchannel_name, 'members': [vars.D1D2P3, vars.D1D2P4]}
        dict2 = {'portchannel': data.portchannel_name, 'members': [vars.D2D1P3, vars.D2D1P4]}
        exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_portchannel_member, [dict1, dict2])
    elif st.get_func_name(request) in ['test_ft_verify_min_links_after_dynamic_lag_creation_001',
                                       'test_ft_verify_dynamic_lag_when_min_links_criteria_met_002',
                                       'test_ft_verify_dynamic_lag_when_min_links_criteria_not_met_003',
                                       'test_ft_verify_po_state_after_port_flap_with_min_links_004',
                                       'test_ft_l2_traffic_on_dynamic_lag_with_min_links_functionality_005',
                                       'test_ft_l3_traffic_on_dynamic_lag_with_min_links_functionality_006',
                                       'test_ft_verify_min_links_functionality_by_flapping_all_member_ports_007',
                                       'test_ft_min_link_functionality_during_device_reboot_008',
                                       'test_ft_no_min_link_functionality_during_device_reboot_009']:
        st.log("Verify whether PO is up with default params")
        if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1,dut2_active_mem=data.members_dut2):
            st.report_fail("PortChannel Verification Failed")
    yield
    if st.get_func_name(request) == 'test_ft_portchannel_behavior_with_tagged_traffic':
        portchannel_behavior_with_tagged_traffic_verify()
    elif st.get_func_name(request) == 'test_ft_untagged_traffic_on_portchannel':
        portchannel_behavior_with_untagged_traffic_verify()
    elif st.get_func_name(request) == 'test_ft_lag_l3_hash_sip_dip_l4port':
        unconfig_test_ft_lag_l3_hash_sip_dip_l4port()
    elif st.get_func_name(request) == 'test_ft_portchannel_with_vlan_variations':
        dict1 = {"portchannel": data.portchannel_name, "members": [data.members_dut1[2],
                                                                   data.members_dut1[3]], "flag": 'add'}
        dict2 = {"portchannel": data.portchannel_name, "members": [data.members_dut2[2],
                                                                   data.members_dut2[3]], "flag": 'add'}
        exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_del_portchannel_member, [dict1, dict2])
    elif st.get_func_name(request) == 'test_ft_lacp_graceful_restart_with_save_reload':
        unconfig_test_ft_lacp_graceful_restart_with_save_reload()
    elif st.get_func_name(request) in ['test_ft_verify_min_links_after_dynamic_lag_creation_001',
                                       'test_ft_verify_dynamic_lag_when_min_links_criteria_met_002',
                                       'test_ft_verify_dynamic_lag_when_min_links_criteria_not_met_003',
                                       'test_ft_verify_po_state_after_port_flap_with_min_links_004' ,
                                       'test_ft_l2_traffic_on_dynamic_lag_with_min_links_functionality_005',
                                       'test_ft_l3_traffic_on_dynamic_lag_with_min_links_functionality_006',
                                       'test_ft_verify_min_links_functionality_by_flapping_all_member_ports_007',
                                       'test_ft_min_link_functionality_during_device_reboot_008',
                                       'test_ft_min_link_functionality_during_device_warm_reboot',
                                       'test_ft_no_min_link_functionality_during_device_warm_reboot',
                                       'test_ft_no_min_link_functionality_during_device_reboot_009']:
        st.log("Unconfigure non-default min-links value")
        add_del_config_params_using_thread(min_links=True, flag='del')

def graceful_restart_prolog():
    dict1 = {'portchannel': data.portchannel_name, 'members': [vars.D1D2P3, vars.D1D2P4]}
    dict2 = {'portchannel': data.portchannel_name, 'members': [vars.D2D1P3, vars.D2D1P4]}
    exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.delete_portchannel_member, [dict1, dict2])
    dict1 = {'portchannel_list': data.portchannel_name2}
    dict2 = {'portchannel_list': data.portchannel_name2}
    exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.create_portchannel, [dict1, dict2])
    dict1 = {'portchannel': data.portchannel_name2, 'members': [vars.D1D2P3, vars.D1D2P4]}
    dict2 = {'portchannel': data.portchannel_name2, 'members': [vars.D2D1P3, vars.D2D1P4]}
    exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_portchannel_member, [dict1, dict2])

def unconfig_test_ft_lacp_graceful_restart_with_save_reload():
    dict1 = {'portchannel': data.portchannel_name2, 'members': [vars.D1D2P3, vars.D1D2P4]}
    dict2 = {'portchannel': data.portchannel_name2, 'members': [vars.D2D1P3, vars.D2D1P4]}
    exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.delete_portchannel_member, [dict1, dict2])
    portchannel_obj.delete_portchannel(vars.D1, data.portchannel_name2)
    portchannel_obj.delete_portchannel(vars.D2, data.portchannel_name2)

def verify_portchannel_status(delay=2):
    dict1 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut1, 'iter_delay': delay}
    dict2 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut2, 'iter_delay': delay}
    exec_parallel(True, [vars.D1, vars.D2], verify_portchannel_cum_member_status, [dict1, dict2])

def verify_dynamic_portchannel_summary(**kwargs):
    dut1_state=kwargs.get('dut1_state','Up')
    dut2_state=kwargs.get('dut2_state','Up')
    var_none = [None, None, None, None]
    dut1_active_mem=kwargs.get('dut1_active_mem',var_none)
    dut2_active_mem=kwargs.get('dut2_active_mem',var_none)
    dut1_down_mem=kwargs.get('dut1_down_mem',var_none)
    dut2_down_mem=kwargs.get('dut2_down_mem',var_none)
    [output, _]=exec_all(True, [ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 30, vars.D1,
                                              [data.portchannel_name], [dut1_state], dut1_active_mem, dut1_down_mem, complete_check=True),
                                  ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 30, vars.D2,
                                              [data.portchannel_name], [dut2_state], dut2_active_mem, dut2_down_mem, complete_check=True)])
    if False in output:
        return False
    else:
        return True

def verify_traffic_hashing_on_member_ports(**kwargs):
    data.intf_count1, data.intf_count2 = get_intf_counters_using_thread([vars.D1, vars.D2])
    rx_count = filter_and_select(data.intf_count1, ['rx_ok'], {'iface': vars.D1T1P1})[0]['rx_ok']
    tx_count = filter_and_select(data.intf_count2, ['tx_ok'], {'iface': vars.D2T1P1})[0]['tx_ok']
    tx_count = parse_integer(tx_count, None)
    rx_count = parse_integer(rx_count, None)
    if kwargs.get("Traffic_check"):
        st.log("Total frames sent:{}".format(tx_count))
        st.log("Total frames received:{}".format(rx_count))
        if not tx_count >= 0.95 * rx_count:
            st.error('Traffic loss observed between end to end ports')
            return False
    if kwargs.get("Traffic_check_on_member_ports"):
        temp = rx_count if kwargs.get('port_list') == data.members_dut1 else tx_count
        pkts_per_port = (temp/len(kwargs.get('port_list')))/2
        st.log("Minimum packets expected on each port are {}".format(pkts_per_port))
        if not verify_traffic_hashed_or_not(vars.D1, kwargs.get('port_list'), pkts_per_port):
            st.error("Traffic hashing failing")
            return False
    return True

def capture_and_processing_lacp_packets(dut,port,fast_rate=False):
    st.banner("Capture LACP pkts using TCPDUMP")
    #if '/' in port:
    #    port = st.get_other_names(dut, [port])[0]
    # Given 20sec,180sec interval for fast_rate enable,disable to capture 20,6 packets respectively...
    interval = 20 if fast_rate else 180
    # expected time in secs i.e., 1sec and 30sec
    exp_time = 1 if fast_rate else 30
    port = convert_intf_name_to_component(dut, intf_list=make_list(port), component='kernel')
    tcpdump_cmd = "sudo timeout {}s tcpdump -ni {} -e ether proto 0x8809".format(interval,port)
    result = st.show(dut, tcpdump_cmd, skip_tmpl=True, type='click')
    pkt_timestamps = re.findall(r"\d+:\d+:\d+.\d{6}", result)
    pkts_captured = re.search(r"(\d+) (packets captured)", result)
    if not (pkt_timestamps and pkts_captured):
        st.error("Fail to get tcpdump output..")
        return False
    if fast_rate:
        if int(pkts_captured.group(1)) < 20:
            st.error("Packets captured {} are not in the expected range 20 after fast_rate enabled".format(pkts_captured))
            return False
    else:
        if int(pkts_captured.group(1)) < 6:
            st.error("Packets captured {} are not in the expected range 6 with fast_rate disabled".format(pkts_captured))
            return False
    pkts  = list()
    for time in range(1, len(pkt_timestamps), 2):
        pkts.append(pkt_timestamps[time].split('.')[0])
    for i, j in zip(pkts, pkts[1:]):
        temp1 = datetime.strptime(i, "%H:%M:%S")
        temp2 = datetime.strptime(j, "%H:%M:%S")
        if not abs(int((temp1 - temp2).total_seconds())) == exp_time:
            st.error("Expected time difference {}sec between lacp pkt1_time {} and lacp pkt2_time {} not reached".format(exp_time,temp1,temp2))
            return False
    return True

def create_vlan_using_thread(dut_list, vlan_list, thread = True):
    sub_list = [[vlan_obj.create_vlan, dut, vlan_list[cnt]] for cnt, dut in enumerate(dut_list, start=0)]
    [output, _] = exec_all(thread, sub_list)
    return output

def config_test_ft_portchannel_with_new_member_and_untagged_traffic():
    delete_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                    [data.portchannel_name, vars.D2T1P1]], True)
    add_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                                                [data.portchannel_name, vars.D2T1P1]], tagged=False)
    dict1 = {'vlan_list': data.vid, 'untagged': [data.portchannel_name, vars.D1T1P1]}
    dict2 = {'vlan_list': data.vid, 'untagged': [data.portchannel_name, vars.D2T1P1]}
    output = exec_parallel(True, [vars.D1, vars.D2], vlan_obj.verify_vlan_config, [dict1, dict2])
    if not output[0][0]:
        st.report_fail('vlan_untagged_member_fail', [data.portchannel_name, vars.D1T1P1], data.vid)
    if not output[0][1]:
        st.report_fail('vlan_untagged_member_fail', [data.portchannel_name, vars.D2T1P1], data.vid)


def config_test_ft_lag_l3_hash_sip_dip_l4port():
    delete_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                    [data.portchannel_name, vars.D2T1P1]], True)
    verify_portchannel_status()

def portchannel_behavior_with_tagged_traffic_verify():
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_Mac_Hash1'])
    if data.return_value == 2:
        portchannel_obj.create_portchannel(vars.D1, data.portchannel_name)
        portchannel_obj.add_portchannel_member(vars.D1, data.portchannel_name, data.members_dut1)
    elif data.return_value == 3:
        if not intf_obj.interface_operation(vars.D1, data.portchannel_name, 'startup', skip_verify=False):
            st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    elif data.return_value == 4:
        if not vlan_obj.add_vlan_member(vars.D1, data.vid, [data.portchannel_name], True):
            st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)
        if not vlan_obj.verify_vlan_config(vars.D1, data.vid, tagged=[data.portchannel_name]):
            st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)
    elif data.return_value == 5:
        intf_obj.interface_noshutdown(vars.D1, data.members_dut1, skip_verify=False)
    else:
        dict1 = {'portchannel': data.portchannel_name}
        output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.get_portchannel_members, [dict1, dict1])
        member_ports1 = []
        member_ports2 = []
        for port in data.members_dut1:
            if port not in output[0][0]:
                member_ports1.append(port)
        for port in data.members_dut2:
            if port not in output[0][1]:
                member_ports2.append(port)
        add_del_member_using_thread([vars.D1, vars.D2], [data.portchannel_name, data.portchannel_name],
                                [member_ports1,member_ports2], flag='add')
        intf_obj.interface_noshutdown(vars.D1, data.members_dut1)

def portchannel_behavior_with_untagged_traffic_verify():
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_Mac_Hash3'])
    delete_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                                                               [data.portchannel_name, vars.D2T1P1]])
    add_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                                    [data.portchannel_name, vars.D2T1P1]], tagged=True)

def unconfig_test_ft_portchannel_disabled_with_traffic():
    intf_obj.interface_operation(vars.D1, data.portchannel_name, 'startup')

def unconfig_test_ft_lag_l3_hash_sip_dip_l4port():
    ip_obj.clear_ip_configuration([vars.D1, vars.D2], family='ipv4', thread=True)
    add_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                                    [data.portchannel_name, vars.D2T1P1]],tagged=True)

def clear_intf_counters_using_thread(dut_list, thread=True):
    sub_list = [[intf_obj.clear_interface_counters, dut] for dut in dut_list]
    exec_all(thread, sub_list)

def add_del_member_using_thread(dut_list, portchannel_list, member_list, flag = 'add', thread=True):
    sub_list = []
    if flag == 'add':
        sub_list.append([portchannel_obj.add_del_portchannel_member, dut_list[0], portchannel_list[0], member_list[0],
                         flag, True])
        sub_list.append([portchannel_obj.add_del_portchannel_member, dut_list[1], portchannel_list[1], member_list[1],
                         flag, True])
        exec_all(thread, sub_list)
    else:
        sub_list.append([portchannel_obj.delete_portchannel_member, dut_list[0], portchannel_list[0], member_list[0]])
        sub_list.append([portchannel_obj.delete_portchannel_member, dut_list[1], portchannel_list[1], member_list[1]])
        exec_all(thread, sub_list)

def verify_traffic_hashed_or_not(dut, port_list, pkts_per_port, traffic_loss_verify = False, rx_port = '',
                                 tx_port = '', dut2 ='',**kwargs):
    traffic_drop_check=kwargs.get('traffic_drop_check',False)
    if traffic_loss_verify is True:
        sub_list = []
        sub_list.append([intf_obj.show_interface_counters_all, dut])
        sub_list.append([intf_obj.show_interface_counters_all, dut2])
        [output, _] = exec_all(True, sub_list)
        data.intf_counters_1, data.intf_counters_2 = output
    else:
        data.intf_counters_1 = intf_obj.show_interface_counters_all(dut)
    data.intf_count_dict = {}
    for port in port_list:
        for counter_dict in data.intf_counters_1:
            if counter_dict['iface'] == port:
                try:
                    tx_ok_counter = counter_dict['tx_ok'].replace(',', '')
                    data.intf_count_dict[port] = int(tx_ok_counter) if tx_ok_counter.isdigit() else 0
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                if traffic_drop_check:
                    if (data.intf_count_dict[port] >= pkts_per_port):
                        st.error("Traffic is getting forwarded by the member ports.")
                        return False
                    return True
                if not (data.intf_count_dict[port] >= pkts_per_port):
                    intf_obj.show_interface_counters_detailed(vars.D1, vars.D1T1P1)
                    st.report_fail("traffic_not_hashed", dut)
    if traffic_loss_verify is True:
        for counter_dict in data.intf_counters_1:
            if counter_dict['iface'] == rx_port:
                try:
                    rx_ok_counter = counter_dict['rx_ok'].replace(',', '')
                    data.rx_traffic = int(rx_ok_counter) if rx_ok_counter.isdigit() else 0
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                break
        for counter_dict in data.intf_counters_2:
            if counter_dict['iface'] == tx_port:
                try:
                    tx_ok_counter = counter_dict['tx_ok'].replace(',', '')
                    data.tx_traffic = int(tx_ok_counter) if tx_ok_counter.isdigit() else 0
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                break
        st.log('Total frames sent:{}'.format(data.tx_traffic))
        st.log('Total frames received:{}'.format(data.rx_traffic))
        if not (data.tx_traffic >= 0.95* data.rx_traffic):
            st.log("data.tx_traffic:{}".format(data.tx_traffic))
            st.log("data.rx_traffic:{}".format(data.rx_traffic))
            intf_obj.show_interface_counters_detailed(vars.D1, vars.D1T1P1)
            st.report_fail('traffic_loss_observed')
    return data.intf_count_dict

def add_del_config_params_using_thread(min_links=False, fallback=False, fast_rate=False, flag='add'):
    if flag == 'add':
        if min_links:
            dict = {'portchannel_list': [data.portchannel_name], 'min_link': min_links, 'enhance_action': True}
        if fallback:
            dict = {'portchannel_list': [data.portchannel_name], 'fallback': True, 'enhance_action': True}
        if fast_rate:
            dict = {'portchannel_list': [data.portchannel_name], 'fast_rate': True, 'enhance_action': True}
    else:
        if min_links:
            dict = {'portchannel_list': [data.portchannel_name], 'min_link': True, 'config_type': 'no', 'enhance_action': True}
        if fallback:
            dict = {'portchannel_list': [data.portchannel_name], 'fallback': True, 'config_type': 'no', 'enhance_action': True}
        if fast_rate:
            dict = {'portchannel_list': [data.portchannel_name], 'fast_rate': True, 'config_type': 'no', 'enhance_action': True}
    exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.create_portchannel, [dict, dict])

def delete_vlan_member_using_thread(dut_list, vlan_list, members_list, tagged= False):
    sub_list = []
    sub_list.append([vlan_obj.delete_vlan_member, dut_list[0], vlan_list[0], members_list[0], tagged])
    sub_list.append([vlan_obj.delete_vlan_member, dut_list[1], vlan_list[1], members_list[1], tagged])
    exec_all(True, sub_list)

def add_vlan_member_using_thread(dut_list, vlan_list, port_list, tagged = True):
    sub_list = []
    sub_list.append([vlan_obj.add_vlan_member, dut_list[0], vlan_list[0], port_list[0], tagged, False])
    sub_list.append([vlan_obj.add_vlan_member, dut_list[1], vlan_list[1], port_list[1], tagged, False])
    [output, _] = exec_all(True, sub_list)
    return output

def get_intf_counters_using_thread(dut_list, thread=True):
    sub_list = [[intf_obj.show_interface_counters_all, dut] for dut in dut_list]
    [output, _] = exec_all(thread, sub_list)
    return output

def verify_portchannel_cum_member_status(dut, portchannel, members_list, iter_count=10, iter_delay=2, state='up'):
    i = 1
    while i <= iter_count:
        st.log("Checking iteration {}".format(i))
        st.wait(iter_delay)
        if not portchannel_obj.verify_portchannel_member_state(dut, portchannel, members_list, state=state):
            i += 1
            if i == iter_count:
                st.report_fail("portchannel_member_verification_failed", portchannel, dut, members_list)
        else:
            break


def check_lldp_neighbors(dut, port, ipaddress, hostname):
    try:
        lldp_value = lldp_obj.get_lldp_neighbors(dut, interface=port)[0]
    except Exception:
        st.error("No LLDP entries are found")
        return False
    lldp_value_dut2 = lldp_value['chassis_mgmt_ip']
    try:
        if not ipaddress[0] == lldp_value_dut2 :
            st.error("Entries are not matching")
            return False
    except Exception:
        st.error("Entries are not matching")
        return False
    lldp_value_hostname = lldp_value['chassis_name']
    if not hostname == lldp_value_hostname:
        st.error("Host name is not matching")
        return False
    return True

def get_mgmt_ip_using_thread(dut_list, mgmt_list, thread=True):
    sub_list = [[basic_obj.get_ifconfig_inet, dut, mgmt_list[cnt]] for cnt, dut in enumerate(dut_list, start=0)]
    [output, _] = exec_all(thread, sub_list)
    return output

def get_hostname_using_thread(dut_list, thread=True):
    sub_list = [[basic_obj.get_hostname, dut] for dut in dut_list]
    [output, _] = exec_all(thread, sub_list)
    return output

def verify_portchannel_rest(dut,json_data):
    get_resp = rest_obj.get_rest(dut,rest_url=data.rest_url)
    return rest_obj.verify_rest(get_resp["output"],json_data)

def verify_graceful_restart_syslog(dut):
    count_msg1 = slog.get_logging_count(dut, severity="NOTICE", filter_list=[
        "teamd#teammgrd: :- sig_handler: --- Received SIGTERM. Terminating PortChannels gracefully"])
    count_msg2 = slog.get_logging_count(dut, severity="NOTICE",
                           filter_list=["teamd#teammgrd: :- sig_handler: --- PortChannels terminated gracefully"])
    if not (count_msg1 == 1 and count_msg2 == 1):
        st.error('SYSLOG message is not observed for graceful restart')
        return False
    return True


@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_lag_l2_hash_smac_dmac_vlan'])
@pytest.mark.inventory(testcases=['ft_lag_member_remove_add'])
@pytest.mark.inventory(testcases=['ft_lag_remove_vlan'])
@pytest.mark.inventory(testcases=['ft_lag_withone_member'])
@pytest.mark.inventory(testcases=['ft_lldp_interaction_with_lag'])
@pytest.mark.inventory(testcases=['ft_portchannel_del_members'])
@pytest.mark.inventory(testcases=['portchannel_member_vlan_participation'])
@pytest.mark.inventory(testcases=['portchannel_status_when_all_members_are_shutdown'])
@pytest.mark.inventory(testcases=['shutdown_on_portchannel_member'])
@pytest.mark.inventory(testcases=['tagged_traffic_on_portchannel'])
@pytest.mark.inventory(testcases=['traffic_distribution_on_new_portchannel_member'])
@pytest.mark.inventory(testcases=['traffic_loss_when_portchannel_member_removed_and_added'])
@pytest.mark.inventory(testcases=['traffic_on_disabled_portchannel'])
@pytest.mark.inventory(feature='KNET Debug Counter', release='Cyrus4.0.0', testcases=['CPU_KNET_DEBUG_FUNC_002'])
def test_ft_portchannel_behavior_with_tagged_traffic():
    '''
    Author: Jagadish <jagadish.chatrasi@broadcom.com>
    This test case covers below test scenarios/tests
    Test scenario-1: Verify that deleting port channel with vlan membership.
    Test scenario-2: Verify that removal of a port from a LAG does not interrupt traffic.
    Test scenario-3: Verify that L2 LAG hashing functionality working fine in Sonic
    Test scenario-4: Verify that adding ports to a LAG causes traffic to redistribute to new ports.
    Test scenario-5: Verify LLDP interaction with LAG.
    Test scenario-6: Verify that a LAG with only 1 port functions properly.
    Test scenario-7: Verify that shutdown and "no shutdown" of port channel group port bring the port back to active state.
    Test scenario-8: Verify that the LAG in DUT is not UP when LAG is not created at partner DUT
    Test scenario-9: Verify that LAG status should be Down when none of LAG members are in Active state.
    Test scenario-10: Verify that no traffic is forwarded on a disabled LAG
    Test scenario-11: Verify only participating lags that are members of the VLAN forward tagged traffic
    Test scenario-12: Verify that the LAG in DUT is not UP when LAG is not created at partner DUT
    Test scenario-13: Verify the LACP CPU pkt counter.
    '''
    lacp_knet_tc = True
    if not knet_api.clear_knet_stats(vars.D1, 'all'):
        lacp_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_313", "msg", "Failed to clear CPU Packet debug KNET counters")
    if not retry_api(knet_api.validate_knet_counters, vars.D1, pkt_type='PKT_TYPE_LACP', queue=data.queue_id['PKT_TYPE_LACP'], tx_queue=True, intf=vars.D1D2P1):
        lacp_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_313", "msg", "Failed to validate KNET counters for LACP")
    rate_pps = tgapi.normalize_pps(2000)
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=72,
              mac_src='00:01:00:00:00:01', mac_src_step='00:00:00:00:00:01', mac_src_mode='increment', mac_src_count=200,
              mac_dst='00:02:00:00:00:02', mac_dst_step='00:00:00:00:00:01', mac_dst_mode='increment', mac_dst_count=200,
              rate_pps=rate_pps, l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=data.vid, transmit_mode='continuous')
    data.streams['D1T1_SD_Mac_Hash1'] = stream['stream_id']
    data.return_value = 1
    st.log("Test scenario-1: Verifying that deleting port channel with vlan membership should not be successful")
    if portchannel_obj.delete_portchannel(vars.D1, data.portchannel_name, skip_error = True):
        data.return_value = 2
        st.report_fail('portchannel_with_vlan_membership_should_not_successful', data.portchannel_name)
    st.log("Test scenario-1: Successfully verified that deleting port channel with vlan membership should not be successful")

    st.log("Test scenario-2: Verifying that removal of a port from a LAG does not interrupt traffic")
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_Mac_Hash1'], enable_arp=0)
    st.wait(2)
    exec_parallel(True, [vars.D1, vars.D2], intf_obj.show_interface_counters_all, [None,None])
    random_number = int(randomnumber(4))
    random_member1 = data.members_dut1[random_number]
    if not portchannel_obj.delete_portchannel_member(vars.D1, data.portchannel_name, random_member1):
        st.report_fail('portchannel_member_delete_failed', random_member1, data.portchannel_name)
    temp_member_list1 = data.members_dut1[:]
    temp_member_list1.remove(random_member1)
    if portchannel_obj.verify_portchannel_and_member_status(vars.D1, data.portchannel_name, random_member1):
        st.report_fail('portchannel_member_verification_failed', data.portchannel_name, vars.D1, random_member1)
    st.wait(2)
    if not retry_api(knet_api.validate_knet_counters, vars.D1, pkt_type='PKT_TYPE_LACP', queue=data.queue_id['PKT_TYPE_LACP'], tx_queue=True, verify_counters='rx_errors', intf=random_member1):
        lacp_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_313", "msg", "Failed to validate KNET counters for LACP")
    if not retry_api(knet_api.validate_clear_knet_counters, vars.D1, pkt_type='PKT_TYPE_LACP', queue=data.queue_id['PKT_TYPE_LACP']):
        lacp_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_313", "msg", "Failed to validate KNET counters clear")
    if lacp_knet_tc:
        st.report_tc_pass("CPU_KNET_DEBUG_FUNC_313", "msg", "Succcessfully verified the LACP protocol CPU pkt counter")
    st.log('Test scenario-3: Verifying that L2 LAG hashing functionality working fine in Sonic')
    portchannel_members_counters1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    st.log('Test scenario-3: Successfully verified that L2 LAG hashing functionality working fine in Sonic')

    verify_portchannel_cum_member_status(vars.D1, data.portchannel_name, temp_member_list1, iter_delay=1)
    portchannel_members_counters2 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    if not (portchannel_members_counters1[random_member1]+10 > portchannel_members_counters2[random_member1]):
        st.report_fail('portchannel_count_verification_fail', vars.D1, random_member1)
    if not portchannel_obj.add_portchannel_member(vars.D1, data.portchannel_name, random_member1):
        st.report_fail('add_members_to_portchannel_failed', random_member1, data.portchannel_name, vars.D1)
    verify_portchannel_cum_member_status(vars.D1, data.portchannel_name, data.members_dut1, iter_delay=1)
    st.wait(2)
    portchannel_members_counters3 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    st.log('Test scenario-4: Verifying that adding ports to a LAG causes traffic to redistribute to new ports')
    if not (portchannel_members_counters3[random_member1] >= portchannel_members_counters2[random_member1]+10):
        st.report_fail('traffic_not_hashed', vars.D1)
    st.log('Test scenario-4: Successfully verified that adding ports to a LAG causes traffic to redistribute to new ports')

    st.log("LAG Members: {}".format(",".join(temp_member_list1)))
    st.log("LAG Member Counters-0: {} {} {}".format( portchannel_members_counters1[temp_member_list1[0]],
            portchannel_members_counters2[temp_member_list1[0]], portchannel_members_counters3[temp_member_list1[0]]))
    st.log("LAG Member Counters-1: {} {} {}".format( portchannel_members_counters1[temp_member_list1[1]],
            portchannel_members_counters2[temp_member_list1[1]], portchannel_members_counters3[temp_member_list1[1]]))
    st.log("LAG Member Counters-2: {} {} {}".format( portchannel_members_counters1[temp_member_list1[2]],
            portchannel_members_counters2[temp_member_list1[2]], portchannel_members_counters3[temp_member_list1[2]]))

    if not ((portchannel_members_counters1[temp_member_list1[0]] < portchannel_members_counters2[temp_member_list1[0]] <
             portchannel_members_counters3[temp_member_list1[0]])
            and (portchannel_members_counters1[temp_member_list1[1]] < portchannel_members_counters2[temp_member_list1[1]] <
             portchannel_members_counters3[temp_member_list1[1]])
            and (portchannel_members_counters1[temp_member_list1[2]] < portchannel_members_counters2[temp_member_list1[2]] <
             portchannel_members_counters3[temp_member_list1[2]])):
        st.report_fail('traffic_not_hashed', vars.D1)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_Mac_Hash1'])
    st.wait(1)
    st.log('Fetching interface counters in both the DUTs')
    data.intf_count1, data.intf_count2 = get_intf_counters_using_thread([vars.D1, vars.D2])
    for counter_dict in data.intf_count1:
        if counter_dict['iface'] == vars.D1T1P1:
            rx_ok_counter = counter_dict['rx_ok'].replace(',', '')
            data.data_rx = int(rx_ok_counter) if rx_ok_counter.isdigit() else 0
            break
    for counter_dict in data.intf_count2:
        if counter_dict['iface'] == vars.D2T1P1:
            tx_ok_counter = counter_dict['tx_ok'].replace(',', '')
            data.data_tx = int(tx_ok_counter) if tx_ok_counter.isdigit() else 0
            break
    st.log('Total frames sent:{}'.format(data.data_rx))
    st.log('Total frames received:{}'.format(data.data_tx))
    data.data101_tx = 1.05 * data.data_tx
    if not (data.data101_tx >= data.data_rx):
        st.report_fail('traffic_verification_failed')
    st.log("Test scenario-2: Successfully verified that removal of a port from a LAG does not interrupt traffic")

    st.log("Test scenario-7: Verifying that shutdown and 'no shutdown' of port channel group port bring the port back to active state")
    st.log('To be added once STP supported')

    st.log("Test scenario-5: Verifying LLDP interaction with LAG")
    data.mgmt_int = 'eth0'
    _, ipaddress_d2 = get_mgmt_ip_using_thread([vars.D1, vars.D2], [data.mgmt_int, data.mgmt_int])
    _, hostname_d2 = get_hostname_using_thread([vars.D1, vars.D2])
    if not st.poll_wait(check_lldp_neighbors, 20, vars.D1, random_member1, ipaddress_d2, hostname_d2):
        st.report_fail("no_lldp_entries_are_available")
    st.log("Test scenario-5: Successfully verified LLDP interaction with LAG")

    st.log("Test scenario-10: Verifying that no traffic is forwarded on a disabled LAG")
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_Mac_Hash1'], enable_arp=0)
    st.wait(2)
    exec_parallel(True, [vars.D1, vars.D2], intf_obj.show_interface_counters_all, [None,None])
    st.log('Administratively disable portchannel in DUT1')
    if not st.poll_wait(intf_obj.interface_operation, 5, data.dut1, data.portchannel_name, 'shutdown', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail', data.portchannel_name)
    st.wait(2)
    st.log('Verify whether traffic is hashed over portchannel members or not and fetchig counters')
    data.int_counter1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    st.log('Verify whether the portchannel is down or not')
    try:
        data.portchannel_status_output = portchannel_obj.get_portchannel(vars.D1, portchannel_name=data.portchannel_name)[0]
    except Exception:
        data.return_value = 3
        st.report_fail('portchannel_verification_failed', data.portchannel_name, vars.D1)
    if not ((data.portchannel_status_output['protocol'] == 'LACP(A)(Dw)') or (data.portchannel_status_output['protocol']
            == 'LACP' and data.portchannel_status_output['state'] == 'D')):
        data.return_value = 3
        st.report_fail('portchannel_state_fail', data.portchannel_name, vars.D1, 'down')
    data.int_counter2 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    if not (((data.int_counter1[vars.D1D2P1] + 100) >= data.int_counter2[vars.D1D2P1]) and
            ((data.int_counter1[vars.D1D2P2] + 100) >= data.int_counter2[vars.D1D2P2]) and
            ((data.int_counter1[vars.D1D2P3] + 100) >= data.int_counter2[vars.D1D2P3]) and
            ((data.int_counter1[vars.D1D2P4] + 100) >= data.int_counter2[vars.D1D2P4])):
        data.return_value = 3
        st.report_fail('traffic_hashed', vars.D1)
    st.log('Administratively Enable portchannel in DUT1')
    if not st.poll_wait(intf_obj.interface_operation, 5, vars.D1, data.portchannel_name, 'startup', skip_verify=False):
        st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    st.log('Verify that whether the portchannel is Up or not')
    if not portchannel_obj.verify_portchannel_and_member_status(vars.D1, data.portchannel_name, data.members_dut1):
        st.report_fail('portchannel_state_fail', data.portchannel_name, vars.D1, 'up')
    st.wait(1)
    data.int_counter3 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300)
    if not ((data.int_counter3[vars.D1D2P1] > data.int_counter2[vars.D1D2P1]) and
            (data.int_counter3[vars.D1D2P2] > data.int_counter2[vars.D1D2P2]) and
            (data.int_counter3[vars.D1D2P3] > data.int_counter2[vars.D1D2P3]) and
            (data.int_counter3[vars.D1D2P4] > data.int_counter2[vars.D1D2P4])):
        st.report_fail('traffic_not_hashed', vars.D1)
    st.log("Test scenario-10: Successfully verified that no traffic is forwarded on a disabled LAG")

    st.log("Test scenario-11: Verifying only participating lags that are members of the VLAN forward tagged traffic")
    st.log('Exclude Port-channel from VLAN')
    if not vlan_obj.delete_vlan_member(vars.D1, data.vid, [data.portchannel_name], tagging_mode=True):
        data.return_value = 4
        st.report_fail('vlan_member_deletion_failed', data.portchannel_name)
    st.wait(2)
    st.log('Verify whether traffic is hashed over portchannel members or not and fetchig counters')
    data.int_counter1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    if not vlan_obj.verify_vlan_config(vars.D1, data.vid):
        st.report_fail('vlan_member_delete_failed', data.vid, data.portchannel_name)
    data.int_counter1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    if not (((data.int_counter1[vars.D1D2P1] + 10) >= data.int_counter2[vars.D1D2P1]) and
            ((data.int_counter1[vars.D1D2P2] + 10) >= data.int_counter2[vars.D1D2P2]) and
            ((data.int_counter1[vars.D1D2P3] + 10) >= data.int_counter2[vars.D1D2P3]) and
            ((data.int_counter1[vars.D1D2P4] + 10) >= data.int_counter2[vars.D1D2P4])):
        data.return_value = 4
        st.report_fail('traffic_hashed', vars.D1)
    st.log('Include Port-channel from VLAN')
    if not vlan_obj.add_vlan_member(vars.D1, data.vid, [data.portchannel_name], tagging_mode=True):
        data.return_value = 4
        st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)
    if not vlan_obj.verify_vlan_config(vars.D1, data.vid, tagged=[data.portchannel_name]):
        data.return_value = 4
        st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)
    data.int_counter3 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_Mac_Hash1'])
    if not ((data.int_counter3[vars.D1D2P1] > data.int_counter2[vars.D1D2P1]) and
            (data.int_counter3[vars.D1D2P2] > data.int_counter2[vars.D1D2P2]) and
            (data.int_counter3[vars.D1D2P3] > data.int_counter2[vars.D1D2P3]) and
            (data.int_counter3[vars.D1D2P4] > data.int_counter2[vars.D1D2P4])):
        st.report_fail('traffic_not_hashed', vars.D1)
    st.log("Test scenario-11: Successfully verified only participating lags that are members of the VLAN forward tagged traffic")

    st.log("Test scenario-6: Verifying that a LAG with only 1 port functions properly")
    random_member2 = data.members_dut2[random_number]
    temp_member_list2 = data.members_dut2[:]
    temp_member_list2.remove(random_member2)
    add_del_member_using_thread([vars.D1, vars.D2], [data.portchannel_name, data.portchannel_name],
                [temp_member_list1,temp_member_list2], flag='del')
    sub_list = []
    sub_list.append([portchannel_obj.verify_portchannel_and_member_status, vars.D1, data.portchannel_name,
                     random_member1])
    sub_list.append([portchannel_obj.verify_portchannel_and_member_status, vars.D2, data.portchannel_name,
                     random_member2])
    [output, _] = exec_all(True, sub_list)
    st.log("Test scenario-6: Successfully verified that a LAG with only 1 port functions properly")

    st.log("Test scenario-12: Verifying that the LAG in DUT is not UP when LAG is not created at partner DUT")
    dict1 = {'portchannel': data.portchannel_name, 'members': temp_member_list1, 'flag': "add"}
    dict2 = {'portchannel': data.portchannel_name, 'members': random_member2, 'flag': "del"}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_del_portchannel_member, [dict1, dict2])
    if not output[0][0]:
        st.report_fail('portchannel_create_failed', data.portchannel_name, vars.D1)
    if not output[0][1]:
        st.report_fail('portchannel_deletion_failed', data.portchannel_name)
    if not portchannel_obj.poll_for_portchannel_status(vars.D1, data.portchannel_name, "down"):
        st.report_fail('portchannel_state_fail', data.portchannel_name, vars.D1, 'down')
    st.log("Test scenario-12: Successfully Verified that the LAG in DUT is not UP when LAG is not created at partner DUT")

    if not portchannel_obj.add_del_portchannel_member(vars.D2, data.portchannel_name, data.members_dut2):
        st.report_fail('portchannel_create_failed', data.portchannel_name, vars.D2)
    verify_portchannel_status(delay=1)
    st.log("Verifying that LAG status should be Down when none of LAG members are in Active state")
    intf_obj.interface_shutdown(vars.D1, data.members_dut1, skip_verify=False)
    if not portchannel_obj.poll_for_portchannel_status(vars.D1, data.portchannel_name, "down"):
        data.return_value = 5
        st.report_fail('portchannel_state_fail', data.portchannel_name, vars.D1, 'down')
    intf_obj.interface_noshutdown(vars.D1, data.members_dut1, skip_verify=False)
    st.log("Successfully verified that LAG status should be Down when none of LAG members are in Active state")
    st.report_pass("test_case_passed")


@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['FtCETA_28524'])
def test_member_status_after_portch_down():
    issue=0
    rate_pps = tgapi.normalize_pps(2000)
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=72,
              mac_src='00:01:00:00:00:01', mac_src_step='00:00:00:00:00:01', mac_src_mode='increment', mac_src_count=200,
              mac_dst='00:02:00:00:00:02', mac_dst_step='00:00:00:00:00:01', mac_dst_mode='increment', mac_dst_count=200,
              rate_pps=rate_pps, l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=data.vid, transmit_mode='continuous')
    data.streams['D1T1_SD_Mac_Hash1'] = stream['stream_id']
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_Mac_Hash1'], enable_arp=0)
    st.wait(2)
    exec_parallel(True, [vars.D1, vars.D2], intf_obj.show_interface_counters_all, [None, None])
    #############Test scenario 1 ######################
    st.log("Shutdown one interface, config save reload and re-veriffy the interface status")
    intf_obj.interface_operation(data.dut1, vars.D1D2P1, 'shutdown')
    if not st.poll_wait(intf_obj.verify_interface_status, 5, vars.D1, vars.D1D2P1, 'admin', 'down'):
        issue+=1
        st.report_fail('interface_admin_shut_down_fail', vars.D1D2P1)
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    verify_traffic_hashed_or_not(vars.D1, vars.D1D2P1, 100)
    st.log("performing Config save")
    reboot_obj.config_save_reload([vars.D1, vars.D2])
    st.log("Verifying interfaces")
    if not st.poll_wait(intf_obj.verify_interface_status, 5, vars.D1,vars.D1D2P1, 'admin', 'down'):
        issue+=1
    st.log("issue counter : {}".format(issue))
    if not intf_obj.interface_operation(vars.D1, [data.portchannel_name,vars.D1D2P1], 'startup'):
        st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    st.wait(2)
    st.log("Re-Verifying interfaces after bringing up portchannel")
    if not st.poll_wait(intf_obj.verify_interface_status, 5, vars.D1,vars.D1D2P1, 'oper', 'up'):
        issue+=1
    st.log("issue counter : {}".format(issue))
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    verify_traffic_hashed_or_not(vars.D1, vars.D1D2P1, 100)
    #############Test scenario 2 ######################
    st.log("Shutdown the port channel and verify the members admin status")
    if not intf_obj.interface_operation(data.dut1, data.portchannel_name, 'shutdown', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail', data.portchannel_name)
    st.wait(2)
    if st.poll_wait(intf_obj.verify_interface_status, 5, vars.D1, data.members_dut1, 'admin', 'down'):
        issue+=1
    st.log("issue counter : {}".format(issue))
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    st.log("read interface counters")
    rx_counters = intf_obj.get_interface_counters(vars.D1, vars.D1D2P1, "rx_ok")
    tx_counters = intf_obj.get_interface_counters(vars.D1, vars.D1D2P1, "tx_ok")
    # process interface counters
    p1_rcvd, p2_txmt = 0, 0
    for i in rx_counters: p1_rcvd = int(i['rx_ok'].replace(",",""))
    for i in tx_counters: p2_txmt = int(i['tx_ok'].replace(",",""))
    diff_count = abs(p1_rcvd - p2_txmt)
    st.log("ingress rx_ok = {} egress tx_ok = {} diff = {}".format(p1_rcvd, p2_txmt, diff_count))

    # verify interface counters
    if not p1_rcvd == 0: st.report_fail("msg", "rx_ok is invalid")
    if not intf_obj.interface_operation(data.dut1, data.portchannel_name, 'startup', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail', data.portchannel_name)
    #if p2_txmt == 0: st.report_fail("msg", "tx_ok is invalid")
    #if not diff_count < data.counters_threshold: st.report_fail("msg", "unexpected counter values")
    #############Test scenario 3 ######################
    st.log("issue counter : {}".format(issue))
    st.log("Add member to the shutdown portchannel and verify interface admin and oper status")
    if not intf_obj.interface_operation(data.dut1, data.portchannel_name, 'shutdown', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail', data.portchannel_name)
    if not portchannel_obj.add_portchannel_member(vars.D1, data.portchannel_name, vars.D1D2P5):
        st.report_fail('add_members_to_portchannel_failed', vars.D1D2P5, data.portchannel_name, vars.D1)
    if not st.poll_wait(intf_obj.verify_interface_status,5,vars.D1, vars.D1D2P5, 'admin', 'up'):
        issue+=1
    st.log("issue counter : {}".format(issue))
    st.log("Shutdown the portchannel and verify the member oper status")
    if not st.poll_wait(intf_obj.verify_interface_status,5,vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'down'):
        issue+=1
    if not intf_obj.interface_operation(data.dut1, data.portchannel_name, 'startup', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail', data.portchannel_name)
    #############Test scenario 4 ######################
    st.log("issue counter : {}".format(issue))
    st.log("Remove member from the portchannel and verify member status")
    if not portchannel_obj.delete_portchannel_member(vars.D1, data.portchannel_name, vars.D1D2P5):
        st.report_fail('portchannel_member_delete_failed', data.portchannel_name)
    if portchannel_obj.verify_portchannel_and_member_status(vars.D1, data.portchannel_name, vars.D1D2P5):
        st.report_fail('portchannel_member_verification_failed', data.portchannel_name, vars.D1, vars.D1D2P5)
    st.wait(2)
    st.log("Unshut the portchannel")
    if not intf_obj.interface_operation(vars.D1, data.portchannel_name, 'startup', skip_verify=False):
        st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    st.wait(5)
    verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300)
    #############Test scenario 5 ######################
    st.log("issue counter : {}".format(issue))
    st.log("Shutdown member port of a LAG while traffic flowing through that port, shutdown the LAG and no shutdown the LAG and verify that the port admin status intact")
    if not intf_obj.interface_operation(data.dut1, vars.D1D2P1, 'shutdown', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail',vars.D1D2P1 )
    st.wait(2)
    if not intf_obj.interface_operation(data.dut1, data.portchannel_name, 'shutdown', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail', data.portchannel_name)
    st.wait(2)
    st.log("Unshut the portchannel")
    if not intf_obj.interface_operation(vars.D1, data.portchannel_name, 'startup', skip_verify=False):
        st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    st.wait(2)
    if not st.poll_wait(intf_obj.verify_interface_status, 5, vars.D1,vars.D1D2P1, 'admin', 'down'):
        issue+=1
    st.log("issue counter : {}".format(issue))
    st.log("read interface counters")
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    rx_counters = intf_obj.get_interface_counters(vars.D1, vars.D1D2P1, "rx_ok")
    tx_counters = intf_obj.get_interface_counters(vars.D1, vars.D1D2P1, "tx_ok")
    # process interface counters
    p1_rcvd, p2_txmt = 0, 0
    for i in rx_counters: p1_rcvd = int(i['rx_ok'].replace(",",""))
    for i in tx_counters: p2_txmt = int(i['tx_ok'].replace(",",""))
    diff_count = abs(p1_rcvd - p2_txmt)
    st.log("ingress rx_ok = {} egress tx_ok = {} diff = {}".format(p1_rcvd, p2_txmt, diff_count))

    # verify interface counters
    if not p1_rcvd == 0: st.report_fail("msg", "rx_ok is invalid")
    #if p2_txmt == 0: st.report_fail("msg", "tx_ok is invalid")
    #if not diff_count < data.counters_threshold: st.report_fail("msg", "unexpected counter values")

    if not intf_obj.interface_operation(vars.D1, data.portchannel_name, 'startup', skip_verify=False):
        st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    st.wait(2)
    if not intf_obj.interface_operation(data.dut1, data.members_dut1, 'startup', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail',vars.D1D2P1 )
    if not st.poll_wait(intf_obj.verify_interface_status,7,data.dut1, data.members_dut1, 'oper', 'up'):
        issue+=1
    st.wait(2)
    #############Test scenario 6 ######################
    st.log("issue counter : {}".format(issue))
    st.log("Shut and unshut the portchannel and verify traffic")
    if not intf_obj.interface_operation(data.dut1, data.portchannel_name, 'shutdown', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail', data.portchannel_name)
    st.wait(2)
    if not st.poll_wait(intf_obj.verify_interface_status,5,vars.D1, [vars.D1D2P1, vars.D1D2P2], 'admin', 'up'):
        issue+=1
    st.log("issue counter : {}".format(issue))
    data.int_counter1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    data.int_counter2 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    if not (((data.int_counter1[vars.D1D2P1] + 100) >= data.int_counter2[vars.D1D2P1]) and
            ((data.int_counter1[vars.D1D2P2] + 100) >= data.int_counter2[vars.D1D2P2]) and
            ((data.int_counter1[vars.D1D2P3] + 100) >= data.int_counter2[vars.D1D2P3]) and
            ((data.int_counter1[vars.D1D2P4] + 100) >= data.int_counter2[vars.D1D2P4])):
        data.return_value = 3
        st.report_fail('traffic_hashed', vars.D1)
    st.log('Administratively Enable portchannel in DUT1')
    if not intf_obj.interface_operation(vars.D1, data.portchannel_name, 'startup', skip_verify=False):
        st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    if not intf_obj.interface_operation(data.dut1, data.members_dut1, 'startup', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail',vars.D1D2P1 )
    st.wait(2)
    st.log('Verify that whether the portchannel is Up or not')
    if not portchannel_obj.verify_portchannel_and_member_status(vars.D1, data.portchannel_name, data.members_dut1):
        st.report_fail('portchannel_state_fail', data.portchannel_name, vars.D1, 'up')
    if not portchannel_obj.verify_portchannel_member_state(data.dut1, data.portchannel_name, data.members_dut1,
                                                           state='up'):
        st.report_fail("msg", "PortChannel member verification failed after PortChannel flap")
    data.int_counter3 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300)
    if not ((data.int_counter3[vars.D1D2P1] > data.int_counter2[vars.D1D2P1]) and
            (data.int_counter3[vars.D1D2P2] > data.int_counter2[vars.D1D2P2]) and
            (data.int_counter3[vars.D1D2P3] > data.int_counter2[vars.D1D2P3]) and
            (data.int_counter3[vars.D1D2P4] > data.int_counter2[vars.D1D2P4])):
        st.report_fail('traffic_not_hashed', vars.D1)
    st.log("issue counter : {}".format(issue))
    if not intf_obj.interface_operation(data.dut1, data.portchannel_name, 'startup', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail', data.portchannel_name)
    if issue>0:
        st.report_fail("msg", "PortChannel member verification failed")
    else:
        st.report_pass('test_case_passed')


@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSwVlFn010'])
@pytest.mark.inventory(testcases=['untagged_traffic_on_portchannel'])
def test_ft_untagged_traffic_on_portchannel():
    '''
    This test case covers below test scenarios/tests
    scenario-1: Verify that LAGs treat untagged packets identically to regular ports.
    '''
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=90,
             mac_src='00:05:00:00:00:01', mac_src_step='00:00:00:00:00:01', mac_src_mode='increment', mac_src_count=200,
             mac_dst='00:06:00:00:00:02', mac_dst_step='00:00:00:00:00:01', mac_dst_mode='increment', mac_dst_count=200,
             pkts_per_burst=2000, l2_encap='ethernet_ii_vlan', transmit_mode='single_burst')
    data.streams['D1T1_SD_Mac_Hash3'] = stream['stream_id']
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_Mac_Hash3'], enable_arp=0)
    st.wait(2)
    exec_parallel(True, [vars.D1, vars.D2], intf_obj.show_interface_counters_all, [None,None])
    verify_traffic_hashed_or_not(vars.D1, data.members_dut1 , 400)
    st.report_pass('test_case_passed')



@pytest.mark.l3_lag_hash
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSwLagFn005'])
@pytest.mark.inventory(testcases=['FtOtSoRtArpFn011'])
@pytest.mark.inventory(testcases=['ft_lag_l3_hash_sip_dip_l4port'])
def test_ft_lag_l3_hash_sip_dip_l4port():
    """
    Author: Karthik Kumar Goud Battula(karthikkumargoud,battula@broadcom.com)
    scenario1-Verify that L3 LAG hashing functionality working fine in Sonic
    scenario2 - Verify an ARP table entry learned on Port-Channel based routing interface is removed
    from ARP table after Port-Channel is shutdown.
    """
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', mac_dst=data.dut1_rt_int_mac,
             mac_src='00:05:00:00:00:01', mac_src_mode='increment', mac_src_step='00:00:00:00:00:01', mac_dst_mode='fixed',
             ip_src_addr=data.ip41, ip_src_mode='increment', ip_src_count=data.ip_src_count, ip_src_step='0.0.0.1', mac_src_count=1000,
             ip_dst_addr=data.ip42, ip_dst_mode='fixed', pkts_per_burst=1000, l3_protocol='ipv4', transmit_mode='single_burst')
    data.streams['D1T1_SD_ip_Hash1'] = stream['stream_id']
    result_state = True
    data.subnet = '8'
    data.ip_addr_pc1 = '20.1.1.2'
    data.ip_addr_pc2 = '20.1.1.3'
    data.ipv4 = 'ipv4'
    data.ip_addr_po1 = '10.1.1.3'
    data.ip_addr_po2 = '30.1.1.2'
    data.ip_addr_po3 = '30.1.1.3'
    data.static_ip1 = '10.0.0.0/8'
    data.static_ip2 = '30.0.0.0/8'
    data.static_ip3 = '40.0.0.0/8'
    data.remote_mac = '00:00:00:00:00:01'
    data.remote_mac2 = '00:00:00:00:00:02'
    dict1 = {'interface_name': data.portchannel_name, 'ip_address': data.ip_addr_pc1, 'subnet': data.subnet,
             'family': "ipv4"}
    dict2 = {'interface_name': data.portchannel_name, 'ip_address': data.ip_addr_pc2, 'subnet': data.subnet,
             'family': "ipv4"}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address': data.ip_addr_po1, 'subnet': data.subnet, 'family': "ipv4"}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address': data.ip_addr_po2, 'subnet': data.subnet, 'family': "ipv4"}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address': "{}/8".format(data.ip_addr_po1), 'family': "ipv4"}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address': "{}/8".format(data.ip_addr_po2), 'family': "ipv4"}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.verify_interface_ip_address, [dict1, dict2])
    if not output[0][0]:
        st.report_fail('ip_routing_int_create_fail', data.ip_addr_po1)
    if not output[0][1]:
        st.report_fail('ip_routing_int_create_fail', data.ip_addr_po2)
    #Scenario 2
    # ping from partner
    ip_obj.ping(vars.D2, data.ip_addr_pc1 , family='ipv4', count=3)
    # test arp entry on portchannel
    if not arp_obj.verify_arp(vars.D1, data.ip_addr_pc2):
        st.error('Dynamic arp entry on prtchannel failed: ARP_entry_dynamic_entry_fail')
        result_state = False
    port_obj.shutdown(vars.D1, [data.portchannel_name])
    # test arp entry on portchannel after shutdown it
    if arp_obj.verify_arp(vars.D1, data.ip_addr_pc2):
        st.error('Dynamic arp entry on prtchannel is not removed after shutdown:ARP_dynamic_entry_removal_fail')
        result_state = False
    port_obj.noshutdown(vars.D1, [data.portchannel_name])

    ip_obj.create_static_route(vars.D1, data.ip_addr_pc2, data.static_ip2, shell='vtysh', family=data.ipv4)
    dict1 = {'next_hop': data.ip_addr_pc2, 'static_ip': data.static_ip3, 'shell': "vtysh", 'family': 'ipv4'}
    dict2 = {'next_hop': data.ip_addr_po3, 'static_ip': data.static_ip3, 'shell': "vtysh", 'family': 'ipv4'}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.create_static_route, [dict1, dict2])
    arp_obj.add_static_arp(vars.D2, data.ip_addr_po3, data.remote_mac, interface=vars.D2T1P1)
    arp_obj.add_static_arp(vars.D2, data.ip42, data.remote_mac2, interface=vars.D2T1P1)
    ip_obj.create_static_route(vars.D2, data.ip_addr_pc1, data.static_ip1, shell='vtysh', family=data.ipv4)
    [output, _] = exec_all(True, [
        ExecAllFunc(poll_wait, ip_obj.verify_ip_route, 10, vars.D1, data.ipv4, ip_address=data.static_ip2, type="S"),
        ExecAllFunc(poll_wait, ip_obj.verify_ip_route, 10, vars.D2, data.ipv4, ip_address=data.static_ip1, type="S")])
    if not all(output):
        st.error('ip_static_route_create_fail')
        result_state = False
    if not ip_obj.ping(vars.D1, data.ip_addr_pc2):
        st.report_fail("ping_fail", data.ip_addr_pc2)
    dict1 = {'addresses': data.ip_addr_po2}
    dict2 = {'addresses': data.ip_addr_po1}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.ping, [dict1, dict2])
    if not output[0][0]:
        st.report_fail("ping_fail", data.ip_addr_po2)
    if not output[0][1]:
        st.report_fail("ping_fail", data.ip_addr_po1)
    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_1, dev_handle=data.h1['handle'], dst_ip=data.ip42,
                      ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_ip_Hash1'], enable_arp=0)
    st.wait(2)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_ip_Hash1'])
    st.log("Verify that traffic is forwarding over portchannel members")
    verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 200,
                                 traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    data.tg.tg_traffic_control(action='reset', port_handle=data.tg_ph_1)
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=90,
             mac_src='00:05:00:00:00:01', mac_src_mode='fixed', mac_dst=data.dut1_rt_int_mac, ip_src_addr=data.ip41,
             ip_src_mode='fixed', ip_dst_addr=data.ip43, ip_dst_mode='increment', ip_dst_step='0.0.0.1',
             ip_dst_count=data.ip_dst_count, pkts_per_burst=2000, l3_protocol='ipv4', transmit_mode='single_burst')
    data.streams['D1T1_SD_ip_Hash2'] = stream['stream_id']
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_ip_Hash2'], enable_arp=0)
    st.wait(2)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_ip_Hash2'])
    st.log("Verify that traffic is forwarding over portchannel members")
    verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300,
                                 traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    data.tg.tg_traffic_control(action='reset', port_handle=data.tg_ph_1)
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=90,
             mac_src='00:05:00:00:00:01', mac_src_mode='fixed', mac_dst=data.dut1_rt_int_mac, tcp_src_port_step=1,
             ip_src_addr=data.ip41, tcp_src_port=data.src_port, tcp_src_port_mode='incr', tcp_src_port_count=data.tcp_src_port_count,
             tcp_dst_port=data.dst_port, ip_dst_addr=data.ip42, tcp_dst_port_mode='incr', pkts_per_burst=2000,
             l4_protocol='tcp', tcp_dst_port_step=1, tcp_dst_port_count=data.tcp_dst_port_count, l3_protocol='ipv4', transmit_mode='single_burst')
    data.streams['D1T1_SD_ip_Hash3'] = stream['stream_id']
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_ip_Hash3'], enable_arp=0)
    st.wait(2)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_ip_Hash3'])
    st.log("Verify that traffic is forwarding over portchannel members")
    verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300,
                                 traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    st.log("Deleting static routes...")
    ip_obj.delete_static_route(vars.D1, data.ip_addr_pc2, data.static_ip2, shell='vtysh', family=data.ipv4)
    dict1 = {'next_hop': data.ip_addr_pc2, 'static_ip': data.static_ip3, 'shell': "vtysh", 'family': 'ipv4'}
    dict2 = {'next_hop': data.ip_addr_po3, 'static_ip': data.static_ip3, 'shell': "vtysh", 'family': 'ipv4'}
    exec_parallel(True, [vars.D1, vars.D2], ip_obj.delete_static_route, [dict1, dict2])
    if result_state:
        st.report_pass('test_case_passed')
    else:
        st.report_fail("traffic_not_hashed", data.dut1)



@pytest.mark.lag_member_interchanged
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSwLagFn010'])
def test_ft_member_state_after_interchanged_the_members_across_portchannels():
    """
    Author: vishnuvardhan.talluri@broadcom.com
    scenario; Verify that the LAG members in DUT are not UP when LAG members between two different Lags are
    interchanged
    :return:
    """
    verify_portchannel_status()
    portchannel_name_second = "PortChannel102"
    result_state = True

    # Remove 2 members from portchannel
    dict1 = {'portchannel': data.portchannel_name, 'members': data.members_dut1[2:]}
    dict2 = {'portchannel': data.portchannel_name, 'members': data.members_dut2[2:]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.delete_portchannel_member, [dict1, dict2])
    # add second portchannel
    portchannel_obj.config_portchannel(data.dut1, data.dut2, portchannel_name_second, data.members_dut1[2:],
                                       data.members_dut2[2:], "add")
    dict1 = {'interfaces': portchannel_name_second, 'operation': "startup", 'skip_verify': True}
    output = exec_parallel(True, [vars.D1, vars.D2], intf_obj.interface_operation, [dict1, dict1])
    if not (output[0][0] and output[0][1]):
        st.report_fail('interface_admin_startup_fail', portchannel_name_second)
    #Verify portchannel is up
    dict1 = {'portchannel': portchannel_name_second, 'members': data.members_dut1[2:]}
    dict2 = {'portchannel': portchannel_name_second, 'members': data.members_dut2[2:]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_and_member_status, [dict1, dict2])
    if not (output[0][0] and output[0][1]):
        result_state = False
    # Interchange ports from one portchannel to another portchannel
    portchannel_obj.delete_portchannel_member(data.dut1, data.portchannel_name, data.members_dut1[0])
    portchannel_obj.delete_portchannel_member(data.dut1, portchannel_name_second, data.members_dut1[2])
    # Wait 3 times the lacp long timeout period to allow dut members to go down
    st.wait(90)
    output1 = portchannel_obj.verify_portchannel_member_state(data.dut2, data.portchannel_name, data.members_dut2[0], "down")
    if not output1:
        output1 = portchannel_obj.verify_portchannel_member_state(data.dut2, data.portchannel_name,
                                                                  data.members_dut2[0], "down")
    output2 = portchannel_obj.verify_portchannel_member_state(data.dut2, portchannel_name_second, data.members_dut2[2], "down")
    if not (output1 and output2):
        result_state = False
    # swapping the ports in DUT1 only
    output1 = portchannel_obj.add_portchannel_member(data.dut1, data.portchannel_name, data.members_dut1[2])
    output2 = portchannel_obj.add_portchannel_member(data.dut1, portchannel_name_second, data.members_dut1[0])
    if not (output1 and output2):
        result_state = False
    # Wait for few seconds after converge and ensure member ports states proper
    st.wait(5)
    # Verify portchannel member state with provided state
    dict1 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut1[2], 'state': "down"}
    dict2 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut2[0], 'state': "down"}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_member_state, [dict1, dict2])
    if not (output[0][0] and output[0][1]):
        result_state = False
    dict1 = {'portchannel': portchannel_name_second, 'members_list': data.members_dut1[0], 'state': "down"}
    dict2 = {'portchannel': portchannel_name_second, 'members_list': data.members_dut2[2], 'state': "down"}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_member_state, [dict1, dict2])
    if not (output[0][0] and output[0][1]):
        result_state = False
    dict1 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut1[1]}
    dict2 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut2[1]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_member_state, [dict1, dict2])
    if not (output[0][0] and output[0][1]):
        result_state = False
    dict1 = {'portchannel': portchannel_name_second, 'members_list': data.members_dut1[3]}
    dict2 = {'portchannel': portchannel_name_second, 'members_list': data.members_dut2[3]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_member_state, [dict1, dict2])
    if not (output[0][0] and output[0][1]):
        result_state = False
    # ensuring module config
    portchannel_obj.config_portchannel(data.dut1, data.dut2, portchannel_name_second,
                                       [data.members_dut1[0], data.members_dut1[3]], data.members_dut2[2:], 'delete')
    dict1 = {'portchannel': data.portchannel_name,
             'members': [data.members_dut1[0], data.members_dut1[3]]}
    dict2 = {'portchannel': data.portchannel_name, 'members': data.members_dut2[2:]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_portchannel_member, [dict1, dict2])
    if not (output[0][0] and output[0][1]):
        result_state = False
    if result_state:
        st.report_pass("operation_successful")
    else:
        st.report_fail("portchannel_member_state_failed")



@pytest.mark.portchannel_with_vlan_variations
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSwLagFn041'])
@pytest.mark.inventory(testcases=['FtOpSoSwLagFn042'])
def test_ft_portchannel_with_vlan_variations():
    '''
    Author: Jagadish <pchvsai.durga@broadcom.com>
    This test case covers below test scenarios/tests
    FtOpSoSwLagFn041 : Verify that port-channel is up or not when port-channel created followed by add it to VLAN and
    then making the port-channel up.
    FtOpSoSwLagFn042 : Verify that port-channel is up when port-channel is created, making the port-channel up and then
    adding the port-channel to VLAN
    '''
    dict1 = {'portchannel': data.portchannel_name, 'members_list': [data.members_dut1[0], data.members_dut1[1]]}
    dict2 = {'portchannel': data.portchannel_name, 'members_list': [data.members_dut2[0], data.members_dut2[1]]}
    exec_parallel(True, [vars.D1, vars.D2], verify_portchannel_cum_member_status, [dict1, dict2])
    portchannel_obj.config_portchannel(data.dut1, data.dut2, data.portchannel_name2, [data.members_dut1[2], data.members_dut1[3]],
                                           [data.members_dut2[2], data.members_dut2[3]], "add")
    dict1 = {'portchannel': data.portchannel_name2, 'members_list': [data.members_dut1[2], data.members_dut1[3]]}
    dict2 = {'portchannel': data.portchannel_name2, 'members_list': [data.members_dut2[2], data.members_dut2[3]]}
    exec_parallel(True, [vars.D1, vars.D2], verify_portchannel_cum_member_status, [dict1, dict2])
    vlan_obj.create_vlan_and_add_members(vlan_data=[{"dut": [vars.D1,vars.D2], "vlan_id":data.vlan_id, "tagged":data.portchannel_name2}])
    dict1 = {'portchannel': data.portchannel_name2, 'members_list': [data.members_dut1[2], data.members_dut1[3]]}
    dict2 = {'portchannel': data.portchannel_name2, 'members_list': [data.members_dut2[2], data.members_dut2[3]]}
    exec_parallel(True, [vars.D1, vars.D2], verify_portchannel_cum_member_status, [dict1, dict2])
    #Clean up
    dict1 = {"vlan": data.vlan_id, "port_list": data.portchannel_name2, "tagging_mode": True}
    dict2 = {"vlan": data.vlan_id, "port_list": data.portchannel_name2, "tagging_mode": True}
    exec_parallel(True, [vars.D1, vars.D2], vlan_obj.delete_vlan_member, [dict1, dict2])
    dict1 = {"vlan_list": data.vlan_id}
    dict2 = {"vlan_list": data.vlan_id}
    exec_parallel(True, [vars.D1, vars.D2], vlan_obj.delete_vlan, [dict1, dict2])
    if not portchannel_obj.config_portchannel(data.dut1, data.dut2, data.portchannel_name2, [data.members_dut1[2], data.members_dut1[3]],
                                           [data.members_dut2[2], data.members_dut2[3]], "del"):
        st.report_fail("portchannel_deletion_failed", data.portchannel_name2)
    st.report_pass('test_case_passed')


@pytest.mark.inventory(feature='LACP Graceful Restart', release='Buzznik+')
@pytest.mark.inventory(testcases=['ft_lag_graceful_restart_cold_reboot'])
def test_ft_lacp_graceful_restart_with_cold_boot():
    '''
    This test case covers below test scenarios/tests
    scenario-1: Verify the LACP graceful restart functionality with cold reboot.
    '''
    if not data.graceful_restart_config:
        graceful_restart_prolog()
    data.graceful_restart_config = True
    [output, _] = exec_all(True, [ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]], [None, None]), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D2, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D2D1P1, vars.D2D1P2], [vars.D2D1P3, vars.D2D1P4]], [None, None])])
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    config_save(vars.D2)
    slog.clear_logging(vars.D2)
    [output, _] = exec_all(True, [ExecAllFunc(st.reboot, vars.D2), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 60, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_down, data.lag_down], [None, None], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]])])
    if output[0] is False:
        st.report_fail('reboot_failed')
    if output[0] is False:
        if not validate_link_events(vars.D1):
            st.warn("Expected failure as the links events are not supported")
        else:
            st.report_fail('portchannel_member_state_failed')
    if not st.poll_wait(verify_graceful_restart_syslog, 60, vars.D2):
        st.report_fail('failed_to_generate_lacp_graceful_restart_log_in_syslog')
    [output, _] = exec_all(True, [ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]], [None, None]), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D2, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D2D1P1, vars.D2D1P2], [vars.D2D1P3, vars.D2D1P4]], [None, None])])
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    st.report_pass('verify_lacp_graceful_restart_success', 'with cold reboot')


@pytest.mark.inventory(feature='LACP Graceful Restart', release='Buzznik+')
@pytest.mark.inventory(testcases=['ft_lag_graceful_restart_save_reload'])
def test_ft_lacp_graceful_restart_with_save_reload():
    '''
    This test case covers below test scenarios/tests
    scenario-1: Verify the LACP graceful restart functionality with config save and reload.
    '''
    if not data.graceful_restart_config:
        graceful_restart_prolog()
    data.graceful_restart_config = True
    output = exec_all(True, [ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]], [None, None]), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D2, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D2D1P1, vars.D2D1P2], [vars.D2D1P3, vars.D2D1P4]], [None, None])])[0]
    slog.clear_logging(vars.D2)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    [output, _] = exec_all(True, [ExecAllFunc(config_save_reload, vars.D2), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 120, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_down, data.lag_down], [None, None], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]])])
    if output[0] is False:
        st.report_fail('reboot_failed')
    if output[0] is False:
        if not validate_link_events(vars.D1):
            st.warn("Expected failure as the links events are not supported")
        else:
            st.report_fail('portchannel_member_state_failed')
    if not st.poll_wait(verify_graceful_restart_syslog, 60, vars.D2):
        st.report_fail('failed_to_generate_lacp_graceful_restart_log_in_syslog')
    [output, _] = exec_all(True, [ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]], [None, None]), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D2, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D2D1P1, vars.D2D1P2], [vars.D2D1P3, vars.D2D1P4]], [None, None])])
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    st.report_pass('verify_lacp_graceful_restart_success', 'with config save reload')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn001'])
def test_ft_verify_min_links_after_dynamic_lag_creation_001():
    result_flag = 0
    random_num = random.randint(1, 16)
    st.banner("FtOpSoSwPominFn001: Verify that min-links value can be changed after dynamic portchannel creation.")
    st.log("Configuring random non-default min-link value under PO")
    add_del_config_params_using_thread(min_links=random_num, flag='add')
    st.log("Check whether min-link value is updated to random non-default value")
    if not portchannel_obj.verify_interface_portchannel(vars.D1,min_links = random_num):
        st.error("Non-default random min-link not updated under the PO output")
        result_flag += 1
    st.log("As expected min-link value is updated to random non-default value.")
    st.log("Unconfigure non-default min-links value")
    add_del_config_params_using_thread(min_links=True, flag='del')
    st.log("Now Verify whether min-link is reverted back to its default value.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1,min_links = 1):
        st.error("Failed to revert back the min-link to its default value.")
        result_flag += 1
    st.log("Successfully min-link value reverted back to its default value 1.")
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2):
        st.error("Portchannel verification failed")
        result_flag += 1
    st.log("Portchannel verification passed with operational status UP")
    if result_flag:
        st.report_fail('portchannel_member_state_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn002'])
def test_ft_verify_dynamic_lag_when_min_links_criteria_met_002():
    result_flag=0
    st.banner("FtOpSoSwPominFn002: Verify dynamic portchannel is operationally UP only if min-links criteria is met..")
    st.log("Now configure min-link to 4 to meet the criteria.")
    add_del_config_params_using_thread(min_links=4, flag='add')
    st.log("Check whether min-link value is changed to configured value 4 from default 1.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, min_links=4):
        st.error("Configured non-default min-link value not updated under the PO output")
        result_flag += 1
    st.log("As expected min-link value is updated to configured non-default value.")
    st.log("Verify that PO state should be UP as it met min-link criteria.")
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed even if min-link and lag member ports are same.")
        result_flag += 1
    st.log("As expected portchannel status is UP when min-link criteria is met.")
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn003'])
def test_ft_verify_dynamic_lag_when_min_links_criteria_not_met_003():
    result_flag=0
    st.banner("FtOpSoSwPominFn003: Verify that the dynamic portchannel is operationally down if min-links criteria is not met.")
    # Remove one member port(out of 4) from both the devices to form a lag with 3 member ports.
    st.log("Removing one lag member port...")
    dict1 = {'portchannel': data.portchannel_name, 'members': vars.D1D2P4}
    dict2 = {'portchannel': data.portchannel_name, 'members': vars.D2D1P4}
    exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.delete_portchannel_member, [dict1, dict2])
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1[:3],dut2_active_mem=data.members_dut2[:3]):
        st.error("Portchannel is not coming Up with 3 lag member ports.")
        result_flag += 1
    st.log("Configure min-link to a value higher than configured lag member ports.")
    add_del_config_params_using_thread(min_links=4, flag='add')
    st.log("Check whether min-link value is changed to configured value 4 from default 1.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, min_links=4):
        st.error("Non-default min-link value not updated under the PO output")
        result_flag += 1
    st.log("Successfully min-link value is updated to configured non-default value.")
    st.log("Now verify that PO state should go DOWN as min-link criteria is not met.")
    if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down, dut1_down_mem=data.members_dut1[:3] ,dut2_down_mem=data.members_dut2[:3]):
        st.error("Portchannel state is not going to down even if min-link criteria is not met.")
        result_flag += 1
    st.log("As expected portchannel status went to DOWN if min-link criteria is not met.")
    st.log("Now add one lag member port on both the devices to meet the min-link criteria.")
    exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_portchannel_member, [dict1, dict2])
    st.log("Verify PO state should operationally Up as min-links and lag member ports are same.")
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed even if min-link and lag member ports are same.")
        result_flag += 1
    st.log("Again configure min-links value higher than lag member ports and verify PO should go Down.")
    add_del_config_params_using_thread(min_links=5, flag='add')
    if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down, dut1_down_mem=data.members_dut1 ,dut2_down_mem=data.members_dut2):
        st.error("Portchannel state is not going to down even if min-link criteria is not met.")
        result_flag += 1
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn004'])
def test_ft_verify_po_state_after_port_flap_with_min_links_004():
    result_flag = 0
    st.banner("FtOpSoSwPominFn004: Verify dynamic PO state with shut/no shut of participating lag member with min-link criteria met.")
    st.log("Configure min_links value to 4 meet the criteria.")
    add_del_config_params_using_thread(min_links=4, flag='add')
    verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1, dut2_active_mem=data.members_dut2)
    st.log("Now shut one of the participating lag member port and verify PO state should go DOWN.")
    portchannel_obj.delete_portchannel_member(vars.D1, data.portchannel_name, vars.D1D2P4)
    if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down, dut1_down_mem=data.members_dut1[:3] ,dut2_down_mem=data.members_dut2):
        st.error("Portchannel state is not going to down even if min-link criteria is not met.")
        result_flag += 1
    st.log("Portchannel operational state went to down state successfully")
    st.log("Unshut lag member port and verify whether PO state Up is retained back.")
    portchannel_obj.add_portchannel_member(vars.D1, data.portchannel_name, vars.D1D2P4)
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed even if min-link and lag member ports are same.")
        result_flag += 1
    st.log("Portchannel operational status retained back to UP as expected after adding the deleted lag member port.")
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn005'])
def test_ft_l2_traffic_on_dynamic_lag_with_min_links_functionality_005():
    result_flag = 0
    st.banner("FtOpSoSwPominFn005: Verify L2 traffic once the dynamic PO is up with min-links configured/Verify traffic should be dropped min-links criteria is not met.")
    st.log("Configure min_links value to 4 meet the criteria.")
    add_del_config_params_using_thread(min_links=4, flag='add')
    verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1, dut2_active_mem=data.members_dut2)
    rate_pps = tgapi.normalize_pps(2000)
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=72,
                                       mac_src='00:01:00:00:00:01', mac_src_step='00:00:00:00:00:01',
                                       mac_src_mode='increment', mac_src_count=200,
                                       mac_dst='00:02:00:00:00:02', mac_dst_step='00:00:00:00:00:01',
                                       mac_dst_mode='increment', mac_dst_count=200,
                                       rate_pps=rate_pps, l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=data.vid,
                                       transmit_mode='continuous')
    data.streams['D1T1_SD_Mac_Hash1'] = stream['stream_id']
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_Mac_Hash1'], enable_arp=0)
    st.wait(2)
    exec_parallel(True, [vars.D1, vars.D2], intf_obj.show_interface_counters_all, [None, None])
    st.log("Now verify traffic hashed on participating lag member ports.")
    if not verify_traffic_hashing_on_member_ports(Traffic_check_on_member_ports=True, port_list=data.members_dut1):
        st.error("Traffic is not getting hashed on lag member ports with min link criteria.")
        result_flag += 1
    data.int_counter1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    st.log("Increase min-link value while traffic is running and verify that traffic is getting dropped or not.")
    add_del_config_params_using_thread(min_links=5, flag='add')
    if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down, dut1_down_mem=data.members_dut1 ,dut2_down_mem=data.members_dut2):
        st.error("Portchannel state is not going to down even if min-link criteria is not met.")
        result_flag += 1
    st.log("Portchannel operational status passed with Down state.")
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    st.wait(10)
    if not verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 500, traffic_drop_check=True):
        st.error("Traffic is not getting dropped.")
        result_flag += 1
    st.log("As expected observed traffic drop when min-link criteria is not met on PO.")
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn006'])
def test_ft_l3_traffic_on_dynamic_lag_with_min_links_functionality_006():
    result_flag = 0
    st.banner("FtOpSoSwPominFn006: Verify L3 traffic once the dynamic PO is up with min-links configured/Verify traffic should be dropped min-links criteria is not met.")
    st.log("Delete the vlan config.. before configuring ip addresses")
    delete_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                                                               [data.portchannel_name, vars.D2T1P1]],
                                    True)
    data.subnet = '8'
    data.po_ip_addr_pc1 = '20.1.1.1'
    data.po_ip_addr_pc2 = '20.1.1.2'
    data.ipv4 = 'ipv4'
    data.ip_addr_tg_pc1 = '10.1.1.3'
    data.ip_addr_tg_pc2 = '30.1.1.2'
    data.static_ip1 = '10.0.0.0/8'
    data.static_ip2 = '30.0.0.0/8'
    dict1 = {'interface_name': data.portchannel_name, 'ip_address': data.po_ip_addr_pc1, 'subnet': data.subnet,
             'family': "ipv4"}
    dict2 = {'interface_name': data.portchannel_name, 'ip_address': data.po_ip_addr_pc2, 'subnet': data.subnet,
             'family': "ipv4"}
    exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address': data.ip_addr_tg_pc1, 'subnet': data.subnet, 'family': "ipv4"}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address': data.ip_addr_tg_pc2, 'subnet': data.subnet, 'family': "ipv4"}
    exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address': "{}/8".format(data.ip_addr_tg_pc1), 'family': "ipv4"}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address': "{}/8".format(data.ip_addr_tg_pc2), 'family': "ipv4"}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.verify_interface_ip_address, [dict1, dict2])
    if not output[0][0]:
        result_flag += 1
    if not output[0][1]:
        result_flag += 1
    st.log("Configure min_links value to 4 meet the criteria.")
    add_del_config_params_using_thread(min_links=4, flag='add')
    verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1, dut2_active_mem=data.members_dut2)
    # ping from partner
    st.log("Ping from partner dut..")
    ip_obj.ping(vars.D2, data.po_ip_addr_pc1 , family='ipv4', count=3)
    data.h1 = data.tg.tg_interface_config(port_handle=data.tg_ph_1, mode='config', intf_ip_addr=data.ip41,
                                          gateway=data.src_ip, src_mac_addr='00:05:00:00:00:01',arp_send_req='1')
    st.log("INTFCONF: " + str(data.h1))
    data.h2 = data.tg.tg_interface_config(port_handle=data.tg_ph_3, mode='config', intf_ip_addr=data.ip42,
                                          gateway=data.dst_ip, src_mac_addr='00:06:00:00:00:01', arp_send_req='1')
    st.log("INTFCONF: " + str(data.h2))
    ip_obj.create_static_route(vars.D1, data.po_ip_addr_pc2, data.static_ip2, shell='vtysh', family=data.ipv4)
    ip_obj.create_static_route(vars.D2, data.po_ip_addr_pc1, data.static_ip1, shell='vtysh', family=data.ipv4)
    [output, _] = exec_all(True, [
        ExecAllFunc(poll_wait, ip_obj.verify_ip_route, 10, vars.D1, data.ipv4, ip_address=data.static_ip2, type="S"),
        ExecAllFunc(poll_wait, ip_obj.verify_ip_route, 10, vars.D2, data.ipv4, ip_address=data.static_ip1, type="S")])
    dict1 = {'addresses': data.ip_addr_tg_pc2}
    dict2 = {'addresses': data.ip_addr_tg_pc1}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.ping, [dict1, dict2])
    rate_pps = tgapi.normalize_pps(1000)
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed',
                                       mac_dst=data.dut1_rt_int_mac,
                                       mac_src='00:05:00:00:00:01', mac_src_mode='increment',
                                       mac_src_step='00:00:00:00:00:01', mac_dst_mode='fixed',
                                       ip_src_addr=data.ip41, ip_src_mode='increment', ip_src_count=data.ip_src_count,
                                       ip_src_step='0.0.0.1', mac_src_count=1000,
                                       ip_dst_addr=data.ip42, ip_dst_mode='fixed', rate_pps=rate_pps,
                                       l3_protocol='ipv4', transmit_mode='continuous')
    data.streams['D1T1_SD_ip_Hash1'] = stream['stream_id']
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_ip_Hash1'], enable_arp=0)
    st.wait(2)
    exec_parallel(True, [vars.D1, vars.D2], intf_obj.show_interface_counters_all, [None, None])
    st.log("Now verify traffic hashed on participating lag member ports.")
    if not verify_traffic_hashing_on_member_ports(Traffic_check_on_member_ports=True,
                                                  port_list=data.members_dut1):
        st.error("Traffic hashing on member ports got failed")
        result_flag += 1
    st.log("Traffic hashing on member successfully verified.")
    st.log("Increase min-link value while traffic is running and verify that traffic is getting dropped or not.")
    add_del_config_params_using_thread(min_links=5, flag='add')
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    st.wait(10)
    if not verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 500, traffic_drop_check=True):
        st.error("Traffic is not getting dropped.")
        result_flag += 1
    st.log("As expected observed traffic drop when min-link criteria is not met on PO.")
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn007'])
def test_ft_verify_min_links_functionality_by_flapping_all_member_ports_007():
    result_flag = 0
    st.banner("FtOpSoSwPominFn007: Verify dynamic PO state by removing and readding all port channel members with min-link criteria met.")
    st.log("Configure min-link to 4 to meet the criteria.")
    add_del_config_params_using_thread(min_links=4, flag='add')
    st.log("Verify that PO state.")
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed even if min-link and lag member ports are same.")
        result_flag += 1
    st.log("Flap all member ports by one time from one of the device and verify PO status.")
    portchannel_obj.delete_portchannel_member(vars.D1, data.portchannel_name, data.members_dut1)
    portchannel_obj.add_portchannel_member(vars.D1, data.portchannel_name, data.members_dut1)
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed even if min-link and lag member ports are same.")
        st.report_fail('test_case_failed')
    st.log("Portchannel verification passed after flapping participating lag member ports.")
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn008'])
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn009'])
def test_ft_min_link_functionality_during_device_reboot_008():
    result_flag = 0
    st.banner("Cold boot/Fast boot tests with min-link functionality")
    for method,value in zip(['normal','fast'],range(8,10)):
        st.banner("FtOpSoSwPominFn00{}: Verify PO with min-link criteria functionality during {}-reboot operation".format(value,method))
        add_del_config_params_using_thread(min_links=4, flag='add')
        st.log("Verify Portchannel operational state while min-link criteria is met.")
        if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2):
            st.error("Portchannel state verification failed even if min-link and lag member ports are same.")
            st.report_fail('test_case_failed')
        st.log("Portchannel verification passed with expected operational status UP.")
        st.log("Increase the min-link value and verify PO should go to operational down state.")
        add_del_config_params_using_thread(min_links=5, flag='add')
        if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down, dut1_down_mem=data.members_dut1 ,dut2_down_mem=data.members_dut2) or not portchannel_obj.verify_interface_portchannel(vars.D1, min_links=5):
            st.error("Portchannel verification failed or non-default min-link value not updated under the PO output.")
            result_flag += 1
        st.log("Portchannel verification passed with expected operational status DOWN.")
        st.log("Performing Config Save and {} reboot on {}".format(method,vars.D1))
        reboot_obj.config_save(vars.D1)
        st.reboot(vars.D1, method=method)
        st.banner("Verify after {} reboot portchannel state and min-link should be retained.".format(method))
        if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down, dut1_down_mem=data.members_dut1 ,dut2_down_mem=data.members_dut2) or not portchannel_obj.verify_interface_portchannel(vars.D1, min_links=5):
            st.error("Portchannel verification failed or non-default min-link value not updated under the PO output.")
            result_flag += 1
        st.log("As expected after {} portchannel verification passed with expected operational status DOWN.".format(method))
        if result_flag:
            st.report_fail('test_case_failed')
        st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn010'])
def test_ft_min_link_functionality_during_device_warm_reboot():
    result_flag = 0
    st.banner("Warm boot test with min-link functionality")
    st.banner(
        "FtOpSoSwPominFn00{}: Verify PO with min-link criteria functionality during {}-reboot operation".format(10,
                                                                                                                'warm'))
    add_del_config_params_using_thread(min_links=4, flag='add')
    st.log("Verify Portchannel operational state while min-link criteria is met.")
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1, dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed even if min-link and lag member ports are same.")
        st.report_fail('test_case_failed')
    st.log("Portchannel verification passed with expected operational status UP.")
    st.log("Increase the min-link value and verify PO should go to operational down state.")
    add_del_config_params_using_thread(min_links=5, flag='add')
    if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down,
                                              dut1_down_mem=data.members_dut1,
                                              dut2_down_mem=data.members_dut2) or not portchannel_obj.verify_interface_portchannel(
            vars.D1, min_links=5):
        st.error("Portchannel verification failed or non-default min-link value not updated under the PO output.")
        result_flag += 1
    st.log("Portchannel verification passed with expected operational status DOWN.")
    st.log("Performing Config Save and {} reboot on {}".format('warn', vars.D1))
    reboot_obj.config_save(vars.D1)
    st.reboot(vars.D1, method='warm')
    st.banner("Verify after {} reboot portchannel state and min-link should be retained.".format('warm'))
    if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down,
                                              dut1_down_mem=data.members_dut1,
                                              dut2_down_mem=data.members_dut2) or not portchannel_obj.verify_interface_portchannel(
            vars.D1, min_links=5):
        st.error("Portchannel verification failed or non-default min-link value not updated under the PO output.")
        result_flag += 1
    st.log("As expected after {} portchannel verification passed with expected operational status DOWN.".format('warm'))
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')


@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn011'])
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn012'])
def test_ft_no_min_link_functionality_during_device_reboot_009():
    result_flag = 0
    st.banner("Cold boot/Warm boot/Fast boot tests with no min-link functionality")
    for method,value in zip(['normal','fast'],range(11,13)):
        st.banner("FtOpSoSwPominFn00{}: Verify dynamic PO with no min-link criteria functionality during {}-reboot operation".format(value,method))
        add_del_config_params_using_thread(min_links=4, flag='add')
        st.log("Verify Portchannel operational state while min-link criteria is met.")
        if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2):
            st.error("Portchannel state verification failed even if min-link and lag member ports are same.")
            st.report_fail('test_case_failed')
        st.log("Portchannel verification passed with expected operational status UP.")
        st.log("Now unconfigure non-default min-links value and trigger reboot.")
        add_del_config_params_using_thread(min_links=True, flag='del')
        st.log("Now verify PO operational state should not be disturbed and whether min-link changed back to its default value.")
        if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2) or not portchannel_obj.verify_interface_portchannel(vars.D1, min_links=1):
            st.error("Portchannel verification failed or default min-link value not retained under the PO output.")
            result_flag += 1
        st.log("As expected portchannel operational status is not disturbed when min-link is reverted back to default value.")
        st.log("Performing Config Save and {} reboot on {}".format(method,vars.D1))
        reboot_obj.config_save(vars.D1)
        st.reboot(vars.D1, method=method)
        st.banner("Verify after {} reboot portchannel operational up state and default min-link should be retained.".format(method))
        if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1 ,dut2_active_mem=data.members_dut2) or not portchannel_obj.verify_interface_portchannel(vars.D1, min_links=1):
            st.error("Portchannel verification failed or default min-link value not retained under the PO output.")
            result_flag += 1
        st.log("As expected after {} portchannel operational status is not disturbed when min-link is reverted back to default value.".format(method))
        if result_flag:
            st.report_fail('test_case_failed')
        st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn013'])
def test_ft_no_min_link_functionality_during_device_warm_reboot():
    result_flag = 0
    st.banner("Warm boot test with no min-link functionality")
    st.banner(
        "FtOpSoSwPominFn00{}: Verify dynamic PO with no min-link criteria functionality during {}-reboot operation".format(
            13, 'warm'))
    add_del_config_params_using_thread(min_links=4, flag='add')
    st.log("Verify Portchannel operational state while min-link criteria is met.")
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1, dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed even if min-link and lag member ports are same.")
        st.report_fail('test_case_failed')
    st.log("Portchannel verification passed with expected operational status UP.")
    st.log("Now unconfigure non-default min-links value and trigger reboot.")
    add_del_config_params_using_thread(min_links=True, flag='del')
    st.log(
        "Now verify PO operational state should not be disturbed and whether min-link changed back to its default value.")
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1,
                                              dut2_active_mem=data.members_dut2) or not portchannel_obj.verify_interface_portchannel(
            vars.D1, min_links=1):
        st.error("Portchannel verification failed or default min-link value not retained under the PO output.")
        result_flag += 1
    st.log(
        "As expected portchannel operational status is not disturbed when min-link is reverted back to default value.")
    st.log("Performing Config Save and {} reboot on {}".format('warm', vars.D1))
    reboot_obj.config_save(vars.D1)
    st.reboot(vars.D1, method='warm')
    st.banner("Verify after {} reboot portchannel operational up state and default min-link should be retained.".format(
        'warm'))
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1,
                                              dut2_active_mem=data.members_dut2) or not portchannel_obj.verify_interface_portchannel(
            vars.D1, min_links=1):
        st.error("Portchannel verification failed or default min-link value not retained under the PO output.")
        result_flag += 1
    st.log(
        "As expected after {} portchannel operational status is not disturbed when min-link is reverted back to default value.".format(
            'warm'))
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')


@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn028'])
def test_ft_lag_fallback_config_after_po_creation_010():
    result_flag = 0
    st.banner("FtOpSoSwPominFn028: Verify that fallback mode can be changed after portchannel creation.")
    st.log("Configure fallback mode under the portchannel")
    add_del_config_params_using_thread(fallback=True, flag='add')
    st.log("Verify whether fallback mode is updated to enabled.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, fallback="Enabled"):
        st.error("Fallback mode is not updated enabled under the PO output")
        result_flag += 1
    st.log("Successfully fallback mode changed to Enabled.")
    st.log("Verify Portchannel operational state while fallback is in enabled state.")
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1, dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed after enabling fallback mode.")
    st.log("Now unconfigure fallback and verify if fallback mode is reverted back to disabled.")
    add_del_config_params_using_thread(fallback=True, flag='del')
    if not portchannel_obj.verify_interface_portchannel(vars.D1, fallback="Disabled"):
        st.error("Fallback mode is not reverted back to disabled under the PO output")
        result_flag += 1
    st.log("Successfully fallback mode reverted back to Disabled.")
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn029'])
def test_ft_verify_dynamic_lag_with_fallback_functionality_011():
    result_flag = 0
    st.banner("FtOpSoSwPominFn029: Verify that the portchannel enters into fallback operational mode if it is enabled.")
    st.log("Unconfigure the member ports on the remote device.")
    portchannel_obj.delete_portchannel_member(vars.D2, data.portchannel_name, data.members_dut2)
    st.log("Polling for PO status to go to operational down state")
    portchannel_obj.poll_for_portchannel_status(vars.D1, data.portchannel_name, state='down')
    if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down,
                                              dut1_down_mem=data.members_dut1):
        st.error("Portchannel is not going to Down even if members links are removed on remote device.")
        result_flag += 1
    st.log("As expected portchannel went Down after removing the member ports on one of the device.")
    st.log("Configure fallback mode under the portchannel")
    add_del_config_params_using_thread(fallback=True, flag='add')
    if not verify_dynamic_portchannel_summary(dut2_state=data.lag_down,dut1_active_mem=[vars.D1D2P1]):
        st.error("Portchannel verification failed with fallback mode")
        result_flag += 1
    st.log("As expected portchannel went to operational up after enabling fallback mode.")
    st.log("Verify whether fallback mode is updated to enabled.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, fallback="Enabled"):
        st.error("Fallback mode is not updated enabled under the PO output")
        result_flag += 1
    st.log("Successfully fallback mode changed to Enabled.")
    st.log("Now unconfigure fallback and verify PO again went to DOWN state on both the devices and fallback mode to disabled state.")
    add_del_config_params_using_thread(fallback=True, flag='del')
    portchannel_obj.poll_for_portchannel_status(vars.D1, data.portchannel_name, state='down')
    if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down,
                                              dut1_down_mem=data.members_dut1):
        st.error("Portchannel is not going to Down even if fallback and members links are removed.")
        result_flag += 1
    st.log("Succesfully portchannel went to Down when fallback is disabled.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, fallback="Disabled"):
        st.error("Fallback mode is not reverted back to disabled under the PO output")
        result_flag += 1
    st.log("Successfully fallback mode reverted back to Disabled.")
    st.log("Adding back lag member ports...")
    portchannel_obj.add_portchannel_member(vars.D2, data.portchannel_name, data.members_dut2)
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn030'])
def test_ft_lag_fast_rate_config_after_po_creation_012():
    result_flag = 0
    st.banner("FtOpSoSwPominFn030: Verify that fast-rate mode can be changed after portchannel creation by enable/disable fast-rate mode.")
    st.log("Configure fast-rate mode under the portchannel")
    add_del_config_params_using_thread(fast_rate=True, flag='add')
    st.log("Verify whether fast-rate mode is updated to enabled.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, interval="FAST"):
        st.error("Fast-rate mode is not updated under the PO output")
        result_flag += 1
    st.log("Successfully fast-rate interval changed to FAST rate.")
    st.log("Now try to unconfigure fast-rate mode.")
    add_del_config_params_using_thread(fast_rate=True, flag='del')
    if not portchannel_obj.verify_interface_portchannel(vars.D1, interval="SLOW"):
        st.error("Fast-rate mode is not reverted back under the PO output")
        result_flag += 1
    st.log("Successfully fast-rate interval reverted back to SLOW rate.")
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn031'])
def test_verify_dynamic_lag_with_fast_rate_0013():
    result_flag = 0
    st.banner("FtOpSoSwPominFn031: Verify PO state by enable/disable fast-rate mode.")
    st.log("Configure fast-rate mode under the portchannel")
    add_del_config_params_using_thread(fast_rate=True, flag='add')
    st.log("Verify whether fast-rate mode is updated to enabled.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, interval="FAST"):
        st.error("Fast-rate mode is not updated under the PO output")
        result_flag += 1
    st.log("Successfully fast-rate interval changed to FAST rate.")
    st.log("Verify Portchannel operational state while fast-rate is in enabled state.")
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1, dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed after enabling fast-rate mode.")
        result_flag += 1
    st.log("Portchannel state verification passed after enabling fast-rate mode.")
    st.log("Now unconfigure fast-rate and verify PO state should not be disturbed upon changing the LACP fast-rate mode.")
    add_del_config_params_using_thread(fast_rate=True, flag='del')
    if not verify_dynamic_portchannel_summary(dut1_active_mem=data.members_dut1, dut2_active_mem=data.members_dut2):
        st.error("Portchannel state verification failed.")
        result_flag += 1
    st.log("As expected portchannel state was not disturbed upon changing the LACP fast-rate mode.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, interval="SLOW"):
        st.error("Fast-rate mode is not reverted back under the PO output")
        result_flag += 1
    st.log("Successfully fast-rate interval reverted back to SLOW rate.")
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn032'])
def test_ft_modify_optional_params_using_po_creation_command_014():
    result_flag = 0
    st.banner("FtOpSoSwPominFn032: Verify user is allowed to change the optional params using PO creation command.")
    st.log("Now try to change the optional params using PO creation command.")

    st.banner("Modifying min-link value with PO creation command...")
    if not portchannel_obj.create_portchannel(vars.D1, portchannel_list=data.portchannel_name, min_link=5,
                                              neg_check=True):
        st.error("User is not allowed to modify min-link value with po creation command.")
        result_flag += 1
    st.log("As expected user is allowed to modify min-link value with po creation command.")
    if not verify_dynamic_portchannel_summary(dut1_state=data.lag_down, dut2_state=data.lag_down, dut1_down_mem=data.members_dut1 ,dut2_down_mem=data.members_dut2):
        st.error("Portchannel state is not going to down even if min-link criteria is not met.")
        result_flag += 1
    st.log("Unconfigure non-default min-links value")
    add_del_config_params_using_thread(min_links=True, flag='del')

    st.banner("Modifying fallback mode with PO creation command...")
    if not portchannel_obj.create_portchannel(vars.D1, portchannel_list=data.portchannel_name, fallback=True,
                                              neg_check=True):
        st.error("User is not allowed to modify fallback mode with po creation command.")
        result_flag += 1
    st.log("Verify whether fallback mode is updated to enabled.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, fallback="Enabled"):
        st.error("Fallback mode is not updated enabled under the PO output")
        result_flag += 1
    st.log("As expected user is allowed to modify fallback mode with po creation command.")
    st.log("Now unconfigure fallback under PO")
    add_del_config_params_using_thread(fallback=True, flag='del')

    st.banner("Modifying fast_rate with PO creation command...")
    if not portchannel_obj.create_portchannel(vars.D1, portchannel_list=data.portchannel_name, fast_rate=True,
                                              neg_check=True):
        st.error("User is not allowed to modify fast_rate mode with po creation command.")
        result_flag += 1
    st.log("Verify whether fast-rate mode is updated to enabled.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, interval="FAST"):
        st.error("Fast-rate mode is not updated under the PO output")
        result_flag += 1
    st.log("As expected user is allowed to modify fast-rate mode with po creation command.")
    st.log("Now unconfigure fast-rate mode under port-channel")
    add_del_config_params_using_thread(fast_rate=True, flag='del')

    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')

@pytest.mark.inventory(feature='PortChannel Config Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSwPominFn033'])
def test_ft_verify_lacp_pdu_rate_of_transmission_when_fast_rate_enabled_015():
    result_flag = 0
    st.banner("FtOpSoSwPominFn033: Verify that the LACPDUs are transmitted from the portchannel members in fast-rate (1-second) when the fast-rate mode is enabled for the portchannel.")
    st.log("Verifying default transmission rate of LACP PDU's...")
    if not capture_and_processing_lacp_packets(vars.D2, vars.D2D1P2):
        st.error("LACP PDU's are not transmitting with default 30sec transmission rate.")
        result_flag += 1
    st.log("Configure fast-rate mode under the portchannel")
    add_del_config_params_using_thread(fast_rate=True, flag='add')
    st.log("Verify whether fast-rate mode is updated to enabled.")
    if not portchannel_obj.verify_interface_portchannel(vars.D1, interval="FAST"):
        st.error("Fast-rate mode is not updated under the PO output")
        result_flag += 1
    st.banner("Now verify LACP PDU's should be transmitting at a rate of 1 sec with fast-interval...")
    if not capture_and_processing_lacp_packets(vars.D2, vars.D2D1P2,fast_rate=True):
        st.error("LACP PDU's are not transmitting with fast-interval 1 sec.")
        result_flag += 1
    st.log("Now unconfigure fast-rate and verify LACP PDU's transmiision rate.")
    add_del_config_params_using_thread(fast_rate=True, flag='del')
    st.banner("Verify whether LACP PDU's are transmitting back at a rate of 30 sec with default slow-interval...")
    if not capture_and_processing_lacp_packets(vars.D2, vars.D2D1P2):
        st.error("LACP PDU's are not transmitting with default  slow-interval 30sec.")
        result_flag += 1
    if result_flag:
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')
