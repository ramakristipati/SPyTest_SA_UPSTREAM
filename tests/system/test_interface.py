import pytest
from random import randint

from spytest import SpyTestDict, st, tgapi
import apis.switching.vlan as vlanapi
import apis.system.interface as intfapi
import apis.routing.ip as ipapi
from apis.routing.arp import config_static_arp
import apis.system.reboot as rbapi
import apis.system.basic as base_obj
import apis.debug.knet as knet_api
import apis.system.box_services as box_api
import apis.system.switch_configuration as scfg_api
from utilities.common import random_vlan_list
from utilities.parallel import exec_parallel
from utilities.utils import report_tc_fail, retry_api

intf_data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def interface_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:2", "D1T1:2", "D2T1:1")
    initialize_variables()
    intf_data.sub_intf_mode = st.get_args("routed_sub_intf")
    st.banner("sub intf_mode is: {}".format(intf_data.sub_intf_mode))
    if not vlanapi.create_vlan(vars.D1, intf_data.vlan_id):
        st.report_fail("vlan_create_fail", intf_data.vlan_id)
    if not vlanapi.add_vlan_member(vars.D1, intf_data.vlan_id, [vars.D1T1P1, vars.D1T1P2]):
        st.report_fail("vlan_untagged_member_fail", [vars.D1T1P1, vars.D1T1P2], intf_data.vlan_id)
    st.log("Getting TG handlers")

    _, intf_data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    _, intf_data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    _, intf_data.tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    intf_data.tg = tgapi.get_chassis(vars)

    st.log("Reset and clear statistics of TG ports")
    intf_data.tg.tg_traffic_control(action='reset', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2, intf_data.tg_ph_3])
    intf_data.tg.tg_traffic_control(action='clear_stats', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2, intf_data.tg_ph_3])

    st.log("Creating TG streams")
    intf_data.streams = {}
    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_1, mode='create',
                                            length_mode='fixed', rate_pps=100, frame_size=intf_data.knet_mtu,
                                            transmit_mode='single_burst', pkts_per_burst=100,
                                            mac_src=intf_data.source_mac, mac_dst=intf_data.dut_rt_int_mac, l3_protocol='ipv4',
                                            ip_src_addr=intf_data.knet_ipaddresses[1], ip_dst_addr=intf_data.knet_ipaddresses[3])
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['knet_stream'] = stream['stream_id']

    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_1, mode='create', port_handle2=intf_data.tg_ph_2,
                                            length_mode='fixed', rate_pps=100, frame_size=intf_data.mtu1,
                                            l2_encap='ethernet_ii_vlan', transmit_mode='single_burst',
                                            pkts_per_burst=100, vlan_id=intf_data.vlan_id,
                                            mac_src=intf_data.source_mac, mac_dst=intf_data.destination_mac,
                                            vlan="enable")
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['mtu1'] = stream['stream_id']

    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_1, mode='create', port_handle2=intf_data.tg_ph_2,
                                            length_mode='fixed', rate_pps=100, frame_size=intf_data.mtu2,
                                            l2_encap='ethernet_ii_vlan', transmit_mode='single_burst',
                                            pkts_per_burst=100, vlan_id=intf_data.vlan_id,
                                            mac_src=intf_data.source_mac, mac_dst=intf_data.destination_mac,
                                            vlan="enable")
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['mtu2'] = stream['stream_id']

    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_1, mode='create',
                                            length_mode='fixed', frame_size='5000',
                                            transmit_mode='continuous')
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['traffic_tg1'] = stream['stream_id']

    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_2, mode='create',
                                            length_mode='fixed', frame_size='5000',
                                            transmit_mode='continuous')
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['traffic_tg2'] = stream['stream_id']
    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_1,mode='create',
                                            transmit_mode='continuous', length_mode='fixed', rate_pps=100,
                                            vlan_id=intf_data.vlan_id, mac_src='00:0a:01:00:00:01',
                                            mac_dst='00:0a:02:00:00:01', vlan="enable")
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['traffic_fec1'] = stream['stream_id']
    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_3,mode='create',
                                            transmit_mode='continuous', length_mode='fixed',
                                            rate_pps=100,vlan_id=intf_data.vlan_id, mac_src='00:0a:02:00:00:01',
                                            mac_dst='00:0a:01:00:00:01', vlan="enable")
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['traffic_fec2'] = stream['stream_id']

    yield
    vlanapi.clear_vlan_configuration(st.get_dut_names(), thread=True)
    # intf_data.tg.tg_traffic_control(action='stop', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])
    intf_data.tg.tg_traffic_control(action='reset', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])
    #intf_data.tg.tg_traffic_control(action='clear_stats',port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])


def verify_traffic():
    intfapi.clear_interface_counters(vars.D1, interface_type="all")
    intfapi.clear_interface_counters(vars.D2, interface_type="all")
    intfapi.show_interface_counters_all(vars.D1)
    intfapi.show_interface_counters_all(vars.D2)
    st.log("Starting of traffic from TGen")
    intf_data.tg.tg_traffic_control(action='run', stream_handle=intf_data.streams['traffic_fec1'])
    st.wait(intf_data.wait_sec)
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [intf_data.tg],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [intf_data.tg],
        },
    }
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=intf_data.streams['traffic_fec1'])
    result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate',
                                          comp_type='packet_count')
    return result

@pytest.fixture(scope="function", autouse=True)
def interface_func_hooks(request):
    if st.get_func_name(request) == "test_ft_port_fn_verify_shut_noshut":
        if intf_data.sub_intf_mode:
            intf_data.sub_intf_id = randint(1, 65535)
            intf_data.port1 = "{}.{}".format(vars.D1D2P1, intf_data.sub_intf_id)
            intf_data.port2 = "{}.{}".format(vars.D2D1P1, intf_data.sub_intf_id)
            dict1 = {'intf': intf_data.port1, 'vlan': 10}
            dict2 = {'intf': intf_data.port2, 'vlan': 10}
            [output, _] = exec_parallel(True, [vars.D1, vars.D2], ipapi.config_sub_interface, [dict1, dict2])
            if not all(output):
                st.report_fail("msg", "Failed to create sub interface")

        else:
            intf_data.port1 = vars.D1D2P1
            intf_data.port2 = vars.D2D1P1
    elif st.get_func_name(request) == "test_knet_ipmtu_ip2me_subnet":
        if not vlanapi.delete_vlan_member(vars.D1, intf_data.vlan_id, [vars.D1T1P1, vars.D1T1P2], tagging_mode=False):
            st.report_fail("vlan_untagged_member_fail", [vars.D1T1P1, vars.D1T1P2], intf_data.vlan_id)
        if not ipapi.config_ip_addr_interface(vars.D1, interface_name=vars.D1T1P1, ip_address=intf_data.knet_ipaddresses[0], subnet='24', family="ipv4", config='add'):
            st.report_fail("msg", "Failed to configure IP address: {} on interface: {}".format(intf_data.knet_ipaddresses[0], vars.D1T1P1))
        if not ipapi.config_ip_addr_interface(vars.D1, interface_name=vars.D1T1P2, ip_address=intf_data.knet_ipaddresses[2], subnet='24', family="ipv4", config='add'):
            st.report_fail("msg", "Failed to configure IP address: {} on interface: {}".format(intf_data.knet_ipaddresses[2], vars.D1T1P2))
        if not config_static_arp(vars.D1, intf_data.knet_ipaddresses[3], mac=intf_data.host_mac, interface=vars.D1T1P2, config="add"):
            st.report_fail("static_arp_create_fail", vars.D1)
        if not intfapi.interface_properties_set(vars.D1, vars.D1T1P1, 'mtu', intf_data.knet_mtu):
            st.report_fail("msg", "Failed to set the MTU to {}".format(intf_data.knet_mtu))
    elif st.get_func_name(request) == "test_ft_port_fec_nofec":
        if not vlanapi.create_vlan(vars.D2, intf_data.vlan_id):
            st.report_fail("vlan_create_fail", intf_data.vlan_id)
        if not vlanapi.add_vlan_member(vars.D1, intf_data.vlan_id, vars.D1D2P1):
            st.report_fail("vlan_untagged_member_fail", vars.D1D2P1, intf_data.vlan_id)
        if not vlanapi.add_vlan_member(vars.D2, intf_data.vlan_id, vars.D2D1P1):
            st.report_fail("vlan_untagged_member_fail", vars.D2D1P1, intf_data.vlan_id)
        if not vlanapi.add_vlan_member(vars.D2, intf_data.vlan_id, vars.D2T1P1):
            st.report_fail("vlan_untagged_member_fail", vars.D2D1P1, intf_data.vlan_id)
        if not vlanapi.delete_vlan_member(vars.D1, intf_data.vlan_id,vars.D1T1P2, tagging_mode=False):
            st.report_fail("vlan_untagged_member_fail", vars.D1T1P2, intf_data.vlan_id)
    yield
    if st.get_func_name(request) == "test_ft_port_frame_fwd_diff_mtu":
        intfapi.interface_properties_set(vars.D1, [vars.D1T1P1, vars.D1T1P2], 'mtu', intf_data.mtu_default)
    elif st.get_func_name(request) == "test_ft_port_fn_verify_shut_noshut":
        if intf_data.sub_intf_mode:
            dict1 = {'intf': intf_data.port1, 'vlan': 10, 'config': 'no'}
            dict2 = {'intf': intf_data.port2, 'vlan': 10, 'config': 'no'}
            [output, _] = exec_parallel(True, [vars.D1, vars.D2], ipapi.config_sub_interface, [dict1, dict2])
            if not all(output):
                st.report_fail("msg", "Failed to delete sub interface")
    elif st.get_func_name(request) == 'test_ft_ovr_counters':
        intfapi.interface_properties_set(vars.D1, vars.D1T1P1, 'mtu', intf_data.mtu_default)
    elif st.get_func_name(request) == "test_knet_ipmtu_ip2me_subnet":
        config_static_arp(vars.D1, intf_data.knet_ipaddresses[3], mac=intf_data.host_mac, interface=vars.D1T1P2, config="del")
        ipapi.clear_ip_configuration(vars.D1)
        vlanapi.add_vlan_member(vars.D1, intf_data.vlan_id, [vars.D1T1P1, vars.D1T1P2])
        intfapi.interface_properties_set(vars.D1, vars.D1T1P1, 'mtu', intf_data.mtu_default)
    elif st.get_func_name(request) == "test_ft_port_fec_nofec":
        if not vlanapi.delete_vlan_member(vars.D1, intf_data.vlan_id, vars.D1D2P1, tagging_mode=False):
            st.report_fail("vlan_untagged_member_fail", vars.D1D2P1, intf_data.vlan_id)
        if not vlanapi.delete_vlan_member(vars.D2, intf_data.vlan_id,[vars.D2D1P1,vars.D2T1P1], tagging_mode=False):
            st.report_fail("vlan_untagged_member_fail", vars.D1T1P2, intf_data.vlan_id)
        if not vlanapi.add_vlan_member(vars.D1, intf_data.vlan_id, vars.D1T1P2):
            st.report_fail("vlan_untagged_member_fail", vars.D2D1P1, intf_data.vlan_id)


def initialize_variables():
    intf_data.clear()
    intf_data.ip_address = '11.11.11.11'
    intf_data.ip_address1 = "11.11.11.9"
    intf_data.mask = "24"
    intf_data.mtu1 = '4096'
    intf_data.mtu2 = '9216'
    intf_data.source_mac = "00:00:02:00:00:01"
    intf_data.destination_mac = "00:00:01:00:00:01"
    intf_data.host_mac = "00:00:03:00:00:01"
    intf_data.vlan_id = str(random_vlan_list()[0])
    intf_data.mtu = '2000'
    intf_data.knet_mtu = 9200
    intf_data.mtu_default = intfapi.get_interface_property(vars.D1, vars.D1T1P1, 'mtu')[0]
    intf_data.wait_sec = 10
    intf_data.queue_id = {'PKT_TYPE_INETV4': 4, 'PKT_TYPE_IP2ME': 7, 'PKT_TYPE_SUBNET': 6}
    intf_data.knet_ipaddresses = ["1.1.1.1", "1.1.1.2", "2.2.2.1", "2.2.2.2", "1.1.1.3"]
    intf_data.dut_rt_int_mac = base_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    intf_data.result = True
    intf_data.chip = base_obj.get_hwsku(vars.D1)


def port_fec_no_fec(vars, speed, fec=["none", "rs"]):
    """
    Author : Nagarjuna Suravarapu <nagarjuna.suravarapu@broadcom.com
    By using this function we can pass parameters where we required (In my usage only fec parameter is changed )
    and we can also reuse the code so that we can reduce the codes of line.
    """
    if not isinstance(fec, list):
        st.log("FEC is not matching the criteria ..")
        st.report_fail("interface_is_down_on_dut", [vars.D1D2P1, vars.D1D2P2])
    st.log("Observed that speed as {} on interface {}".format(speed, vars.D1D2P1))
    if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'up'):
        st.report_fail("interface_is_down_on_dut", [vars.D1D2P1, vars.D1D2P2])
    if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'up'):
        st.report_fail("interface_is_down_on_dut", [vars.D2D1P1, vars.D2D1P2])
    if base_obj.get_hwsku(vars.D1).lower() == "dellemc-z9432f-o32":
        st.report_unsupported("msg", "FEC is not supported for dellemc-z9432f-o32 as they are PAM4 interfaces")
    elif (base_obj.get_hwsku(vars.D1).lower() in vars.constants[vars.D1]["TH3_PLATFORMS"]):
        if speed not in ['400G', '400000']:
            st.log("enabling the fec on Dut1")
            st.log(" if the fec on both duts interfaces mismatch then the ports should be down")
            intfapi.interface_properties_set(vars.D1, [vars.D1D2P1, vars.D1D2P2], "fec", fec[0], skip_error=False)
            if scfg_api.verify_show_running_configuration(vars.D1,sub_cmd='interface {}'.format(vars.D1D2P1),match_pattern_list=['fec {}'.format(fec[0].upper())]):
                st.log("Enable fec config, under interface is present in running config")
            else:
                st.log("Enable fec config, under interface is not present in running config")
                st.report_fail("msg", "fec config is not added in running config")
            if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'down'):
                st.report_fail("interface_is_up_on_dut", [vars.D1D2P1, vars.D1D2P2])
            if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'down'):
                st.report_fail("interface_is_up_on_dut", [vars.D2D1P1, vars.D2D1P2])
            st.log("disabling the fec on Dut1")
            intfapi.interface_properties_set(vars.D1, [vars.D1D2P1, vars.D1D2P2], "fec", fec[1], skip_error=False)
            if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'up'):
                st.report_fail("interface_is_down_on_dut", [vars.D1D2P1, vars.D1D2P2])
            if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'up'):
                st.report_fail("interface_is_down_on_dut", [vars.D2D1P1, vars.D2D1P2])
            if not verify_traffic():
                intf_data.result = False

    else:
        st.log("enabling the fec on Dut1")
        st.log("if the fec on both duts interfaces mismatch then the ports should be down")
        intfapi.interface_properties_set(vars.D1, [vars.D1D2P1, vars.D1D2P2], "fec", fec[1], skip_error=False)
        if scfg_api.verify_show_running_configuration(vars.D1,sub_cmd='interface {}'.format(vars.D1D2P1),match_pattern_list=['fec {}'.format(fec[1].upper())]):
            st.log("Enable fec config, under interface is present in running config")
        else:
            st.log("Enable fec config, under interface is not present in running config")
            st.report_fail("msg", "fec config is not added in running config")
        if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'down'):
            st.report_fail("interface_is_up_on_dut", [vars.D1D2P1, vars.D1D2P2])
        if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'down'):
            st.report_fail("interface_is_up_on_dut", [vars.D2D1P1, vars.D2D1P2])
        st.log("disabling the fec on Dut1")
        intfapi.interface_properties_set(vars.D1, [vars.D1D2P1, vars.D1D2P2], "fec", fec[0], skip_error=False)
        if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'up'):
            st.report_fail("interface_is_down_on_dut", [vars.D1D2P1, vars.D1D2P2])
        if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'up'):
            st.report_fail("interface_is_down_on_dut", [vars.D2D1P1, vars.D2D1P2])
        if not verify_traffic():
            intf_data.result = False


@pytest.mark.regression
@pytest.mark.interface_ft
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_port_check'])
@pytest.mark.inventory(testcases=['ft_port_config_mtu'])
@pytest.mark.inventory(testcases=['ft_port_fn_config_checking'])
@pytest.mark.inventory(testcases=['ft_port_frame_fwd_diff_mtu'])
@pytest.mark.inventory(testcases=['ft_port_mtu_change_verify'])
@pytest.mark.inventory(testcases=['ft_port_save_reload'])
@pytest.mark.inventory(testcases=['ft_port_speed_fn  '])
@pytest.mark.inventory(testcases=['ft_port_traffic_fn'])
@pytest.mark.inventory(testcases=['ft_specific_port_shutdown'])
def test_ft_port_frame_fwd_diff_mtu():
    intfapi.get_interface_property(vars.D1, vars.D1T1P1, "mtu")
    intfapi.get_interface_property(vars.D1, vars.D1T1P2, "mtu")
    st.log("Configuring MTU values for each interface")
    intfapi.interface_properties_set(vars.D1, [vars.D1T1P1, vars.D1T1P2], 'mtu', intf_data.mtu1)
    if scfg_api.verify_show_running_configuration(vars.D1,sub_cmd='interface {}'.format(vars.D1T1P1),match_pattern_list=['mtu {}'.format(intf_data.mtu1)]):
        st.log("MTU added under under interface, is present in running config")
    else:
        st.log("MTU added under under interface, is not present in running config")
        st.report_fail("msg", "mtu {} is not added under interface in runnign config".format(intf_data.mtu1)) 
    intf_data.tg.tg_traffic_control(action='run', stream_handle=[intf_data.streams['mtu1'], intf_data.streams['mtu2']])
    st.wait(2)
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=[intf_data.streams['mtu1'], intf_data.streams['mtu2']])
    st.log("Fetching TGen statistics")
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [intf_data.tg],
            'exp_ratio': [[1, 0]],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [intf_data.tg],
            'stream_list': [[intf_data.streams['mtu1'], intf_data.streams['mtu2']]],
        },
    }
    streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock',
                                               comp_type='packet_count')
    if not streamResult:
        st.report_fail("traffic_transmission_failed", vars.T1D1P1)
    st.report_pass("test_case_passed")


@pytest.mark.inventory(feature='KNET Debug Counter', release='Cyrus4.0.0')
@pytest.mark.inventory(testcases=['CPU_KNET_DEBUG_FUNC_008'])
@pytest.mark.inventory(testcases=['CPU_KNET_DEBUG_FUNC_009'])
def test_knet_ipmtu_ip2me_subnet():
    """
    Author : Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify the IPMTU CPU pkt counter
    Verify the IP2ME and IP2ME_SUBNET CPU pkt counter
    """
    if 'CELESTICA-BELGITE' in intf_data.chip or 'Alphanetworks-BES2348T' in intf_data.chip:
        msg = st.log("TD3-X2 platforms does not support this TC")
        st.report_unsupported("test_case_unsupported", msg)
    ipmtu_knet_tc = True
    ip2me_knet_tc = True
    if not knet_api.clear_knet_stats(vars.D1, 'all'):
        ipmtu_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_009", "msg", "Failed to clear KNET counters")
    intf_data.tg.tg_traffic_control(action='run', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(3, "Sending the traffic")
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(2, "Waiting for stabilized counters")
    if not retry_api(knet_api.validate_knet_counters, vars.D1, pkt_type='PKT_TYPE_INETV4', queue=intf_data.queue_id['PKT_TYPE_INETV4']):
        ipmtu_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_009", "msg", "Failed to validate KNET counters clear")
    ipmtu_counter = knet_api.get_knet_counter(vars.D1, 'pkt-type', 'rx_pkts', {'pkt_type': 'PKT_TYPE_INETV4'})
    if not ipmtu_counter:
        ipmtu_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_009", "msg", "Failed to get KNET counter for pkt_type: PKT_TYPE_INETV4")
    intf_data.tg.tg_traffic_config(mode='modify', stream_id=intf_data.streams['knet_stream'], frame_size=9100)
    intf_data.tg.tg_traffic_control(action='run', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(3, "Sending the traffic")
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(2, "Waiting for stabilized counters")
    ipmtu_counter2 = knet_api.get_knet_counter(vars.D1, 'pkt-type', 'rx_pkts', {'pkt_type': 'PKT_TYPE_INETV4'})
    if not ipmtu_counter2:
        ipmtu_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_009", "msg", "Failed to get KNET counter for pkt_type: PKT_TYPE_INETV4")
    if ipmtu_counter and ipmtu_counter2:
        if int(ipmtu_counter) != int(ipmtu_counter2):
            ipmtu_knet_tc = False
            report_tc_fail("CPU_KNET_DEBUG_FUNC_009", "msg", "KNET counters are incremented even the traffic pkt size is less than the port MTU")
    intf_data.tg.tg_traffic_config(mode='modify', stream_id=intf_data.streams['knet_stream'], frame_size=intf_data.knet_mtu)
    intf_data.tg.tg_traffic_control(action='run', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(3, "Sending the traffic")
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(2, "Waiting for stabilized counters")
    ipmtu_counter3 = knet_api.get_knet_counter(vars.D1, 'pkt-type', 'rx_pkts', {'pkt_type': 'PKT_TYPE_INETV4'})
    if not ipmtu_counter3:
        ipmtu_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_009", "msg", "Failed to get KNET counter for pkt_type: PKT_TYPE_INETV4")
    if ipmtu_counter2 and ipmtu_counter3:
        if int(ipmtu_counter3) <= int(ipmtu_counter2):
            ipmtu_knet_tc = False
            report_tc_fail("CPU_KNET_DEBUG_FUNC_009", "msg", "KNET counters are not incremented even the traffic pkt size is greater than the port MTU")
    if not retry_api(knet_api.validate_clear_knet_counters, vars.D1, pkt_type='PKT_TYPE_INETV4', queue=intf_data.queue_id['PKT_TYPE_INETV4']):
        ipmtu_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_009", "msg", "Failed to validate KNET counters clear")

    intf_data.tg.tg_traffic_config(mode='modify', stream_id=intf_data.streams['knet_stream'], frame_size=9100, ip_dst_addr=intf_data.knet_ipaddresses[0])
    intf_data.tg.tg_traffic_control(action='run', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(3, "Sending the traffic")
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(2, "Waiting for stabilized counters")
    ip2me_counter1 = knet_api.get_knet_counter(vars.D1, 'rx-queue', 'rx_pkts', {'queue': intf_data.queue_id['PKT_TYPE_IP2ME'], 'description': 'ip2me'})
    if not ip2me_counter1:
        ip2me_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_008", "msg", "Failed to validate KNET counters for IP2ME")
    intf_data.tg.tg_traffic_config(mode='modify', stream_id=intf_data.streams['knet_stream'], ip_dst_addr=intf_data.knet_ipaddresses[4])
    intf_data.tg.tg_traffic_control(action='run', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(3, "Sending the traffic")
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=[intf_data.streams['knet_stream']])
    st.wait(2, "Waiting for stabilized counters")
    ip2me_counter2 = knet_api.get_knet_counter(vars.D1, 'rx-queue', 'rx_pkts', {'queue': intf_data.queue_id['PKT_TYPE_IP2ME'], 'description': 'ip2me'})
    if ip2me_counter1 != ip2me_counter2:
        ip2me_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_008", "msg", "KNET counters incremented for IP2ME even the traffic not belong to that")
    ip2subnet_counter1 = knet_api.get_knet_counter(vars.D1, 'rx-queue', 'rx_pkts', {'queue': intf_data.queue_id['PKT_TYPE_SUBNET'], 'description': 'subnet'})
    if not ip2subnet_counter1:
        ip2me_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_008", "msg", "Failed to validate KNET counters for SUBNET")
    if ipmtu_knet_tc:
        st.report_tc_pass("CPU_KNET_DEBUG_FUNC_009", "msg", "Succcessfully verified the IPMTU CPU pkt counter")
    if ip2me_knet_tc:
        st.report_tc_pass("CPU_KNET_DEBUG_FUNC_008", "msg", "Succcessfully verified the IP2ME/SUBNET CPU pkt counter")
    if not (ipmtu_knet_tc and ip2me_knet_tc):
        st.report_fail("msg", "Failed to validate the IPMTU/IP2ME/SUBNET KNET CPU pkt counter")
    st.report_pass("msg", "Succcessfully validate the IPMTU/IP2ME/SUBNET KNET CPU pkt counter")


@pytest.mark.regression
@pytest.mark.interface_ft
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_port_fec_nofec'])
def test_ft_port_fec_nofec():
    """
    Author : Nagarjuna Suravarapu <nagarjuna.suravarapu@broadcom.com>
    Testbed :  D1====== D2(two links)
    Verify the port status by enabling / disabling fec when we connected it with other device.
    """
    st.banner("get the interface connected type")
    type = box_api.show_interface_transceiver_summary(vars.D1, interface=vars.D1D2P1)
    if type[0]['media_type'] == "RJ45":
        st.report_unsupported("msg","FEC is not supported for RJ45 CABLE")
    speed = intfapi.get_interface_property(vars.D1, vars.D1D2P1, "speed")
    if not speed:
        st.report_fail("Dut_failed_to_get_speed")
    if speed[0] in ['1G', '1000']:
        st.report_unsupported("msg","FEC is not supported for 1G")
    elif speed[0] in ['10G', '10000']:
        port_fec_no_fec(vars, speed[0], fec=["none", "fc"])
    else:
        port_fec_no_fec(vars, speed[0], fec=["none", "rs"])
    if intf_data.result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


@pytest.mark.regression
@pytest.mark.interface_ft
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSyInIpFn002'])
def test_ft_port_fn_verify_shut_noshut():
    if not ipapi.config_ip_addr_interface(vars.D1, interface_name=intf_data.port1, ip_address=intf_data.ip_address,
                                          subnet=intf_data.mask, family="ipv4", config='add'):
        st.report_fail("operation_failed")
    if not ipapi.config_ip_addr_interface(vars.D2, interface_name=intf_data.port2, ip_address=intf_data.ip_address1,
                                          subnet=intf_data.mask, family="ipv4", config='add'):
        st.report_fail("operation_failed")
    if not ipapi.ping_poll(vars.D1, intf_data.ip_address1, family='ipv4', iter=5, count=3, timeout=10):
        st.report_fail("ping_fail", intf_data.ip_address, intf_data.ip_address1)
    if not ipapi.ping(vars.D2, intf_data.ip_address, family='ipv4', count=1):
        st.report_fail("ping_fail", intf_data.ip_address1, intf_data.ip_address)
    for _ in range(3):
        intfapi.interface_shutdown(vars.D1, [intf_data.port1], skip_verify=True)
        intfapi.interface_noshutdown(vars.D1, [intf_data.port1], skip_verify=True)
    if not ipapi.ping_poll(vars.D1, intf_data.ip_address1, family='ipv4', iter=5, count=5, timeout=10):
        st.report_fail("ping_fail", intf_data.ip_address, intf_data.ip_address1)
    if not ipapi.ping(vars.D2, intf_data.ip_address, family='ipv4', count=1):
        st.report_fail("ping_fail", intf_data.ip_address1, intf_data.ip_address)
    rbapi.config_save_reload(vars.D1)
    if not ipapi.config_ip_addr_interface(vars.D1, interface_name=intf_data.port1, ip_address=intf_data.ip_address,
                                          subnet=intf_data.mask, family="ipv4", config='remove'):
        st.report_fail("operation_failed")
    if not ipapi.config_ip_addr_interface(vars.D2, interface_name=intf_data.port2, ip_address=intf_data.ip_address1,
                                          subnet=intf_data.mask, family="ipv4", config='remove'):
        st.report_fail("operation_failed")
    for _ in range(3):
        intfapi.interface_shutdown(vars.D1, [intf_data.port1], skip_verify=True)
        intfapi.interface_noshutdown(vars.D1, [intf_data.port1], skip_verify=True)
    if not st.poll_wait(intfapi.verify_interface_status, 15, vars.D1, vars.D1D2P1, "oper", "up"):
        st.report_fail("interface_is_down_on_dut", [vars.D1D2P1])
    if not st.poll_wait(intfapi.verify_interface_status, 15, vars.D2, vars.D2D1P1, "oper", "up"):
        st.report_fail("interface_is_down_on_dut", [vars.D2D1P1])
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.interface_ft
@pytest.mark.inventory(feature='Regression', release='Buzznik')
@pytest.mark.inventory(testcases=['FtOpSoSysPoFn010'])
def test_ft_ovr_counters():
    """
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    Verify tx_ovr and rx_ovr counters should not increment.
    Verify rx_err counters should increment, when framesize is more than MTU.
    """
    flag = 1
    properties = ['rx_ovr','tx_ovr']
    intf_data.port_list = [vars.D1T1P1, vars.D1T1P2]
    intfapi.clear_interface_counters(vars.D1)
    intf_data.tg.tg_traffic_control(action='clear_stats', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])

    intf_data.tg.tg_traffic_control(action='run', stream_handle=[intf_data.streams['traffic_tg1'],
                                                         intf_data.streams['traffic_tg2']])
    st.wait(intf_data.wait_sec)
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=[intf_data.streams['traffic_tg1'],
                                                         intf_data.streams['traffic_tg2']])
    counters = intfapi.get_interface_counter_value(vars.D1, intf_data.port_list, properties)
    for each_port in intf_data.port_list:
        for each_property in properties:
            value = counters[each_port][each_property]
            if value:
                flag = 0
                st.error("{} counters value expected 0, but found {} for port {}".format(each_property,value,each_port))
    if flag == 1:
        st.log("rx_ovr and tx_ovr counters is not increasing as expected")
    intfapi.clear_interface_counters(vars.D1)
    intfapi.interface_properties_set(vars.D1, vars.D1T1P1, 'mtu', intf_data.mtu)
    intf_data.tg.tg_traffic_control(action='clear_stats', port_handle=[intf_data.tg_ph_1])
    intf_data.tg.tg_traffic_control(action='run', stream_handle=intf_data.streams['traffic_tg1'])
    st.wait(intf_data.wait_sec)
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=intf_data.streams['traffic_tg1'])
    rx_err = intfapi.get_interface_counter_value(vars.D1, vars.D1T1P1,
                                                     properties="rx_err")[vars.D1T1P1]['rx_err']

    if not rx_err:
        st.report_fail("interface_rx_err_counters_fail", vars.D1T1P1)
    if flag == 1:
        st.log("rx_err counters is increasing as expected")
    if flag == 0:
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")

