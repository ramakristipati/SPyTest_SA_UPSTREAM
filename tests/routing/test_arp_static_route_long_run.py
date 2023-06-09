import pytest

from spytest import st, tgapi, SpyTestDict

import apis.routing.arp as arp_obj
import apis.system.reboot as rb_obj
import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.routing.bgp as bgp_obj
from utilities.utils import get_traffic_loss_duration

def init_vars():
    global vars
    vars = st.ensure_min_topology("D1T1:2")

def initialize_variables():
    global data
    data = SpyTestDict()
    data.static_arp_mac = "00:00:00:00:00:66"
    data.static_arp_ip = "192.168.12.2"
    data.ipv4_address_tgen = "10.10.10.2"
    data.ipv4_address = "10.10.10.1"
    data.ipv4_address_network = "20.20.20.0/24"
    data.mask = "24"
    data.src_mac_addr = "00:00:01:02:03:04"
    data.ipv4_address_1 = "192.168.12.1"
    data.traffic_rate = 1488095 #10% of line rate traffic pps

def get_parms():
    data.platform = basic_obj.get_hwsku(vars.D1)
    data.constants = st.get_datastore(vars.D1, "constants", "default")

@pytest.fixture(scope="module", autouse=True)
def arp_static_route_reboot_module_hooks(request):
    # add things at the start of this module
    init_vars()
    initialize_variables()
    get_parms()

    global tg_handler
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2")
    global tg
    tg = tg_handler["tg"]
    st.log("configuring static route")
    adding_static_route()
    st.log("Getting ARP entry dynamically")
    adding_dynamic_arp()
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.ipv4_address_1, data.mask, family="ipv4", config='add')
    st.log("Configuring static ARP")
    arp_obj.add_static_arp(vars.D1, data.static_arp_ip, data.static_arp_mac, vars.D1T1P2)
    st.log("Verifying static route entries before save and reboot/fast-reboot/warm-reboot")
    static_route_verify()
    st.log("Verifying dynamic ARP entries before save and reboot/fast-reboot/warm-reboot")
    if not arp_obj.verify_arp(vars.D1, data.ipv4_address_tgen, data.src_mac_addr, vars.D1T1P1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.ipv4_address_tgen, vars.D1)
    else:
        st.log("Verified that dynamic ARP entry is present in arp table")
    st.log("Verifying static ARP entries before save and reboot/fast-reboot/warm-reboot")
    if not arp_obj.verify_arp(vars.D1, data.static_arp_ip, data.static_arp_mac, ""):
        st.report_fail("static_arp_create_fail", vars.D1)
    else:
        st.log("Verified that static ARP entry is present in arp table")
    st.log("Save the config on the DUT")
    rb_obj.config_save(vars.D1)
    st.log("saving config in vtysh mode to save static route")
    rb_obj.config_save(vars.D1, shell="vtysh")
    yield
    # Below step will clear IP adresses configured on different interfaces in the device
    ip_obj.clear_ip_configuration(st.get_dut_names())
    #Below step will clear static route configured in the device
    ip_obj.delete_static_route(vars.D1, data.ipv4_address_tgen, data.ipv4_address_network, family='ipv4', shell="vtysh")
    #Below step will delete static arp entries configured in the device
    arp_obj.delete_static_arp(vars.D1, data.static_arp_ip, vars.D1T1P2)

@pytest.fixture(scope="function", autouse=True)
def arp_static_route_reboot_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    # add things at the end every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case

def adding_static_route():
    st.log("About to add ipv4 address on TGen connected interface")
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.ipv4_address, data.mask, family="ipv4", config='add')
    st.log("Enabling docker routing config mode to split")
    bgp_obj.enable_docker_routing_config_mode(vars.D1)
    st.log("configuring static route via vtysh mode")
    ip_obj.create_static_route(vars.D1, data.ipv4_address_tgen, data.ipv4_address_network, shell="vtysh", family="ipv4")

def static_route_verify():
    st.log("Ip address configuration verification")
    if not st.poll_wait(ip_obj.verify_interface_ip_address, 60, vars.D1, vars.D1T1P1, "{}/{}".format(data.ipv4_address, data.mask),
                                              family="ipv4"):
        st.report_fail("ip_routing_int_create_fail", vars.D1T1P1)
    else:
        st.log("Successfully added ipv4 address on TGen connected interface")

    st.log("static route configuration verification")
    if not st.poll_wait(ip_obj.verify_ip_route, 120, vars.D1, "ipv4", ip_address=data.ipv4_address_network, type="S"):
        st.error("Static route - {} information not exists.".format(data.ipv4_address_network))
        st.report_fail("ip_static_route_create_fail", data.ipv4_address_network)
    else:
        st.log("creation of static route is successful")

def adding_dynamic_arp():
    data.h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', intf_ip_addr=data.ipv4_address_tgen,
                                gateway=data.ipv4_address, src_mac_addr=data.src_mac_addr, arp_send_req='1')
    st.wait(10)
    st.log("INTFCONF: " + str(data.h1))
    st.log("Pinging from tgen to DUT's TGen connected IPV4 interface")
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=data.h1['handle'], dst_ip=data.ipv4_address,
                      ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    if not st.poll_wait2(5, 5, arp_obj.show_arp, vars.D1, data.ipv4_address_tgen):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.ipv4_address_tgen, vars.D1)

@pytest.mark.inventory(feature='warmboot', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRtStRtFn016'])
def test_ft_arp_static_route_config_mgmt_verifying_config_with_warm_reboot():
    '''
    Author: Surendra Kumar Vella(surendrakumar.vella@broadcom.com)
    Verify static ARP route config after warm-reboot
    '''
    dut_mac = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    stream_tg1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"],port_handle2=tg_handler["tg_ph_2"], mode='create', transmit_mode="continuous",
                                       length_mode='fixed', rate_pps=data.traffic_rate, mac_src='00.00.00.11.12.53',
                                       mac_dst=dut_mac, l3_protocol='ipv4', ip_src_addr=data.ipv4_address_tgen,
                                       ip_dst_addr=data.static_arp_ip)

    stream_id = stream_tg1['stream_id']
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg],
            'stream_list': [[stream_id]],
        }
    }
    st.log("Checking whether the platform supports warm-reboot")
    if not data.platform.lower() in data.constants['WARM_REBOOT_SUPPORTED_PLATFORMS']:
        st.report_unsupported('test_case_unsupported', "warm-reboot not supported in this platform")
    st.log("Performing warm-reboot on DUT")
    validate_tg_traffic_config(tg, tg, tg_handler["tg_ph_1"], tg_handler["tg_ph_2"], stream_id, data.traffic_rate, run=True)
    validate_tg_traffic_config(tg, tg, tg_handler["tg_ph_1"], tg_handler["tg_ph_2"], stream_id, data.traffic_rate, stop=True, get_traffic_loss=True)

    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count', tolerance_factor=1):
        st.error("due to traffic loss,traffic verificaiton failed")
        st.report_fail("ip_traffic_fail")

    st.banner("verify traffic statistics before warmboot")
    validate_tg_traffic_config(tg, tg, tg_handler["tg_ph_1"], tg_handler["tg_ph_2"], stream_id, data.traffic_rate, run=True)
    validate_tg_traffic_config(tg, tg, tg_handler["tg_ph_1"], tg_handler["tg_ph_2"], stream_id, data.traffic_rate, stop=True, get_traffic_loss=True)
    validate_tg_traffic_config(tg, tg, tg_handler["tg_ph_1"], tg_handler["tg_ph_2"], stream_id, data.traffic_rate, run=True)
    rb_obj.warm_reboot(vars.D1)
    st.banner("verify traffic statistics after warmboot")
    validate_tg_traffic_config(tg, tg, tg_handler["tg_ph_1"], tg_handler["tg_ph_2"], stream_id, data.traffic_rate, stop=True, get_traffic_loss=True)
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count', tolerance_factor=0):
        st.error("traffic verification failed after warmboot")
        st.report_fail("traffic_verification_failed_during_warm_reboot")
    st.log("Verifying static route entries after save and warm-reboot")
    st.wait(5)
    static_route_verify()
    st.log("Verifying dynamic ARP entries after save and warm-reboot")
    if not arp_obj.verify_arp(vars.D1, data.ipv4_address_tgen, data.src_mac_addr, vars.D1T1P1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.ipv4_address_tgen, vars.D1)
    else:
        st.log("Verified that dynamic ARP entry is present in arp table")
    if st.get_ui_type(vars.D1) != "click":
        st.log("Verifying static ARP entries after save and warm-reboot")
        if not arp_obj.verify_arp(vars.D1, data.static_arp_ip, data.static_arp_mac, ""):
            st.report_fail("static_arp_create_fail", vars.D1)
        else:
            st.log("Verified that static ARP entry is present in arp table")
    st.report_pass("test_case_passed")

@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_test_arp_after_fast_reboot'])
@pytest.mark.inventory(testcases=['FtOpSoRtStRtFn015'])
def test_ft_arp_static_route_config_mgmt_verifying_config_with_save_fast_reboot():
    '''
    Author: Surendra Kumar Vella(surendrakumar.vella@broadcom.com)
    Verify static ARP route config after save fast-reboot
    '''
    st.log("Performing fast-reboot on DUT")
    st.reboot(vars.D1, "fast")
    st.log("Verifying static route entries after save and fast-reboot")
    st.wait(5)
    static_route_verify()
    adding_dynamic_arp()
    st.log("Verifying dynamic ARP entries after save and fast-reboot")
    if not arp_obj.verify_arp(vars.D1, data.ipv4_address_tgen, data.src_mac_addr, vars.D1T1P1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.ipv4_address_tgen, vars.D1)
    else:
        st.log("Verified that dynamic ARP entry is present in arp table")
    st.report_pass("test_case_passed")


@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRtStRtFn014'])
def test_ft_arp_static_route_config_mgmt_verifying_config_with_save_reboot():
    '''
    Author: Surendra Kumar Vella(surendrakumar.vella@broadcom.com)
    Verify static ARP route config after save cold-reboot
    '''
    st.log("Performing reboot on DUT")
    st.reboot(vars.D1)
    st.log("Verifying static route entries after save and reboot")
    st.wait(5)
    static_route_verify()
    adding_dynamic_arp()
    st.log("Verifying dynamic ARP entries after save and reboot")
    if not arp_obj.verify_arp(vars.D1, data.ipv4_address_tgen, data.src_mac_addr, vars.D1T1P1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.ipv4_address_tgen, vars.D1)
    else:
        st.log("Verified that dynamic ARP entry is present in arp table")
    st.report_pass("test_case_passed")
def validate_tg_traffic_config(tg1,tg2,tg_ph_1,tg_ph_2,stream_id,traffic_rate,**kwargs):

    '''

    :param tg1:
    :param tg2:
    :param tg_ph_1:
    :param tg_ph_2:
    :param stream_id:
    :param traffic_rate:
    :param kwargs:
    :return:
    '''
    get_traffic_loss = kwargs.get('get_traffic_loss', False)
    if kwargs.get('run'):
        tg1.tg_traffic_control(action='clear_stats', port_handle=[tg_ph_1,tg_ph_2])
        tg1.tg_traffic_control(action='run', stream_handle=stream_id)

    if kwargs.get('stop'):
        tg1.tg_traffic_control(action='stop', stream_handle=stream_id)


    if get_traffic_loss:
        tg_out1 = tgapi.get_traffic_stats(tg1, mode='streams', port_handle=tg_ph_1, direction='tx', stream_handle=stream_id)
        tg_out2 = tgapi.get_traffic_stats(tg2, mode='streams', port_handle=tg_ph_2, direction='rx', stream_handle=stream_id)
        tx_pkt = tg_out1['tx']['total_packets']
        rx_pkt = tg_out2['rx']['total_packets']
        get_traffic_loss_duration(tx_pkt, rx_pkt,traffic_rate)
