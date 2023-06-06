##################################################################################
#Script Title : VRF Lite
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com
#################################################################################

import pytest
from spytest import st,utils
from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen.tgen_utils import validate_tgen_traffic

from vrf_vars import * #all the variables used for vrf testcase
from vrf_vars import data
import vrf_lib as loc_lib
from apis.system import basic
import apis.switching.portchannel as pc_api
import apis.routing.ip as ip_api
import apis.routing.vrf as vrf_api
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
import apis.routing.arp as arp_api
import apis.system.interface as intf_api
import apis.system.reboot as reboot_api
from utilities import parallel
from utilities.utils import rif_support_check, report_tc_fail

def initialize_topology():
    st.banner("Initialize variables")
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2", "D2T1:2")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    utils.exec_all(True,[[bgp_api.enable_docker_routing_config_mode,data.dut1], [bgp_api.enable_docker_routing_config_mode,data.dut2]])
    platform_1 = basic.get_hwsku(data.dut1)
    platform_2 = basic.get_hwsku(data.dut2)
    data.platform_1 = rif_support_check(data.dut1, platform=platform_1.lower())
    data.platform_2 = rif_support_check(data.dut2, platform=platform_2.lower())
    data.d1_dut_ports = [vars.D1D2P1,vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]
    data.d2_dut_ports = [vars.D2D1P1, vars.D2D1P2,vars.D2D1P3, vars.D2D1P4]
    data.dut1_tg1_ports = [vars.D1T1P1]
    data.dut2_tg1_ports = [vars.D2T1P1]
    data.tg_dut1_hw_port = vars.T1D1P1
    data.tg_dut2_hw_port = vars.T1D2P1
    data.tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg_dut1_p1 = data.tg1.get_port_handle(vars.T1D1P1)
    data.tg_dut2_p1 = data.tg2.get_port_handle(vars.T1D2P1)
    data.d1_p1_intf_v4 = {}
    data.d1_p1_intf_v6 = {}
    data.d2_p1_intf_v4 = {}
    data.d2_p1_intf_v6 = {}
    data.d1_p1_bgp_v4 = {}
    data.d1_p1_bgp_v6 = {}
    data.d2_p1_bgp_v4 = {}
    data.d2_p1_bgp_v6 = {}
    data.stream_list = {}
    data.sub_intf = st.get_args("routed_sub_intf")
    st.banner("sub interface mode is: {}".format(data.sub_intf))
    if data.sub_intf:
        data.phy_port121 = "{}.{}".format(data.d1_dut_ports[0],111)
        data.phy_port211 = "{}.{}".format(data.d2_dut_ports[0],111)
        data.phy_port123 = data.d1_dut_ports[2]
        data.phy_port213 = data.d2_dut_ports[2]
        data.phy_port124 = data.d1_dut_ports[3]
        data.phy_port214 = data.d2_dut_ports[3]
        data.port_channel12 = 'PortChannel10.123'
    else:
        data.phy_port121 = data.d1_dut_ports[0]
        data.phy_port211 = data.d2_dut_ports[0]
        data.phy_port123 = data.d1_dut_ports[2]
        data.phy_port213 = data.d2_dut_ports[2]
        data.phy_port124 = data.d1_dut_ports[3]
        data.phy_port214 = data.d2_dut_ports[3]
        data.port_channel12 = 'PortChannel10'

@pytest.fixture(scope='module', autouse = True)
def prologue_epilogue():
    initialize_topology()
    loc_lib.vrf_base_config()
    yield
    #loc_lib.vrf_base_unconfig()

@pytest.mark.sanity
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli001'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli006'])
def test_VrfFun001_06():
    st.log('#######################################################################################################################')
    st.log(' Combining FtRtVrfFun001 and FtRtVrfFun006')
    st.log(' FtRtVrfFun001: Verify address family IPv4 and IPv6 in VRF instance')
    st.log(' FtRtVrfFun006: Configure multiple interfaces to a VRF and configure same interface to multiple VRFs')
    st.log('#######################################################################################################################')

    err_list = []
    output = vrf_api.get_vrf_verbose(dut = data.dut1,vrfname = vrf_name[0])
    if vrf_name[0] in output['vrfname']:
        st.banner('STEP 1 PASS: VRF {} configured on DUT1 is as expected'.format(vrf_name[0]))
    else:
        err = st.banner('STEP 1 FAIL: VRF {} configured on DUT1 is not expected'.format(vrf_name[0]))
        err_list.append(err)
    for value in output['interfaces']:
        if data.phy_port121 or dut1_loopback[0] or data.dut1_loopback[1] or value == 'Vlan11':
            st.banner('STEP 2 PASS: Bind to VRF for intf {} is as expected'.format(value))
        else:
            err = st.banner('STEP 2 FAIL: Bind to VRF for intf {} is not as expected'.format(value))
            err_list.append(err)
    output = vrf_api.get_vrf_verbose(dut = data.dut2,vrfname = vrf_name[0])
    if vrf_name[0] in output['vrfname']:
        st.banner('STEP 3 PASS: VRF {} configured on DUT1 is as expected'.format(vrf_name[0]))
    else:
        err = st.banner('STEP 3 FAIL: VRF {} configured on DUT1 is as not expected'.format(vrf_name[0]))
        err_list.append(err)
    for value in output['interfaces']:
        if data.d2_dut_ports[0] or dut2_loopback[0] or value == 'Vlan16':
            st.banner('STEP 4 PASS: Bind to VRF for intf {} is as expected'.format(value))
        else:
            err = st.banner('STEP 4 FAIL: Bind to VRF for intf {} is not as expected'.format(value))
            err_list.append(err)
    if not ip_api.verify_interface_ip_address(data.dut1, data.port_channel12 ,dut1_dut2_vrf_ip[0]+'/24', vrfname = vrf_name[2]):
        err = st.banner('STEP 5 FAIL: IPv4 address configuration on portchannel interface failed')
        err_list.append(err)
    else:
        st.banner('STEP 5 PASS: IPv4 address configuration on portchannel interface')
    if not ip_api.verify_interface_ip_address(data.dut2, data.port_channel12 ,dut2_dut1_vrf_ipv6[0]+'/64', vrfname = vrf_name[2],family='ipv6'):
        err = st.banner('STEP 6 FAIL: IPv6 address configuration on portchannel interface failed')
        err_list.append(err)
    else:
        st.banner('STEP 6 PASS: IPv6 address configuration on portchannel interface')
    if arp_api.get_arp_count(data.dut1, vrf = vrf_name[1]) < 2:
        err = st.banner('STEP 7 FAIL: ARP entry for VRF-102 not as expected on DUT1')
        err_list.append(err)
    else:
        st.banner('STEP 7 PASS: ARP entry for VRF-102 found as expected on DUT1')
    if arp_api.get_arp_count(data.dut2, vrf = vrf_name[1]) < 2:
        err = st.banner('STEP 8 FAIL: ARP entry for VRF-102 not as expected on DUT2')
        err_list.append(err)
    else:
        st.banner('STEP 8 PASS: ARP entry for VRF-102 found as expected on DUT2')
    if arp_api.get_ndp_count(data.dut1, vrf = vrf_name[1]) < 2:
        err = st.banner('STEP 9 FAIL: NDP entry for VRF-102 not as expected on DUT1')
        err_list.append(err)
    else:
        st.banner('STEP 9 PASS: NDP entry for VRF-102 found as expected on DUT1')
    if arp_api.get_ndp_count(data.dut2, vrf = vrf_name[1]) < 2:
        err = st.banner('STEP 10 FAIL: NDP entry for VRF-102 not as expected on DUT2')
        err_list.append(err)
    else:
        st.banner('STEP 10 PASS: NDP entry for VRF-102 found as expected on DUT2')
    if not loc_lib.verify_bgp(phy = '1',ip = 'ipv6'):
        err = st.banner('STEP 11 FAIL: IPv6 BGP session on VRF-101 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 11 PASS: IPv6 BGP session on VRF-101 did come up')
    if not loc_lib.verify_bgp(ve = '1',ip = 'ipv4'):
        err = st.banner('STEP 12 FAIL: IPv4 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 12 PASS: IPv4 BGP session on VRF-102 did come up')
    if not loc_lib.verify_bgp(ve = '1',ip = 'ipv6'):
        err = st.banner('STEP 13 FAIL: IPv6 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 13 PASS: IPv6 BGP session on VRF-102 did come up')
    if not loc_lib.verify_bgp(pc = '1',ip = 'ipv4'):
        err = st.banner('STEP 14 FAIL: IPv4 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 14 PASS: IPv4 BGP session on VRF-103 did come up')
    if not loc_lib.verify_bgp(pc = '1',ip = 'ipv6'):
        err = st.banner('STEP 15 FAIL: IPv6 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 15 PASS: IPv6 BGP session on VRF-103 did come up')

    if err_list:
        loc_lib.debug_bgp_vrf()

    st.report_result(err_list, first_only=True)

#@pytest.mark.depends('test_VrfFun001_06')
def lib_test_VrfFun002():
    result = 0
    loc_lib.clear_tg()
    st.banner('Verify ping and traceroute on physical interface on non default vrf for both IPv4 and IPv6')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ip[0], interface= vrf_name[0], count = 2):
        st.banner('lib_test_VrfFun002 STEP 1 FAIL: IPv4 Ping from Vrf-101-DUT1 to Vrf-101-DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun002 STEP 1 PASS: IPv4 Ping from Vrf-101-DUT1 to Vrf-101-DUT2')
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ip[0], vrf_name= vrf_name[0], timeout = 3):
        st.banner('lib_test_VrfFun002 STEP 2 FAIL: IPv4 Traceroute from Vrf-101-DUT1 to Vrf-101-DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun002 STEP 2 PASS: IPv4 Traceroute from Vrf-101-DUT1 to Vrf-101-DUT2')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', interface= vrf_name[0], count = 2):
        st.banner('lib_test_VrfFun002 STEP 3 FAIL: IPv6 Ping from Vrf-101-DUT1 to Vrf-101-DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun002 STEP 3 PASS: IPv6 Ping from Vrf-101-DUT1 to Vrf-101-DUT2')
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', vrf_name= vrf_name[0], timeout = 3):
        st.banner('lib_test_VrfFun002 STEP 4 FAIL: IPv6 Traceroute from Vrf-101-DUT1 to Vrf-101-DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun002 STEP 4 PASS: IPv6 Traceroute from Vrf-101-DUT1 to Vrf-101-DUT2')
    if not ip_api.verify_ip_route(data.dut1, vrf_name = vrf_name[0], type='B', nexthop = tg1_dut1_vrf_ip[0], interface = 'Vlan'+dut1_tg1_vlan[0]):
        st.banner('lib_test_VrfFun002 STEP 4 FAIL: IPv4 routes on VRF-101 not learnt on DUT1')
        result += 1
    else:
        st.banner('lib_test_VrfFun002 STEP 4 PASS: IPv4 routes on VRF-101 learnt on DUT1')
    if not ip_api.verify_ip_route(data.dut2, vrf_name = vrf_name[0], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = data.phy_port211):
        st.banner('lib_test_VrfFun002 STEP 5 FAIL: IPv4 routes on VRF-101, not learnt on DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun002 STEP 5 PASS: IPv4 routes on VRF-101 learnt on DUT2')
    loc_lib.clear_tg()
    if not ip_api.verify_ip_route(data.dut1,vrf_name=vrf_name[0],type='B',nexthop=tg1_dut1_vrf_ipv6[0],interface='Vlan'+dut1_tg1_vlan[0],family='ipv6'):
        st.banner('lib_test_VrfFun002 STEP 6 FAIL: IPv6 routes on VRF-101, not learnt on DUT1')
        result += 1
    else:
        st.banner('lib_test_VrfFun002 STEP 6 PASS: IPv6 routes on VRF-101 learnt on DUT1')
    if not ip_api.verify_ip_route(data.dut2, vrf_name =vrf_name[0], type='B', nexthop =dut1_dut2_vrf_ipv6[0], interface =data.phy_port211, family ='ipv6'):
        st.banner('lib_test_VrfFun002 STEP 7 FAIL: IPv6 routes on VRF-101, not learnt on DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun002 STEP 7 PASS: IPv6 routes on VRF-101 learnt on DUT2')
    return result

@pytest.mark.sanity
#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli002'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun016'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun017'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun018'])
def test_VrfFun002():
    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun002: Bind/unbind/rebind VRF to a physical interface ')
    st.log('#######################################################################################################################')
    result = 0
    st.banner('Unbind and rebind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses')
    loc_lib.dut_vrf_bind(phy = '1', config = 'no')
    loc_lib.dut_vrf_bind(phy = '1')
    result = lib_test_VrfFun002()
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('BGP is not converging after unbind/bind on physical interface')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

def lib_test_VrfFun003():

    result = 0
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('ve_v4_stream'), duration = '2')
    st.banner('Verify ping and traceroute on virtual interface non-default vrf for both IPv4 and IPv6')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ip[0], interface= vrf_name[1], count = 2):
        st.banner('lib_test_VrfFun003 STEP 1 FAIL: IPv4 Ping from Vrf-102-DUT1 to vrf DUT2-102')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 1 PASS: IPv4 Ping from Vrf-102-DUT1 to vrf DUT2-102')
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ip[0], vrf_name= vrf_name[1], timeout = 3):
        st.banner('lib_test_VrfFun003 STEP 2 FAIL: IPv4 Traceroute Vrf-102-DUT1 to vrf DUT2-102')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 2 PASS: IPv4 Traceroute Vrf-102-DUT1 to vrf DUT2-102')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', interface= vrf_name[1], count = 2):
        st.banner('lib_test_VrfFun003 STEP 3 FAIL: IPv6 Ping Vrf-102-DUT1 to vrf DUT2-102')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 3 PASS: IPv6 Ping Vrf-102-DUT1 to vrf DUT2-102')
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', vrf_name= vrf_name[1], timeout = 3):
        st.banner('lib_test_VrfFun003 STEP 4 FAIL: IPv6 Traceroute Vrf-102-DUT1 to vrf DUT2-102')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 4 PASS: IPv6 Traceroute Vrf-102-DUT1 to vrf DUT2-102')
    if not ip_api.verify_ip_route(data.dut1, vrf_name = vrf_name[1], type='B', nexthop = tg1_dut1_vrf_ip[1], interface = 'Vlan'+dut1_tg1_vlan[1]):
        st.banner('lib_test_VrfFun003 STEP 5 FAIL: IPv4 routes on VRF-102, not learnt on DUT1')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 5 PASS: IPv4 routes on VRF-102, learnt on DUT1')
    if not ip_api.verify_ip_route(data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = 'Vlan'+dut2_dut1_vlan[0]):
        st.banner('lib_test_VrfFun003 STEP 6 FAIL: IPv4 routes on VRF-102, not learnt on DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 6 PASS: IPv4 routes on VRF-102, learnt on DUT2')

    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('ve_v4_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('ve_v4_stream'))

    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if data.platform_1 and data.platform_2:
        st.banner("Verifying RIF Counters on VLAN Interfaces for V4")
        tx = {'dut': data.dut2, 'interface': 'Vlan'+dut1_dut2_vlan[0], 'count_type': 'tx_ok'}
        rx = {'dut': data.dut1, 'interface': 'Vlan'+dut1_dut2_vlan[0], 'count_type': 'rx_ok'}
        success_v4 = loc_lib.rifcounter_validation(tx=tx, rx=rx)
        intf_api.clear_interface_counters(data.dut1, rif=True)
        intf_api.clear_interface_counters(data.dut2, rif=True)
    if not aggrResult:
        st.banner('lib_test_VrfFun003 STEP 7 FAIL: IPv4 Traffic on VRF-102 bound to virtual interfaces')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 7 PASS: IPv4 Traffic on VRF-102 bound to virtual interfaces')

    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('ve_v6_stream'), duration = '2')
    if not ip_api.verify_ip_route(data.dut1,vrf_name=vrf_name[1],type='B',nexthop=tg1_dut1_vrf_ipv6[1],interface='Vlan'+dut1_tg1_vlan[1],family='ipv6'):
        st.banner('lib_test_VrfFun003 STEP 8 FAIL: IPv6 routes on VRF-102, not learnt on DUT1')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 8 PASS: IPv6 routes on VRF-102, not learnt on DUT1')

    if not ip_api.verify_ip_route(data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = 'Vlan'+dut2_dut1_vlan[0],family='ipv6'):
        st.banner('lib_test_VrfFun003 STEP 9 FAIL: IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 9 PASS: IPv6 routes on VRF-102, not learnt on DUT2')

    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('ve_v6_stream')]]}}

    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('ve_v6_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if data.platform_1 and data.platform_2:
        st.banner("Verifying RIF Counters on VLAN Interfaces for V6")
        tx = {'dut': data.dut2, 'interface': 'Vlan'+dut1_dut2_vlan[0], 'count_type': 'tx_ok'}
        rx = {'dut': data.dut1, 'interface': 'Vlan'+dut1_dut2_vlan[0], 'count_type': 'rx_ok'}
        success_v6 = loc_lib.rifcounter_validation(tx=tx, rx=rx)
        intf_api.clear_interface_counters(data.dut1, rif=True)
        intf_api.clear_interface_counters(data.dut2, rif=True)
        if success_v4 is False or success_v6 is False:
            report_tc_fail('RIF_COUNT_FUNC_009', 'rif_counters_update', 'Failed', 'VLAN_User_Vrf')
            result += 1
        else:
            st.report_tc_pass('RIF_COUNT_FUNC_009', 'rif_counters_update', 'Successful', 'VLAN_User_Vrf')
    else:
        st.report_tc_unsupported("RIF_COUNT_FUNC_009", "rif_counters_update", "unsupported", "VLAN-Interface")

    if not aggrResult:
        st.banner('lib_test_VrfFun003 STEP 10 FAIL: IPv6 Traffic on VRF-102 bound to virtual interfaces failed')
        result += 1
    else:
        st.banner('lib_test_VrfFun003 STEP 10 PASS: IPv6 Traffic on VRF-102 bound to virtual interfaces')
    return result

@pytest.mark.sanity
#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli003'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun019'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun021'])
@pytest.mark.inventory(feature='RIF Counters', release='Cyrus4.0.0', testcases=['RIF_COUNT_FUNC_009'])
@pytest.mark.inventory(feature='RIF Counters', release='Cyrus4.0.0', testcases=['RIF_COUNT_FUNC_014'])
def test_VrfFun003():
    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun003: Bind/unbind/rebind VRF to a virtual interface ')
    st.log('#######################################################################################################################')

    result = 0
    st.banner('Unbind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses')
    loc_lib.dut_vrf_bind(ve = '1', config = 'no')
    st.banner('Rebind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses')
    loc_lib.dut_vrf_bind(ve = '1')
    result = lib_test_VrfFun003()
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('BGP is not converging after unbind/bind on virtual interface')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

def lib_test_VrfFun004():
    result = 0
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.values(), duration = '2')
    st.banner('Verify ping and traceroute on portchannel non-default vrf for both IPv4 and IPv6')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ip[0], interface= vrf_name[2], count = 2):
        st.banner('lib_test_VrfFun004 STEP 1 FAIL: IPv4 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 1 PASS: IPv4 Ping from Vrf-103-DUT1 to Vrf-103-DUT2')
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ip[0], vrf_name= vrf_name[2], timeout = 3):
        st.banner('lib_test_VrfFun004 STEP 2 FAIL: IPv4 Traceroute from Vrf-103-DUT1 to Vrf-103-DUT2 failed')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 2 PASS: IPv4 Traceroute from Vrf-103-DUT1 to Vrf-103-DUT2')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', interface= vrf_name[2], count = 2):
        st.banner('lib_test_VrfFun004 STEP 3 FAIL: IPv6 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 3 PASS: IPv6 Ping from Vrf-103-DUT1 to Vrf-103-DUT2')
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', vrf_name= vrf_name[2], timeout = 3):
        st.banner('lib_test_VrfFun004 STEP 4 FAIL: IPv6 Traceroute from Vrf-103-DUT1 to Vrf-103-DUT2 failed')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 4 PASS: IPv6 Traceroute from Vrf-103-DUT1 to Vrf-103-DUT2')
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut1, vrf_name = vrf_name[2], type='B', nexthop = tg1_dut1_vrf_ip[2], interface = 'Vlan'+dut1_tg1_vlan[2], retry_count= 2, delay= 5):
        st.banner('lib_test_VrfFun004 STEP 5 FAIL: IPv4 routes on VRF-103, not learnt on DUT1')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 5 PASS: IPv4 routes on VRF-103, learnt on DUT1')
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = data.port_channel12, retry_count= 2, delay= 5):
        st.banner('lib_test_VrfFun004 STEP 6 FAIL: IPv4 routes on VRF-103, not learnt on DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 6 PASS: IPv4 routes on VRF-103, learnt on DUT2')

    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('pc_v4_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.values())

    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if data.platform_1 and data.platform_2:
        st.banner("Verifying RIF Counters on LAG Interfaces for V4")
        tx = {'dut': data.dut2, 'interface': data.port_channel12, 'count_type': 'tx_ok'}
        rx = {'dut': data.dut1, 'interface': data.port_channel12, 'count_type': 'rx_ok'}
        success_v4 = loc_lib.rifcounter_validation(tx=tx, rx=rx)
        intf_api.clear_interface_counters(data.dut1, rif=True)
        intf_api.clear_interface_counters(data.dut2, rif=True)
    if not aggrResult:
        st.banner('lib_test_VrfFun004 STEP 7 FAIL: IPv4 Traffic on VRF-103 bound to port channel failed')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 7 PASS: IPv4 Traffic on VRF-103 bound to port channel')

    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.values(), duration = '2')
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut1, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = tg1_dut1_vrf_ipv6[2], interface = 'Vlan'+dut1_tg1_vlan[2], retry_count= 2, delay= 5):
        st.banner('lib_test_VrfFun004 STEP 8 FAIL: IPv6 routes on VRF-103, not learnt on DUT1')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 8 PASS: IPv6 routes on VRF-103, learnt on DUT1')

    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = data.port_channel12,retry_count= 2, delay= 5):
        st.banner('lib_test_VrfFun004 STEP 9 FAIL: IPv6 routes on VRF-103, not learnt on DUT2')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 9 PASS: IPv6 routes on VRF-103, learnt on DUT2')

    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('pc_v6_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('pc_v6_stream'))

    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if data.platform_1 and data.platform_2:
        st.banner("Verifying RIF Counters on LAG Interfaces for V6")
        tx = {'dut': data.dut2, 'interface': data.port_channel12, 'count_type': 'tx_ok'}
        rx = {'dut': data.dut1, 'interface': data.port_channel12, 'count_type': 'rx_ok'}
        success_v6 = loc_lib.rifcounter_validation(tx=tx, rx=rx)
        intf_api.clear_interface_counters(data.dut1, rif=True)
        intf_api.clear_interface_counters(data.dut2, rif=True)
        if success_v4 is False or success_v6 is False:
            report_tc_fail('RIF_COUNT_FUNC_010', 'rif_counters_update', 'Failed', 'LAG_User_Vrf')
            result += 1
        else:
            st.report_tc_pass('RIF_COUNT_FUNC_010', 'rif_counters_update', 'Successful', 'LAG_User_Vrf')
    else:
        st.report_tc_unsupported("RIF_COUNT_FUNC_010","rif_counters_update", "unsupported", "LAG-Interface")
    if not aggrResult:
        st.banner('lib_test_VrfFun004 STEP 10 FAIL: IPv6 Traffic on VRF-103 bound to port channel failed')
        result += 1
    else:
        st.banner('lib_test_VrfFun004 STEP 10 PASS: IPv6 Traffic on VRF-103 bound to port channel')

    return result

@pytest.mark.sanity
#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli004'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun022'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun023'])
@pytest.mark.inventory(feature='RIF Counters', release='Cyrus4.0.0', testcases=['RIF_COUNT_FUNC_010'])
def test_VrfFun004():
    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun004: Bind/unbind/rebind VRF to a port channel interface ')
    st.log('#######################################################################################################################')

    result = 0
    st.banner('Unbind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses')
    loc_lib.dut_vrf_bind(pc = '1', config = 'no')

    st.banner('Verify ping and traceroute on portchannel global vrf for both IPv4 and IPv6')
    utils.exec_all(True, [[pc_api.create_portchannel, data.dut1, 'PortChannel10'], [pc_api.create_portchannel, data.dut2, 'PortChannel10']])
    utils.exec_all(True, [[pc_api.add_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[2]], [pc_api.add_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[2]]])
    utils.exec_all(True, [[pc_api.add_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[3]], [pc_api.add_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[3]]])

    if data.sub_intf:
        st.banner('Create the PortChannel sub interfaces between DUT1 and DUT2 ')
        dict1 = {'intf': data.port_channel12, 'vlan': 40}
        dict2 = {'intf': data.port_channel12, 'vlan': 40}
        st.exec_each2([data.dut1, data.dut2], ip_api.config_sub_interface, [dict1, dict2])

    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.port_channel12,dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, data.port_channel12, dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.port_channel12,dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, data.port_channel12, dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ip[0], count = 2):
        st.banner('STEP 1 FAIL: IPv4 Ping from Portchannel10-DUT1 to Portchannel10-DUT2 failed')
        result += 1
    else:
        st.banner('STEP 1 PASS: IPv4 Ping from Portchannel10-DUT1 to Portchannel10-DUT2')
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ip[0],timeout = 3):
        st.banner('STEP 2 FAIL: IPv4 Traceroute from Portchannel10-DUT1 to Portchannel10-DUT2 failed')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv4 Traceroute from Portchannel10-DUT1 to Portchannel10-DUT2')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', count = 2):
        st.banner('STEP 3 FAIL: IPv6 Ping from Portchannel10-DUT1 to Portchannel10-DUT2 failed')
        result += 1
    else:
        st.banner('STEP 3 PASS: IPv6 Ping from Portchannel10-DUT1 to Portchannel10-DUT2')
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', timeout = 3):
        st.banner('STEP 4 FAIL: IPv6 Traceroute from Portchannel10-DUT1 to Portchannel10-DUT2 failed')
        result += 1
    else:
        st.banner('STEP 4 PASS: IPv6 Traceroute from Portchannel10-DUT1 to Portchannel10-DUT2')

    st.banner('Delete the member port and port-channel')
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.port_channel12,dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, data.port_channel12, dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.port_channel12,dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, data.port_channel12, dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])

    if data.sub_intf:
        st.banner('Remove the PortChannel sub interfaces between DUT1 and DUT2 ')
        dict1 = {'intf': data.port_channel12, 'vlan': 40, 'config': 'no'}
        dict2 = {'intf': data.port_channel12, 'vlan': 40, 'config': 'no'}
        st.exec_each2([data.dut1, data.dut2], ip_api.config_sub_interface, [dict1, dict2])

    st.banner('Delete PortChannel10 membership in DUT1 and DUT2')
    utils.exec_all(True, [[pc_api.add_del_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[2],'del'], [pc_api.add_del_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[2],'del']])
    utils.exec_all(True, [[pc_api.add_del_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[3],'del'], [pc_api.add_del_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[3],'del']])
    utils.exec_all(True, [[pc_api.delete_portchannel, data.dut1, 'PortChannel10'], [pc_api.delete_portchannel, data.dut2, 'PortChannel10']])

    st.banner('Rebind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses')
    loc_lib.dut_vrf_bind(pc = '1')
    result = lib_test_VrfFun004()

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('BGP is not converging after unbind/bind on portchannel')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_07_08(request,prologue_epilogue):
    yield
    st.banner('Delete the physical interface from port channel')
    pc_api.add_del_portchannel_member(data.dut1, 'PortChannel10', data.d1_dut_ports[0], flag='del')
    pc_api.add_del_portchannel_member(data.dut2, 'PortChannel10', data.d2_dut_ports[0], flag='del')

    st.banner('Create the sub interface between DUt1 and DUt2 first port')
    if data.sub_intf:
        dict1 = {'intf': data.phy_port121, 'vlan': 112}
        dict2 = {'intf': data.phy_port211, 'vlan': 112}
        st.exec_each2([data.dut1, data.dut2], ip_api.config_sub_interface, [dict1, dict2])

    st.banner('Bind DUT1 <--> DUT2 one physical interface to vrf-101 and config v4 and v6 addresses')
    dict1 = {'vrf_name':vrf_name[0], 'intf_name':data.phy_port121,'skip_error':True}
    dict2 = {'vrf_name':vrf_name[0], 'intf_name':data.phy_port211,'skip_error':True}
    st.exec_each2([data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.phy_port121,dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2,data.phy_port211, dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.phy_port121,dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2,data.phy_port211, dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[0],dut1_loopback_ip[0],dut1_loopback_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[0],dut2_loopback_ip[0],dut2_loopback_ip_subnet,'ipv4']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[0],dut1_loopback_ipv6[0],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[0],dut2_loopback_ipv6[0],dut2_loopback_ipv6_subnet,'ipv6']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ip[0],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ipv6[0],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli007'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli008'])
def test_VrfFun_07_08(vrf_fixture_tc_07_08):

    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun007: Dynamically change port membership from one non-default VRF to another')
    st.log('FtRtVrfFun008: Dynamically modify port channel interfaces in a vrf ')
    st.log('#######################################################################################################################')
    result = 0
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ip[0],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ipv6[0],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.phy_port121,dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2,data.phy_port211, dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.phy_port121,dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2,data.phy_port211, dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[0],dut1_loopback_ip[0],dut1_loopback_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[0],dut2_loopback_ip[0],dut2_loopback_ip_subnet,'ipv4']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[0],dut1_loopback_ipv6[0],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[0],dut2_loopback_ipv6[0],dut2_loopback_ipv6_subnet,'ipv6']])
    st.banner('Unbind DUT2 <--> DUT1 one physical interface from vrf-101')
    vrf_api.bind_vrf_interface(dut = data.dut1, vrf_name = vrf_name[0], intf_name = data.phy_port121, skip_error = True, config = 'no')
    vrf_api.bind_vrf_interface(dut = data.dut2, vrf_name = vrf_name[0], intf_name = data.phy_port211, skip_error = True, config = 'no')

    if data.sub_intf:
        st.banner('Remove the sub interface between DUt1 and DUt2 first port')
        dict1 = {'intf': data.phy_port121, 'vlan': 112, 'config': 'no'}
        dict2 = {'intf': data.phy_port211, 'vlan': 112, 'config': 'no'}
        st.exec_each2([data.dut1, data.dut2], ip_api.config_sub_interface, [dict1, dict2])

    st.banner('Add the physical ports to the port channel')
    pc_api.add_del_portchannel_member(data.dut1, 'PortChannel10', data.d1_dut_ports[0], flag = 'add')
    pc_api.add_del_portchannel_member(data.dut2, 'PortChannel10', data.d2_dut_ports[0], flag = 'add')
    loc_lib.clear_tg()

    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('pc_v6_stream'), duration = '2')
    if not pc_api.verify_portchannel(data.dut1, 'PortChannel10'):
        st.banner('STEP 1 FAIL: Port channel not up after adding memebers from another vrf')
        result += 1
    else:
        st.banner('STEP 1 PASS: Port channel up after adding memebers from another vrf')

    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('pc_v6_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('pc_v6_stream'))

    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.banner('STEP 2 FAIL: IPv6 Traffic on Port channel failed')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv6 Traffic on Port channel passed')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('Changing port membership from one vrf to another vrf failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun034'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun046'])
def test_VrfFun_34_46():

    st.log('#######################################################################################################################')
    st.log('Combining FtRtVrfFun005, FtRtVrfFun034 and FtRtVrfFun046 ')
    st.log('#######################################################################################################################')
    result = 0
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[0], family = 'ipv4')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[0], family = 'ipv6')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[1], family = 'ipv4')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[1], family = 'ipv6')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[2], family = 'ipv4')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[2], family = 'ipv6')
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = 'Vlan'+dut2_dut1_vlan[0], retry_count= 2, delay= 5):
        st.banner('STEP 1 FAIL: IPv4 routes on VRF-102, not learnt on DUT2')
        result += 1
    else:
        st.banner('STEP 1 PASS: IPv4 routes on VRF-102, learnt on DUT2')

    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = 'Vlan'+dut2_dut1_vlan[0],family='ipv6',retry_count= 2, delay= 5):
        st.banner('STEP 2 FAIL: IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv6 routes on VRF-102, learnt on DUT2')

    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = data.port_channel12,retry_count= 2, delay= 5):
        st.banner('STEP 3 FAIL: IPv6 routes on VRF-103, not learnt on DUT2')
        result += 1
    else:
        st.banner('STEP 3 PASS: IPv6 routes on VRF-103, learnt on DUT2')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

def vrf_tc_38_39_48():
    st.banner('IPv6 BGP session did not come up, after delete/add IPv6 IBGP and EBGP config.')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config_type_list =['neighbor'])
    st.banner('Readd EBGP IPv6 neighbor configuration from all the VRFs  ')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config_type_list =['activate','nexthop_self'])
    st.banner('Readd EBGP IPv6 neighbor configuration from all the VRFs  ')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config_type_list =['activate'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], local_as = dut1_as[2], config = 'yes', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=tg1_dut1_vrf_ipv6[2])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], local_as = dut1_as[2], config = 'yes', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut2_dut1_vrf_ipv6[0])

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun038'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun039'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun048'])
def test_VrfFun_38_39_48():

    st.log('#######################################################################################################################')
    st.log('Combined  FtRtVrfFun038, FtRtVrfFun039 and FtRtVrfFun048')
    st.log('FtRtVrfFun038 Verify IBGP neighbor for BGPv6 in vrf for ipv6 ')
    st.log('FtRtVrfFun039 Verify EBGP neighbor for BGPv6 in vrf for ipv6 ')
    st.log('FtRtVrfFun048 Verify BGP4+ route-map functionality in non-default VRF ')
    st.log('#######################################################################################################################')
    result = 0
    st.banner('Remove IBGP IPv6 neighbor configuration from all the VRFs  ')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config = 'no', config_type_list =['neighbor'])
    st.banner('Readd IBGP IPv6 neighbor configuration from all the VRFs  ')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], connect='3', config_type_list =['neighbor','connect'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config_type_list =['activate','nexthop_self'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], local_as = dut1_as[2], config = 'yes', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut2_dut1_vrf_ipv6[0])

    if not loc_lib.retry_api(ip_bgp.check_bgp_session,dut=data.dut1,nbr_list=[dut2_dut1_vrf_ipv6[0]],state_list=['Established'],vrf_name=vrf_name[2],retry_count=15,delay=2):
        st.banner('STEP 0 FAIL: IPv6 BGP session not Up in VRF-102 in DUT2')
    else:
        st.banner('STEP 0 PASS: IPv6 BGP session came Up in VRF-102 in DUT2')

    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = data.port_channel12, retry_count= 15, delay= 2):
        st.banner('STEP 1 FAIL: IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
        basic.get_techsupport(filename='test_VrfFun_38_39_48_ipv6_routes')
    else:
        st.banner('STEP 1 PASS: IPv6 routes on VRF-102, learnt on DUT2')

    st.banner('Remove EBGP IPv6 neighbor configuration from all the VRFs  ')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config = 'no', config_type_list =['neighbor'])
    st.banner('Readd EBGP IPv6 neighbor configuration from all the VRFs  ')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, connect='3', config_type_list =['neighbor','connect'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config_type_list =['activate'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], local_as = dut1_as[2], config = 'yes', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=tg1_dut1_vrf_ipv6[2])

    if not loc_lib.retry_api(ip_bgp.check_bgp_session,dut=data.dut1,nbr_list=[tg1_dut1_vrf_ipv6[2]],state_list=['Established'],vrf_name=vrf_name[2],retry_count=15,delay=2):
        st.banner('STEP 2 FAIL: IPv6 BGP session not Up in VRF-102 in DUT2')
    else:
        st.banner('STEP 2 PASS: IPv6 BGP session came Up in VRF-102 in DUT2')

    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = data.port_channel12, retry_count= 10, delay= 3):
        st.banner('STEP 3 FAIL: IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
    else:
        st.banner('STEP 3 PASS: IPv6 routes on VRF-102, learnt on DUT2')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        vrf_tc_38_39_48()
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_31_43(request,prologue_epilogue):
    yield
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'no', config_type_list =['redist'], redistribute ='connected')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2],local_as = dut1_as[2], addr_family ='ipv6', neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config = 'no', config_type_list =['redist'], redistribute ='connected')

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun031'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun043'])
def test_VrfFun_31_43(vrf_fixture_tc_31_43):
    st.log('#######################################################################################################################')
    st.log('Combined FtRtVrfFun031 and FtRtVrfFun043 ')
    st.log('FtRtVrfFun031 Redistribute connected IPv4 routes into IBGP in non-default vrf ')
    st.log('FtRtVrfFun043 Redistribute connected IPv6 routes into IBGP in non-default vrf ')
    st.log('#######################################################################################################################')

    result = 0
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['redist'], redistribute ='connected')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2],local_as = dut1_as[2], addr_family ='ipv6', neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config = 'yes', config_type_list =['redist'], redistribute ='connected')
    st.wait(5,"Waiting for 5 sec")
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('pc_v6_stream'), duration = '2')
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('pc_v6_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('pc_v6_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.banner('STEP 1 FAIL: IPv6 Traffic on VRF-103 failed')
        st.log('DEBUG STEP: Ping test from DUT 1 to DUT 2 upon test case failure')
        ip_api.ping(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6',interface= vrf_name[2], count = 2)
        st.log('DEBUG STEP: Ping test from DUT 2 to DUT 1 upon test case failure')
        ip_api.ping(data.dut2, dut1_dut2_vrf_ipv6[0], family='ipv6',interface= vrf_name[2], count = 2)
        result += 1
    else:
        st.banner('STEP 1 PASS: IPv6 Traffic on VRF-103')

    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('phy_v4_stream'), duration = '2')
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('phy_v4_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('phy_v4_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.banner('STEP 2 FAIL: IPv4 Traffic on VRF-101 failed')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv4 Traffic on VRF-101')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('Redistribute connected IPv4 and IPv6 routes into IBGP in VRF-103 failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

def vrf_tc_26_27():
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as,  config = 'yes',config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as,  config = 'yes',config_type_list =['activate'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['activate','nexthop_self'])

#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun026'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun027'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun037'])
def test_VrfFun_26_27():
    st.log('#######################################################################################################################')
    st.log('Combined FtRtVrfFun026 and FtRtVrfFun027 ')
    st.log(' FtRtVrfFun026: Verify IBGP neighbor for BGPv4 in vrf ')
    st.log('FtRtVrfFun027 Verify EBGP neighbor for BGPv4 in vrf for ipv4 ')
    st.log('#######################################################################################################################')

    result = 0
    st.banner('Remove EBGP IPv4 neighbor configuration from all the VRFs  ')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0], local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'no', config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['activate','nexthop_self'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0], local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as, config = 'no', config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as,  config = 'yes',config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as,  config = 'yes',config_type_list =['activate'])
    st.wait(5,"Waiting for 5 sec")
    if not ip_api.verify_ip_route(data.dut1, vrf_name = vrf_name[0], type='B', nexthop = tg1_dut1_vrf_ip[0], interface = 'Vlan'+dut1_tg1_vlan[0]):
        st.banner('STEP 1 FAIL: IPv4 routes on VRF-101, not learnt on DUT1')
        result += 1
    else:
        st.banner('STEP 1 PASS: IPv4 routes on VRF-101, learnt on DUT1')
    if not ip_api.verify_ip_route(data.dut2, vrf_name = vrf_name[0], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = data.phy_port211):
        st.banner('STEP 2 FAIL: IPv4 routes on VRF-101, not learnt on DUT2')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv4 routes on VRF-101, learnt on DUT2')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('IPv4 BGP session did not come up, after delete/add IPv4 IBGP and EBGP config')
        vrf_tc_26_27()
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_28_36_43_47(request,prologue_epilogue):
    yield
    #for nbr_1,nbr_2 in zip(dut2_dut1_vrf_ip[0:2],dut1_dut2_vrf_ip[0:2]):
    # dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'peergroup':'peergroup_v4','config_type_list':['peergroup']}
    # dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'peergroup':'peergroup_v4','config_type_list':['peergroup']}
    # st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    # for nbr_1,nbr_2 in zip(dut2_dut1_vrf_ipv6[0:2],dut1_dut2_vrf_ipv6[0:2]):
    # dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'peergroup':'peergroup_v6','config_type_list':['peergroup'],'addr_family':'ipv6'}
    # dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'peergroup':'peergroup_v6','config_type_list':['peergroup'],'addr_family':'ipv6'}
    # st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    bgp_api.activate_bgp_neighbor(data.dut1, dut1_as[1], dut2_dut1_vrf_ip[1], family="ipv4", config='no',vrf=vrf_name[1], remote_asn=dut2_as[1])
    bgp_api.activate_bgp_neighbor(data.dut1, dut1_as[1], dut2_dut1_vrf_ipv6[1], family="ipv6", config='no',vrf=vrf_name[1], remote_asn=dut2_as[1])
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    bgp_api.activate_bgp_neighbor(data.dut2, dut2_as[1], dut1_dut2_vrf_ip[1], family="ipv4", config='no',vrf=vrf_name[1], remote_asn=dut1_as[1])
    bgp_api.activate_bgp_neighbor(data.dut2, dut2_as[1], dut1_dut2_vrf_ipv6[1], family="ipv6", config='no',vrf=vrf_name[1], remote_asn=dut1_as[1])
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun028'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun036'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun040'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun047'])
def test_VrfFun_28_36_43_47(vrf_fixture_tc_28_36_43_47):
    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun026 Verify the EBGP peer connection and route advertisement under IPV4 address-family in non-default vrf ')
    st.log('FtRtVrfFun036 Verify BGP peer-group for IPv4 address family on non-default VRF ')
    st.log('FtRtVrfFun043 Verify the EBGP peer connection and route advertisement under IPV6 address-family in non-default vrf ')
    st.log('FtRtVrfFun047 Verify BGP peer-group for IPv6 address family with EBGP neighbors non-default VRF')
    st.log('#######################################################################################################################')
    result = 0
    st.banner('Configuring Vlan102 as another neighbor in VRF-102')
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['activate','nexthop_self']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['activate','nexthop_self']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.banner('Configuring Vlan102 as another neighbor in VRF-102')
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['activate','nexthop_self']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['activate','nexthop_self']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.banner('Configuring IPv4 peer group for Vlan101 and Vlan 102')
    for nbr_1,nbr_2 in zip(dut2_dut1_vrf_ip[0:2],dut1_dut2_vrf_ip[0:2]):
        dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'peergroup':'peergroup_v4','config_type_list':['peergroup'],'remote_as':dut2_as[1],'neighbor':nbr_1}
        dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'peergroup':'peergroup_v4','config_type_list':['peergroup'],'remote_as':dut1_as[1],'neighbor':nbr_2}
        st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.banner('Configuring IPv6 peer group for Vlan101 and Vlan 102')
    for nbr_1,nbr_2 in zip(dut2_dut1_vrf_ipv6[0:2],dut1_dut2_vrf_ipv6[0:2]):
        dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'peergroup':'peergroup_v6','config_type_list':['peergroup'],'remote_as':dut2_as[1],'neighbor':nbr_1,'addr_family':'ipv6'}
        dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'peergroup':'peergroup_v6','config_type_list':['peergroup'],'remote_as':dut1_as[1],'neighbor':nbr_2,'addr_family':'ipv6'}
        st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.wait(30,'added delay for the bgp retry timer')
    if not ip_bgp.verify_bgp_neighbor(data.dut1, neighborip = dut2_dut1_vrf_ip[1], state='Established', vrf = vrf_name[1]):
        st.banner('STEP 1 FAIL: IPv6 IBGP neighbor did not come up on VRF-102 after peer-group configuration')
        result += 1
    else:
        st.banner('STEP 1 PASS: IPv6 IBGP neighbor came up on VRF-102 after peer-group configuration')

    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('ve_v4_stream'), duration = '2')
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('ve_v4_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('ve_v4_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.banner('STEP 2 FAIL: IPv4 Traffic on VRF-102 failed after peer-group configuration')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv4 Traffic on VRF-102 passed after peer-group configuration')

    if not ip_bgp.verify_bgp_neighbor(data.dut1, neighborip = dut2_dut1_vrf_ipv6[1], state='Established', vrf = vrf_name[1]):
        st.banner('STEP 3 FAIL: IPv6 IBGP neighbor did not come up on VRF-102 after peer-group configuration')
        result += 1
    else:
        st.banner('STEP 3 PASS: IPv6 IBGP neighbor came up on VRF-102 after peer-group configuration')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('Peer group verification for IPv4 and IPv6 in VRF-102 failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_35_49(request,prologue_epilogue):
    yield
    st.banner('UnConfigure max path iBGP for IPv4 is 2 in DUT1 and 8 in DUT2')
    dict1 = {'vrf_name':vrf_name[1],'local_as': dut1_as[1], 'max_path_ibgp': '', 'config_type_list': ["max_path_ibgp"], 'config' : 'no'}
    dict2 = {'vrf_name':vrf_name[1],'local_as': dut2_as[1], 'max_path_ibgp': '', 'config_type_list': ["max_path_ibgp"], 'config' : 'no'}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    st.banner('UnConfigure max path iBGP for IPv6 is 2 in DUT1 and 8 in DUT2')
    dict1 = {'vrf_name':vrf_name[1],'local_as': dut1_as[1], 'max_path_ibgp': '', 'config_type_list': ["max_path_ibgp"],'addr_family' : 'ipv6', 'config' : 'no'}
    dict2 = {'vrf_name':vrf_name[1],'local_as': dut2_as[1], 'max_path_ibgp': '', 'config_type_list': ["max_path_ibgp"],'addr_family' : 'ipv6', 'config' : 'no'}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    bgp_api.config_bgp(dut = data.dut2, vrf_name = vrf_name[1], local_as = dut1_as[1], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[0])
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'addr_family':'ipv6','remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'addr_family':'ipv6','remote_as':dut1_as[1],'config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])


#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun035'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun049'])
def test_VrfFun_35_49(vrf_fixture_tc_35_49):
    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun035 IPv4 ECMP in non-default vrf along with route leak into another vrf ')
    st.log('FtRtVrfFun049 IPv6 ECMP in non-default vrf along with route leak into another vrf ')
    st.log('#######################################################################################################################')
    result = 0
    st.banner('Configure max path iBGP for IPv4 is 2 in DUT1 and 8 in DUT2')
    dict1 = {'vrf_name':vrf_name[1],'local_as': dut1_as[1], 'max_path_ibgp': 2, 'config_type_list': ["max_path_ibgp"]}
    dict2 = {'vrf_name':vrf_name[1],'local_as': dut2_as[1], 'max_path_ibgp': 8, 'config_type_list': ["max_path_ibgp"]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    st.banner('Configuring Vlan102 as another neighbor in VRF-102')
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['activate','nexthop_self']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['activate','nexthop_self']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = 'Vlan'+dut2_dut1_vlan[0]):
        st.banner('STEP 1 FAIL: IPv4 routes on VRF-102, not learnt on DUT2')
        result += 1
        basic.get_techsupport(filename='test_VrfFun_35_49_ipv4_routes')
    else:
        st.banner('STEP 1 PASS: IPv4 routes on VRF-102, learnt on DUT2')

    st.banner('Configure max path iBGP for IPv6 is 2 in DUT1 and 8 in DUT2')
    dict1 = {'vrf_name':vrf_name[1],'local_as': dut1_as[1], 'max_path_ibgp': 2, 'config_type_list': ["max_path_ibgp"],'addr_family' : 'ipv6'}
    dict2 = {'vrf_name':vrf_name[1],'local_as': dut2_as[1], 'max_path_ibgp': 8, 'config_type_list': ["max_path_ibgp"],'addr_family' : 'ipv6'}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    st.banner('for BGPv4+ Configuring Vlan102 as another neighbor in VRF-102')
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['activate','nexthop_self']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['activate','nexthop_self']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    bgp_api.config_bgp(dut = data.dut2, vrf_name = vrf_name[1], local_as = dut1_as[1], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[1])
    bgp_api.config_bgp(dut = data.dut2, vrf_name = vrf_name[1], local_as = dut1_as[1], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[0])
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ipv6[1], interface = 'Vlan'+dut2_dut1_vlan[1],family='ipv6'):
        st.banner('STEP 2 FAIL: IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv6 routes on VRF-102, learnt on DUT2')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('Multipath IBGP verification for IPv4 and IPv6 in VRF-102 failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_10_12_14(request,prologue_epilogue):
    yield
    st.banner('Delete the static routes configured in VRF 1')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[0], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[0], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[0],'no']])
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[0], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[0], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[0],'no']])

    st.banner('Delete the static routes configured in VRF 2')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[1], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[1], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[1], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[1],'no']])
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[1], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[1], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[1], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[1],'no']])

    st.banner('Delete the static routes configured in VRF 3')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[2], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[2], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[2], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[2],'no']])
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[2], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[2], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[2], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[2],'no']])


    loc_lib.dut_vrf_bgp(phy = '1')
    loc_lib.dut_vrf_bgp(ve = '1')
    loc_lib.dut_vrf_bgp(pc = '1')
    loc_lib.tg_vrf_bgp(phy = '1')
    loc_lib.tg_vrf_bgp(ve = '1')
    loc_lib.tg_vrf_bgp(pc = '1')

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun010'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun012'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun014'])
def test_VrfFun_10_12_14(vrf_fixture_tc_10_12_14):

    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun0010: Add/delete static route under vrf with next hop as physical interface')
    st.log('FtRtVrfFun0012: Add/delete static route under vrf with next hop as virtual interface ')
    st.log('FtRtVrfFun0014: Add/delete static route under vrf with next hop as port channel ')
    st.log('#######################################################################################################################')

    result = 0
    loc_lib.dut_vrf_bgp(phy = '1', config = 'no')
    loc_lib.dut_vrf_bgp(ve = '1', config = 'no')
    loc_lib.dut_vrf_bgp(pc = '1', config = 'no')
    st.banner('Configure IPv4 static routes on VRF-101')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[0], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[0], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[0],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ip[0], interface= vrf_name[0], count = 2):
        st.banner('STEP 1 FAIL: IPv4 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 failed after static route configuration')
        result += 1
    else:
        st.banner('STEP 1 PASS: IPv4 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 passed after static route configuration')
    st.banner('Configure IPv6 static routes on VRF-101')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[0], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[0], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[0],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ipv6[0], interface= vrf_name[0], count = 2, family='ipv6'):
        st.banner('STEP 2 FAIL: IPv6 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 failed after static route configuration')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv6 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 passed after static route configuration')
    st.banner('Configure IPv4 static routes on VRF-102')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[1], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[1], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[1], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[1],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ip[1], interface= vrf_name[1], count = 2):
        st.banner('STEP 3 FAIL: IPv4 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration')
        result += 1
    else:
        st.banner('STEP 3 PASS: IPv4 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 passed after static route configuration')
    st.banner('Configure IPv6 static routes on VRF-102')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[1], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[1], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[1], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[1],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ipv6[1], family='ipv6', interface= vrf_name[1], count = 2):
        st.banner('STEP 4 FAIL: IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration')
        result += 1
    else:
        st.banner('STEP 4 PASS: IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 passed after static route configuration')
    st.banner('Configure IPv4 static routes on VRF-103')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[2], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[2], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[2], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[2],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ip[2], interface= vrf_name[2], count = 2):
        st.banner('STEP 5 FAIL: IPv4 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed after static route configuration')
        result += 1
    else:
        st.banner('STEP 5 PASS: IPv4 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 passed after static route configuration')
    st.banner('Configure IPv6 static routes on VRF-103')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[2], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[2], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[2], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[2],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ipv6[2], family='ipv6', interface= vrf_name[2], count = 2):
        st.banner('STEP 6 FAIL: IPv6 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed after static route configuration')
        result += 1
    else:
        st.banner('STEP 6 PASS: IPv6 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 passed after static route configuration')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('Static route between VRFs failed for VRf-101, VRF-102 and VRF-103')
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_29_30_41_42_54_55(request,prologue_epilogue):
    yield
    st.banner('Delete Loopback as BGP neighbor')
    dict1 = {'vrf_name':vrf_name[1],'local_as':'104','config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':'105','config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    utils.exec_all(True,[[ip_api.config_static_route_vrf, data.dut1, dut2_loopback_ip[1], dut2_loopback_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[1], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_loopback_ip[1], dut1_loopback_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[1],'no']])
    dict1 = {'vrf_name':vrf_name[2],'local_as':'106','config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    dict2 = {'vrf_name':vrf_name[2],'local_as':'107','config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_loopback_ipv6[2], dut2_loopback_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[2], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_loopback_ipv6[2], dut1_loopback_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[2],'no']])
    loc_lib.dut_vrf_bgp(ve = '1')
    loc_lib.dut_vrf_bgp(pc = '1')
    loc_lib.tg_vrf_bgp(ve = '1')
    loc_lib.tg_vrf_bgp(pc = '1')

#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun029'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun030'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun041'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun042'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun054'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun055'])
def test_VrfFun_29_30_41_42_54_55(vrf_fixture_tc_29_30_41_42_54_55):

    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun029: Verify multihop EBGP under IPv4 address-family in non-default vrfe')
    st.log('FtRtVrfFun030: Add/delete non-default vrf with both single hop and multihop EBGP sessions e')
    st.log('FtRtVrfFun041: Verify multihop EBGP under IPv6 address-family in non-default vrfe')
    st.log('FtRtVrfFun042: Add/delete non-default vrf with both single hop and multihop EBGP sessions for IPv6 address family')
    st.log('FtRtVrfFun054: IPv4 forwarding with default route in default vrf and also in non-default vrf')
    st.log('FtRtVrfFun055: IPv6 forwarding with default route in default vrf and also in non-default vrf')
    st.log('#######################################################################################################################')

    result = 0
    loc_lib.dut_vrf_bgp(ve = '1', config = 'no')
    st.banner('Configure EBGP between DUTs')
    st.banner('Add Loopback as BGP neighbor')
    dict1 = {'vrf_name':vrf_name[1],'local_as':'104','neighbor':dut2_loopback_ip[1],'remote_as':'105','config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':'105','neighbor':dut1_loopback_ip[1],'remote_as':'104','config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':'104','neighbor':dut2_loopback_ip[1],'remote_as':'105','config_type_list':['activate','update_src','ebgp_mhop'],'update_src':dut1_loopback_ip[1],'ebgp_mhop':'1'}
    dict2 = {'vrf_name':vrf_name[1],'local_as':'105','neighbor':dut1_loopback_ip[1],'remote_as':'104','config_type_list':['activate','update_src','ebgp_mhop'],'update_src':dut2_loopback_ip[1],'ebgp_mhop':'1'}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.banner('Configure static routes on VRF-102')
    utils.exec_all(True,[[ip_api.config_static_route_vrf, data.dut1, dut2_loopback_ip[1], dut2_loopback_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[1], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_loopback_ip[1], dut1_loopback_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[1],'']])
    if not ip_api.ping(data.dut1, dut2_loopback_ip[1], interface= vrf_name[1], count = 2):
        st.banner('STEP 1 FAIL: IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration to loopback interface')
        result += 1
    else:
        st.banner('STEP 1 PASS: IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 passed after static route configuration to loopback interface')
    if not ip_bgp.verify_bgp_neighbor(data.dut1, neighborip = dut2_loopback_ip[1], state='Established', vrf = vrf_name[1]):
        st.banner('STEP 2 FAIL: IPv4 routes on VRF-102 over the loopback, not learnt on DUT2')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv4 routes on VRF-102 over the loopback, learnt on DUT2')
    dict1 = {'vrf_name':vrf_name[1],'local_as':'104','config_type_list':['redist'],'redistribute':'connected'}
    dict2 = {'vrf_name':vrf_name[1],'local_as':'105','config_type_list':['redist'],'redistribute':'connected'}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    loc_lib.dut_vrf_bgp(pc = '1', config = 'no')
    st.banner('Add Loopback as BGP neighbor for vrf-103')
    dict1 = {'vrf_name':vrf_name[2],'local_as':'106','neighbor':dut2_loopback_ipv6[2],'remote_as':'107','addr_family':'ipv6','config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[2],'local_as':'107','neighbor':dut1_loopback_ipv6[2],'remote_as':'106','addr_family':'ipv6','config_type_list':['neighbor']}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[2],'local_as':'106','neighbor':dut2_loopback_ipv6[2],'remote_as':'107','addr_family':'ipv6','config_type_list':['activate','update_src','ebgp_mhop'],'update_src':dut1_loopback_ipv6[2],'ebgp_mhop':'1'}
    dict2 = {'vrf_name':vrf_name[2],'local_as':'107','neighbor':dut1_loopback_ipv6[2],'remote_as':'106','addr_family':'ipv6','config_type_list':['activate','update_src','ebgp_mhop'],'update_src':dut2_loopback_ipv6[2],'ebgp_mhop':'1'}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.banner('Configure static routes for vrf-103')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_loopback_ipv6[2], dut2_loopback_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[2], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_loopback_ipv6[2], dut1_loopback_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[2],'']])
    if not ip_api.ping(data.dut1, dut2_loopback_ipv6[2], interface= vrf_name[2], family='ipv6', count = 2):
        st.banner('STEP 3 FAIL: IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration to loopback interface')
        result += 1
    else:
        st.banner('STEP 3 PASS: IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 passed after static route configuration to loopback interface')
    if not ip_bgp.verify_bgp_neighbor(data.dut1, neighborip = dut2_loopback_ipv6[2], state='Established', vrf = vrf_name[2]):
        st.banner('STEP 4 FAIL: IPv4 routes on VRF-102 over the loopback, not learnt on DUT2')
        result += 1
    else:
        st.banner('STEP 4 PASS: IPv4 routes on VRF-102 over the loopback, learnt on DUT2')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('Static route between VRFs failed for VRf-101, VRF-102 and VRF-103')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_20_24_25_32_33_44_45(request,prologue_epilogue):
    yield
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut2_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut1_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'config':'no','vrf_name':vrf_name[2],'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'config':'no','vrf_name':vrf_name[2],'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'config':'no','vrf_name':vrf_name[2],'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut2_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'config':'no','vrf_name':vrf_name[2],'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut1_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    #dict1 = {'vrf_name':'default','local_as':dut1_as[1],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    #dict2 = {'vrf_name':'default','local_as':dut2_as[1],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    #st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    #port_api.noshutdown(data.dut1, ['Vlan2','Vlan3'])

#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun020'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun024'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun025'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun032'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun033'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun044'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun045'])
def test_VrfFun_20_24_25_32_33_44_45(vrf_fixture_tc_20_24_25_32_33_44_45):

    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun020: IPv4 static route leak from non-default vrf to another non-default vrf')
    st.log('FtRtVrfFun024: IPv6 static route leak from non-default vrf to another non-default vrf')
    st.log('FtRtVrfFun025: Import same route from VRF A to VRF B, C and D ')
    st.log('#######################################################################################################################')

    result = 0
    #port_api.shutdown(data.dut1, ['Vlan2','Vlan3'])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut2_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut1_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    ip_api.show_ip_route(data.dut2, family="ipv4", shell="sonic", vrf_name=vrf_name[1])
    ip_api.show_ip_route(data.dut2, family="ipv6", shell="sonic", vrf_name=vrf_name[1])
    dict1 = {'vrf_name':vrf_name[2],'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'vrf_name':vrf_name[2],'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[2],'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut2_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'vrf_name':vrf_name[2],'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut1_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    ip_api.show_ip_route(data.dut2, family="ipv4", shell="sonic", vrf_name=vrf_name[2])
    ip_api.show_ip_route(data.dut2, family="ipv6", shell="sonic", vrf_name=vrf_name[2])
    if not loc_lib.verify_bgp(ve = '1',ip = 'ipv4'):
        st.banner('STEP 1 FAIL: IPv4 BGP session on VRF-102 did not come up')
        result += 1
    else:
        st.banner('STEP 1 PASS: IPv4 BGP session on VRF-102 came up')
    if not loc_lib.verify_bgp(ve = '1',ip = 'ipv6'):
        st.banner('STEP 2 FAIL: IPv6 BGP session on VRF-102 did not come up')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv6 BGP session on VRF-102 came up')
    if not loc_lib.verify_bgp(pc = '1',ip = 'ipv4'):
        st.banner('STEP 3 FAIL: IPv4 BGP session on VRF-103 did not come up')
        result += 1
    else:
        st.banner('STEP 3 PASS: IPv4 BGP session on VRF-103 came up')
    if not loc_lib.verify_bgp(pc = '1',ip = 'ipv6'):
        st.banner('STEP 4 FAIL: IPv6 BGP session on VRF-103 did not come up')
        result += 1
    else:
        st.banner('STEP 4 PASS: IPv6 BGP session on VRF-103 came up')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('Static route between VRFs failed for VRf-101, VRF-102 and VRF-103')
        #debug_bgp_vrf()
        st.report_fail('test_case_failed')

#@pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli005'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun050'])
def test_VrfFun_05_50():

    st.log('######################################################################################################################')
    st.log('FtRtVrfFun005 Configure overlapping IP addresses belonging to different VRFs ')
    st.log('FtRtVrfFun050 Verify non-default vrf after cold reboot ')
    st.log('#######################################################################################################################')

    result = 0
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve = '1',ip = 'ipv4'):
        st.banner('STEP 1 FAIL: IPv4 BGP session on VRF-102 did not come up')
        result += 1
    else:
        st.banner('STEP 1 PASS: IPv4 BGP session on VRF-102 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve = '1',ip = 'ipv6'):
        st.banner('STEP 2 FAIL: IPv6 BGP session on VRF-102 did not come up')
        result += 1
    else:
        st.banner('STEP 2 PASS: IPv6 BGP session on VRF-102 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc = '1',ip = 'ipv4'):
        st.banner('STEP 3 FAIL: IPv4 BGP session on VRF-103 did not come up')
        result += 1
    else:
        st.banner('STEP 3 PASS: IPv4 BGP session on VRF-103 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc = '1',ip = 'ipv6'):
        st.banner('STEP 4 FAIL: IPv6 BGP session on VRF-103 did not come up')
        result += 1
    else:
        st.banner('STEP 4 PASS: IPv6 BGP session on VRF-103 came up')
    reboot_api.config_save(data.dut1)
    reboot_api.config_save(data.dut1,shell='vtysh')
    st.reboot(data.dut1, 'fast')
    st.wait(40,"Waiting for the sessions to come up")
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve = '1',ip = 'ipv4'):
        st.banner('STEP 5 FAIL: IPv4 BGP session on VRF-102 did not come up')
        result += 1
    else:
        st.banner('STEP 5 PASS: IPv4 BGP session on VRF-102 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve = '1',ip = 'ipv6'):
        st.banner('STEP 6 FAIL: IPv6 BGP session on VRF-102 did not come up')
        result += 1
    else:
        st.banner('STEP 6 PASS: IPv6 BGP session on VRF-102 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc = '1',ip = 'ipv4'):
        st.banner('STEP 7 FAIL: IPv4 BGP session on VRF-103 did not come up')
        result += 1
    else:
        st.banner('STEP 7 PASS: IPv4 BGP session on VRF-103 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc = '1',ip = 'ipv6'):
        st.banner('STEP 8 FAIL: IPv6 BGP session on VRF-103 did not come up')
        result += 1
    else:
        st.banner('STEP 8 PASS: IPv6 BGP session on VRF-103 came up')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('Save and reload with VRF configuration failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')


@pytest.fixture(scope="function")
def vrf_leak_fixture():
    st.banner('Delete IPv4 address between DUT1 and DUT2 for first link')
    st.exec_all([[ip_api.delete_ip_interface, data.dut1, data.phy_port121,
                  dut1_dut2_vrf_ip[0], dut1_dut2_vrf_ip_subnet, 'ipv4'],
                 [ip_api.delete_ip_interface, data.dut2, data.phy_port211,
                  dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    st.banner('Delete IPv6 address between DUT1 and DUT2 for first link')
    st.exec_all([[ip_api.delete_ip_interface, data.dut1, data.phy_port121,
                  dut1_dut2_vrf_ipv6[0], dut1_dut2_vrf_ipv6_subnet, 'ipv6'],
                 [ip_api.delete_ip_interface, data.dut2, data.phy_port211,
                  dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    st.banner('Unbind DUT1 <--> DUT2 first link from VRF : {}'.format(vrf_name[0]))
    dict1 = {'vrf_name': vrf_name[0], 'intf_name': data.phy_port121, 'config': 'no'}
    dict2 = {'vrf_name': vrf_name[0], 'intf_name': data.phy_port211, 'config': 'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
    st.banner('Configure IPv6 address between DUT1 and DUT2 for first link')
    st.exec_all([[ip_api.config_ip_addr_interface, data.dut1, data.phy_port121,
                  dut1_dut2_vrf_ipv6[0], dut1_dut2_vrf_ipv6_subnet, 'ipv6'],
                 [ip_api.config_ip_addr_interface, data.dut2, data.phy_port211,
                  dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    st.banner('Delete the port-channel membership in DUT1 and DUT2')
    st.exec_all([[pc_api.add_del_portchannel_member, data.dut1, data.port_channel12,
                  data.phy_port123, 'del'],
                 [pc_api.add_del_portchannel_member, data.dut2, data.port_channel12,
                  data.phy_port213, 'del']])
    st.exec_all([[pc_api.add_del_portchannel_member, data.dut1, data.port_channel12,
                  data.phy_port124, 'del'],
                 [pc_api.add_del_portchannel_member, data.dut2, data.port_channel12,
                  data.phy_port214, 'del']])
    st.banner('Bind DUT1 <--> DUT2 3rd and 4th interfaces to vrf binding')
    dict1 = {'vrf_name': vrf_name[1], 'intf_name': data.phy_port123}
    dict2 = {'vrf_name': vrf_name[1], 'intf_name': data.phy_port213}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
    dict1 = {'vrf_name': vrf_name[2], 'intf_name': data.phy_port124}
    dict2 = {'vrf_name': vrf_name[2], 'intf_name': data.phy_port214}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
    st.banner('Configure IPv6 addresses in DUT1 <--> DUT2 VRF bound 3rd and 4th interfaces')
    st.exec_all([[ip_api.config_ip_addr_interface, data.dut1, data.phy_port123,
                  dut1_dut2_vrf_ipv6[98], dut1_dut2_vrf_ipv6_subnet, 'ipv6'],
                 [ip_api.config_ip_addr_interface, data.dut2, data.phy_port213,
                  dut2_dut1_vrf_ipv6[98], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    st.exec_all([[ip_api.config_ip_addr_interface, data.dut1, data.phy_port124,
                  dut1_dut2_vrf_ipv6[99], dut1_dut2_vrf_ipv6_subnet, 'ipv6'],
                 [ip_api.config_ip_addr_interface, data.dut2, data.phy_port214,
                  dut2_dut1_vrf_ipv6[99], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    ip_api.create_static_route(data.dut2, next_hop=dut1_dut2_vrf_ipv6[0],
                               static_ip=dut2_loopback_ipv6[0] + "/" + dut1_loopback_ipv6_subnet,
                               family='ipv6')
    ip_api.create_static_route(data.dut1, interface=data.phy_port123,
                               static_ip=dut2_loopback_ipv6[0] + "/" + dut1_loopback_ipv6_subnet,
                               family='ipv6', nexthop_vrf=vrf_name[1])
    ip_api.create_static_route(data.dut1, interface=data.phy_port124,
                               static_ip=dut2_loopback_ipv6[0] + "/" + dut1_loopback_ipv6_subnet,
                               family='ipv6', vrf=vrf_name[1], nexthop_vrf=vrf_name[2])
    yield
    st.banner("Delete the static routes from DUT1 and DUT2")
    ip_api.delete_static_route(data.dut2, next_hop=dut1_dut2_vrf_ipv6[0],
                               static_ip=dut2_loopback_ipv6[0] + "/" + dut1_loopback_ipv6_subnet,
                               family='ipv6')
    ip_api.delete_static_route(data.dut1, interface=data.phy_port123,
                               static_ip=dut2_loopback_ipv6[0] + "/" + dut1_loopback_ipv6_subnet,
                               family='ipv6', nexthop_vrf=vrf_name[1])
    ip_api.delete_static_route(data.dut1, interface=data.phy_port124,
                               static_ip=dut2_loopback_ipv6[0] + "/" + dut1_loopback_ipv6_subnet,
                               family='ipv6', vrf=vrf_name[1], nexthop_vrf=vrf_name[2])
    st.banner('Delete IPv6 addresses in DUT1 <--> DUT2 VRF bound 3rd and 4th interfaces')
    st.exec_all([[ip_api.delete_ip_interface, data.dut1, data.phy_port123,
                  dut1_dut2_vrf_ipv6[98], dut1_dut2_vrf_ipv6_subnet, 'ipv6'],
                 [ip_api.delete_ip_interface, data.dut2, data.phy_port213,
                  dut2_dut1_vrf_ipv6[98], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    st.exec_all([[ip_api.delete_ip_interface, data.dut1, data.phy_port124,
                  dut1_dut2_vrf_ipv6[99], dut1_dut2_vrf_ipv6_subnet, 'ipv6'],
                 [ip_api.delete_ip_interface, data.dut2, data.phy_port214,
                  dut2_dut1_vrf_ipv6[99], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    st.banner('UnBind DUT1 <--> DUT2 3rd and 4th interfaces from vrf binding')
    dict1 = {'vrf_name': vrf_name[1], 'intf_name': data.phy_port123, 'config': 'no'}
    dict2 = {'vrf_name': vrf_name[1], 'intf_name': data.phy_port213, 'config': 'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
    dict1 = {'vrf_name': vrf_name[2], 'intf_name': data.phy_port124, 'config': 'no'}
    dict2 = {'vrf_name': vrf_name[2], 'intf_name': data.phy_port214, 'config': 'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
    st.banner("Add back 3rd and 4th links between DUT1 and DUT2 part of PO")
    pc_api.config_portchannel(data.dut1, data.dut2, 'PortChannel10' ,
                              [data.phy_port123, data.phy_port124],
                              [data.phy_port213, data.phy_port214], config='add', thread=True)
    st.banner('Delete IPv6 address between DUT1 and DUT2 for first link')
    st.exec_all([[ip_api.delete_ip_interface, data.dut1, data.phy_port121,
                  dut1_dut2_vrf_ipv6[0], dut1_dut2_vrf_ipv6_subnet, 'ipv6'],
                 [ip_api.delete_ip_interface, data.dut2, data.phy_port211,
                  dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    st.banner('Bind DUT1 <--> DUT2 firs link part of VRF: {}'.format(vrf_name[0]))
    dict1 = {'vrf_name': vrf_name[0], 'intf_name': data.phy_port121}
    dict2 = {'vrf_name': vrf_name[0], 'intf_name': data.phy_port211}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
    st.banner('Configure IPv4 and IPv6 address between DUT1 and DUT2 for first link')
    st.exec_all([[ip_api.config_ip_addr_interface, data.dut1, data.phy_port121,
                  dut1_dut2_vrf_ip[0], dut1_dut2_vrf_ip_subnet, 'ipv4'],
                 [ip_api.config_ip_addr_interface, data.dut2, data.phy_port211,
                  dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    st.exec_all([[ip_api.config_ip_addr_interface, data.dut1, data.phy_port121,
                  dut1_dut2_vrf_ipv6[0], dut1_dut2_vrf_ipv6_subnet, 'ipv6'],
                 [ip_api.config_ip_addr_interface, data.dut2, data.phy_port211,
                  dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])


@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['KERNAL_CRASH_CETA70471'])
def test_ceta_70471(vrf_leak_fixture):
    test_result=True
    test_case_id = "KERNAL_CRASH_CETA70471"
    fail_msg = "\n"
    st.log('######################################################################################################################')
    st.log('FtOpSoRoVrfCeta70471 Verify 3 level route leak not resulting any crash ')
    st.log('#######################################################################################################################')
    st.banner("Ping to 3 level VRf leaked route and verify kernal crash is not seen")
    ip_api.ping(data.dut2, dut2_loopback_ipv6[0], count=10, family="ipv6")
    st.wait(20, "wait before checking kernal crash")
    if basic.check_kdump_files(data.dut1, skip_template=True):
        test_result=False
        st.error("########## FAIL: kernal crash is seen in DUT1 ##########")
        fail_msg += "Kernal crash observed in DUT1"
    else:
        st.log("########## PASS: No kernal crash in DUT1 as expected ##########")
    if test_result:
        st.banner("TC Pass: {}".format(test_case_id))
        st.report_pass("test_case_id_passed", test_case_id)
    else:
        st.banner("TC Fail:  {}, {}".format(test_case_id, fail_msg))
        st.report_fail("test_case_id_failed", test_case_id)
