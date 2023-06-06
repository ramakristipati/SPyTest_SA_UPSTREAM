# BGP 4 node topology test cases
import pytest

from spytest import st,SpyTestDict

from apis.system import port as port_api
from apis.routing.route_map import RouteMap
from apis.routing import ip_bgp
import apis.routing.bgp as bgpapi
import apis.routing.ip as ipapi
import BGP.bgp4nodelib as bgp4nodelib

from utilities.common import ExecAllFunc
from utilities.utils import retry_api

bgp_4node_data = SpyTestDict()
bgp_4node_data.dut1_as = 65001
bgp_4node_data.dut2_as = 65002
bgp_4node_data.dut3_as = 65003
bgp_4node_data.dut4_as = 65004
bgp_4node_data.network1 = '172.16.2.2/32'
bgp_4node_data.network2 = '172.16.4.4/32'
bgp_4node_data.aggr_route = '172.16.0.0/16'
bgp_4node_data.aggr_route1 = '6002:1::/64'
bgp_4node_data.wait_timer = 150
bgp_4node_data.network3 = '6002:1::1/128'
bgp_4node_data.network4 = '6002:1::2/128'
bgp_4node_data.network5 = '50.50.50.50/32'
bgp_4node_data.network6 = '60.60.60.60/32'
bgp_4node_data.network7 = '70.70.70.70/32'

bgp_4node_data.dut1_as_4byte = 4294967292
bgp_4node_data.dut2_as_4byte = 4294967293
bgp_4node_data.dut3_as_4byte = 4294967294
bgp_4node_data.dut4_as_4byte = 4294967295
bgp_4node_data.loopback0= 'Loopback0'
bgp_4node_data.loopback0_addr6= '6002:1::3/128'
bgp_4node_data.loopback0_addr6_net= '6002:1::3'
bgp_4node_data.loopback1= 'Loopback1'
bgp_4node_data.loopback1_addr4= '172.16.5.5/32'
bgp_4node_data.loopback1_addr4_net= '172.16.5.5'
bgp_4node_data.loopback1_addr6= '7002:1::3/128'
bgp_4node_data.loopback1_addr6_net= '7002:1::3'
bgp_4node_data.d2d4_ip = "10.5.0.1"
bgp_4node_data.d4d2_ip = "10.5.0.4"
bgp_4node_data.d4network = "172.16.50.50/32"

@pytest.fixture(scope="module", autouse=True)
def bgp_module_hooks(request):
    global sub_intf
    sub_intf =st.get_args("routed_sub_intf")
    bgp_pre_config()
    yield
    bgp_pre_config_cleanup()

# bgp module level pre config function
def bgp_pre_config():
    global topo
    st.banner("BGP MODULE CONFIG - START")
    st.log("Ensure minimum linear 4-node topology")
    st.ensure_min_topology('D1D2:1', 'D2D3:1', 'D2D4:1', 'D3D4:1','D3D1:1')
    if sub_intf is not True:
        bgp4nodelib.l3_ipv4v6_address_config_unconfig(config='yes', config_type='all')
    else:
        bgp4nodelib.l3_ipv4v6_address_config_unconfig_sub_intf(config='yes', config_type='all')
    # Ping Verification
    if not bgp4nodelib.l3tc_vrfipv4v6_address_ping_test(config_type='all', ping_count=3):
        msg = st.error("Ping failed between DUTs")
        st.report_fail('msg', msg)
    topo = bgp4nodelib.get_confed_topology_info()
    st.log(topo)
    st.banner("BGP MODULE CONFIG - END")

# bgp module level pre config cleanup function
def bgp_pre_config_cleanup():
    st.banner("BGP MODULE CONFIG CLEANUP - START")
    if sub_intf is not True:
        bgp4nodelib.l3_ipv4v6_address_config_unconfig(config='no')
    else:
        bgp4nodelib.l3_ipv4v6_address_config_unconfig_sub_intf(config='no')
    st.banner("BGP MODULE CONFIG CLEANUP - END")


@pytest.fixture(scope="function")
def bgp_func_hooks(request):
    yield

@pytest.mark.bgp_ft
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOtSoRtBgp4Fn057'])
def test_ft_bgp_ebgp_multihop_4byteASN(hooks_test_ft_bgp_ebgp_multihop_4byteASN):
    """

    Verify the functioning of ebgp multihop command with 4 byte ASN
    """
    # On DUT1 and DUT3, create BGP with 4byte ASN
    dut1_as = 6500001
    dut1 = topo['dut_list'][0]
    dut3_as = 6500002
    dut3 = topo['dut_list'][2]
    errs = []
    wait_timer = 150

    st.banner("Verify the ebgp multihop functionality with 4 byte AS Number")

    # Configure bgp on DUT1 and configure DUT3 as neighbor with ebgp-multihop ttl set to 5
    st.log("Configure eBGP on DUT1 with Neighbor as DUT3 with multihop set to maximum hops of 5")
    bgpapi.config_bgp(dut1, local_as=dut1_as, neighbor=topo['D3D2P1_ipv4'], remote_as=dut3_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='5')

    # Add static route towards neighbor DUT3
    st.log("Add static route towards DUT3")
    ipapi.create_static_route(dut1, topo['D1D2P1_neigh_ipv4'], "{}/24".format(topo['D3D2P1_ipv4']))

    # Configure bgp on DUT3 and configure DUT1 as neighbor with ebgp-multihop ttl set to 5
    st.log("Configure eBGP on DUT3 with DUT1 as Neighbor with multihop set to maximum hops of 5")
    bgpapi.config_bgp(dut3, local_as=dut3_as, neighbor=topo['D1D2P1_ipv4'], remote_as=dut1_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='5')

    # Add static route towards neighbor DUT1
    st.log("Add static route towards DUT1")
    ipapi.create_static_route(dut3, topo['D3D2P1_neigh_ipv4'], "{}/24".format(topo['D1D2P1_ipv4']))

    st.log("Verify BGP neighborship on DUT1")
    if not st.poll_wait(bgpapi.verify_bgp_summary, wait_timer, dut1, family='ipv4', neighbor=topo['D3D2P1_ipv4'],
                           state='Established'):
        errs.append(st.error("Failed to form BGP eBGP multihop peering with 4byte ASN"))
    if not errs:
        st.log("Pass: BGP neighborship established between DUT1 and DUT3")
    else:
        errs.append(st.error("Fail: BGP neighborship not established between DUT1 and DUT3"))
        st.banner("Collecting techsupport")
        st.generate_tech_support(topo['dut_list'][0:3], "test_ft_bgp_ebgp_multihop_4byteASN")

    st.banner("Verifying now the BGP strict capability match option")
    bgpapi.cleanup_router_bgp(dut1)
    bgpapi.cleanup_router_bgp(dut3)
    # Rearranging the configs due to vtysh issue SONIC-75344.
    bgpapi.config_bgp(dut1, local_as=dut1_as, neighbor=topo['D3D2P1_ipv4'], remote_as=dut3_as,
            config_type_list=["neighbor","ebgp_mhop","connect"], ebgp_mhop='5',connect="1")
    bgpapi.config_bgp(dut3, local_as=dut3_as, neighbor=topo['D1D2P1_ipv4'], remote_as=dut1_as,
            config_type_list=["neighbor","ebgp_mhop","connect"], ebgp_mhop='5',connect="1")
    bgpapi.config_bgp_capability(dut3,local_as=dut3_as,neighbor=topo['D1D2P1_ipv4'],input_param="strict_capability_match",config="yes")
    bgpapi.config_bgp_capability(dut3,local_as=dut3_as,neighbor=topo['D1D2P1_ipv4'],input_param="dont_capability_negotiate",config="yes")
    bgpapi.config_bgp_capability(dut1,local_as=dut1_as,neighbor=topo['D3D2P1_ipv4'],input_param="strict_capability_match",config="yes")
    wait_timer = 15
    st.log("Verify BGP neighborship on DUT1")
    if not st.poll_wait(bgpapi.verify_bgp_summary, wait_timer, dut1, family='ipv4', neighbor=topo['D3D2P1_ipv4'],state='Established'):
        st.log("Pass: BGP neighborship NOT established from DUT3 towards DUT1 as expected")
    else:
        errs.append(st.error("Fail: BGP neighborship came up which is not expected"))

    if not st.poll_wait(bgpapi.verify_bgp_summary, wait_timer, dut3, family='ipv4', neighbor=topo['D1D2P1_ipv4'],state='Established'):
        st.log("Pass: BGP neighborship NOT established from DUT3 towards DUT1 as expected")
    else:
        errs.append(st.error("Fail: BGP neighborship came up which is not expected"))
        st.banner("Collecting techsupport")
        st.generate_tech_support(topo['dut_list'][0:3],"test_ft_bgp_strict_capability_match")

    bgpapi.config_bgp_capability(dut3,local_as=dut3_as,neighbor=topo['D1D2P1_ipv4'],input_param="dont_capability_negotiate",config="no")
    bgpapi.config_bgp_capability(dut3,local_as=dut3_as,neighbor=topo['D1D2P1_ipv4'],input_param="strict_capability_match",config="no")
    bgpapi.config_bgp_capability(dut1,local_as=dut1_as,neighbor=topo['D3D2P1_ipv4'],input_param="strict_capability_match",config="no")
    bgpapi.clear_ip_bgp(dut3)

    if st.poll_wait(bgpapi.verify_bgp_summary, wait_timer, dut3, family='ipv4', neighbor=topo['D1D2P1_ipv4'],state='Established'):
        st.log("Pass: BGP neighborship established from DUT3 towards DUT1")
    else:
        errs.append(st.error("Fail: BGP neighborship from DUT3 towards DUT1 did not came up after 150 sec"))
        st.banner("Collecting techsupport")
        st.generate_tech_support(topo['dut_list'][0:3],"test_ft_bgp_strict_capability_match")

    st.report_result(errs)

@pytest.fixture(scope="function")
def hooks_test_ft_bgp_ebgp_multihop_4byteASN():
    yield
    dut1 = topo['dut_list'][0]
    dut3 = topo['dut_list'][2]
    bgpapi.cleanup_router_bgp(dut1)
    bgpapi.cleanup_router_bgp(dut3)
    ipapi.delete_static_route(dut1, topo['D1D2P1_neigh_ipv4'], "{}/24".format(topo['D3D2P1_ipv4']))
    ipapi.delete_static_route(dut3, topo['D3D2P1_neigh_ipv4'], "{}/24".format(topo['D1D2P1_ipv4']))

################################################################################
# BGP Confederation test cases  - START

def bgp_confed_pre_config():
    st.banner("BGP CONFED CLASS CONFIG - START")
    bgp4nodelib.l3tc_vrfipv4v6_confed_bgp_config(config='yes')
    # BGP Neighbour Verification
    if not st.poll_wait(bgp4nodelib.l3tc_vrfipv4v6_address_confed_bgp_check, 10, config_type='all'):
        msg = st.error("Neighborship failed to Establish between DUTs")
        st.report_fail('msg', msg)
    st.log("Getting all topology info related to connectivity / TG and other parameters between duts")
    st.banner("BGP CONFED CLASS CONFIG - END")

def bgp_confed_pre_config_cleanup():
    st.banner("BGP CONFED CLASS CONFIG CLEANUP - START")
    bgp4nodelib.l3tc_vrfipv4v6_confed_bgp_config(config='no')
    st.banner("BGP RIF CLASS CONFIG CLEANUP - END")

@pytest.fixture(scope='class')
def bgp_confed_class_hook(request):
    bgp_confed_pre_config()
    yield
    bgp_confed_pre_config_cleanup()

# TestBGPConfed class
@pytest.mark.usefixtures('bgp_confed_class_hook')
class TestBGPConfed():

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ipv6_confed_route_distribution(self):
        st.banner("Verify the config of BGP v6 confederation and router advertisement")

        st.log("Advertise a network from DUT1 and check if it is learnt on confederation peer DUT3")
        dut1_name = topo['dut_list'][0]
        dut3_name = topo['dut_list'][2]
        network_ipv4 = '131.5.6.0/24'
        network_ipv6 = '2000:1::0/64'

        # Advertise a network to peer

        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv4, network_import_check=True)
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv6, addr_family='ipv6', config='yes', network_import_check=True)
        entries = bgpapi.get_ip_bgp_route(dut3_name, family="ipv4", network=network_ipv4)
        entries1 = bgpapi.get_ip_bgp_route(dut3_name, family="ipv6", network="2000:1::/64")
        errs = []
        if entries and entries1:
            st.log("Pass: Routes advertised by DUT1 found on DUT3")
        else:
            errs.append(st.error("Fail: Route advertised by DUT1 not found on DUT3"))
            st.banner("Collecting techsupport")
            st.generate_tech_support(topo['dut_list'][0:3], "test_ipv6_confed_route_distribution")

        # Clear applied configs
        st.banner("Cleanup for TestFunction")
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv4, config='no' )
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv6, addr_family='ipv6', config='no')

        st.report_result(errs)

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ipv6_confed_with_rr(self):
        st.banner("Verify Route Reflector behavior within a confederation of BGP v6 peers")
        st.banner("Consider the right confederation iBGP AS and check Route Reflector functionality between the 3 iBGP Routers")

        network_ipv4 = '131.6.6.0/24'
        network_ipv6 = '3000:1::0/64'
        # iBGP AS is one of D2/D3/D4 ASN
        iBGP_as=topo['D2_as']

        st.log("Advertise an IPv4 and an IPv6 network from DUT2 through BGP")
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, network_import_check=True)
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='yes', network_import_check=True)

        st.log("Check the network on the 3rd iBGP peer DUT4 is not learnt because Route Reflector is not configured on peer DUT3")
        entries = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv4", network=network_ipv4)
        entries1 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv6", network="3000:1::/64")

        if not entries and not entries1:
            st.log("Pass: DUT4 did not learn routes without configuring Route Reflector on peer DUT3")
        else:
            msg = st.error("Fail: DUT4 learned route without configuring Route Reflector on peer DUT3")
            st.banner("Collecting techsupport")
            st.generate_tech_support(topo['dut_list'][1:4], "test_ipv6_confed_with_rr")
            # Clear applied configurations
            st.banner("Cleanup for TestFunction")
            bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, config='no' )
            bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='no')
            st.report_fail('msg', msg)

        st.log("Now configure Route Reflector on DUT3")
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv4', topo['D3D4P1_neigh_ipv4'], 'yes')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv6', topo['D3D4P1_neigh_ipv6'], 'yes')

        st.wait(10)
        st.log("Now the routes should be learnt on the 3rd IBGP peer DUT4")
        entries2 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv4", network=network_ipv4)
        entries3 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv6", network="3000:1::/64")
        errs = []
        if entries2 and entries3:
            st.log("Pass: DUT4 learned the routes advertised by peer DUT2")
        else:
            errs.append(st.error("Fail: DUT4 did not learn the routes advertised by peer DUT2"))
            st.banner("Collecting techsupport")
            st.generate_tech_support(topo['dut_list'][1:4], "test_ipv6_confed_with_rr")

        # Clear applied configurations
        st.banner("Cleanup for TestFunction")
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, config='no' )
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='no')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv4', topo['D3D4P1_neigh_ipv4'], 'no')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv6', topo['D3D4P1_neigh_ipv6'], 'no')

        st.report_result(errs)

    @pytest.mark.rmap
    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_fail
    def test_confed_route_distribution_with_rmap(self):
        st.banner("Verify the behavior of Route-Maps over confederation peers")
        errs = []

        network1 = '134.5.6.0/24'
        network2 = '134.5.7.0/24'
        network3 = '134.5.8.0'
        as_path = '200'
        access_list1 = 'test-access-list1'
        access_list2 = 'test-access-list2'
        access_list3 = 'test-access-list3'

        st.log("Create access-lists and a route-map in DUT1, add to it permit, deny and AS-path prepending policies")
        # Create access-list test-access-list1
        ipapi.config_access_list(topo['dut_list'][0], access_list1, network3+'/24', 'permit', seq_num="1")
        # Create route-map and permit network3
        ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'test-rmap', 'permit', '10', access_list1)

        # Add set option to prepend as-path 200
        ipapi.config_route_map_set_aspath(topo['dut_list'][0], 'test-rmap', 'permit', '10', as_path)

        # Create access-list test-access-list2
        ipapi.config_access_list(topo['dut_list'][0], access_list2, network1, 'deny', seq_num="2")
        # In route-map, deny network1
        ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'test-rmap', 'deny', '20', access_list2)

        # Create access-list test-access-list3
        ipapi.config_access_list(topo['dut_list'][0], access_list3, network2, 'permit', seq_num="3")
        # In route-map, permit network2
        ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'test-rmap', 'permit', '30', access_list3)

        # Advertise three networks from leaf
        st.log("Advertise the networks from DUT1 through BGP and associate with the route-map")
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network1, 'test-rmap', network_import_check=True)
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network2, 'test-rmap', network_import_check=True)
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network3+'/24', 'test-rmap', network_import_check=True)

        st.log("Verify in peer DUT2 the network configured in {} has the AS-path prepended".format(access_list1))
        # Verify that the neighbor has the as-path prepended
        output = bgpapi.show_bgp_ipvx_prefix(topo['dut_list'][1], prefix=network3, masklen=topo['D1_as'])
        result = False
        for x in output or {}:
            peer_asn = x['peerasn']
            peer_asn = peer_asn.split()
            for each in peer_asn:
                if each == as_path:
                    result = True
                    break
        if result:
            st.log("Pass: AS-Path {} found to be prepended with network {}/24".format(as_path, network3))
        else:
            errs.append(st.error("Fail: AS-Path {} not found to be prepended".format(as_path)))

        # Verify that network1 is not present in ip route table
        st.log("Verify that peer DUT2 not learnt the network configured as 'deny' in {}".format(access_list2))
        n1 = ipapi.verify_ip_route(topo['dut_list'][1], ip_address=network1)
        if n1 is False:
            st.log("Pass: DUT2 did not learn network {}".format(network1))
        else:
            errs.append(st.error("Fail: DUT2 learned the network {}".format(network1)))

        # Verify that network2 is present in ip route table
        st.log("Verify that peer DUT2 learnt the network configured as 'permit' in {}".format(access_list3))
        n2 = ipapi.verify_ip_route(topo['dut_list'][1], ip_address=network2)
        if n2:
            st.log("Pass: DUT2 learned the network {}".format(network2))
        else:
            errs.append(st.error("Fail: DUT2 did not learn network {}".format(network2)))

        if errs:
            st.banner("Collecting techsupport")
            st.generate_tech_support(topo['dut_list'][0:2], "test_confed_route_distribution_with_rmap")

        ipapi.config_route_map_mode(topo['dut_list'][0], 'test-rmap', 'permit', '10', config='no')

        # Clear applied configurations
        st.banner("Cleanup for TestFunction")
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list3', network2, 'permit', config='no', seq_num="3")
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list2', network1, 'deny', config='no', seq_num="2")
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list1', network3+'/24', 'permit', config='no', seq_num="1")

        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network1, 'test-rmap', config='no')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network2, 'test-rmap', config='no')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network3+'/24', 'test-rmap', config='no')

        st.report_result(errs)

# BGP Confederation test cases  - END
################################################################################

@pytest.mark.bgp_ft
@pytest.mark.inventory(feature='Regression', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_bgp_ebgp_aggr_addr_as_set'])
def test_ft_bgp_ebgp_aggr_addr_as_set(hooks_test_ft_bgp_ebgp_aggr_addr_as_set):
    """

    Verify the functioning of ebgp aggregate address summary-only and as-set
    """
    err_list = []
    prefix_name = "P1"
    prefix_seq = 1

    prefix_ip = "11.2.0.2/32"
    route_map_name = "R1"
    route_map_seq = 10

    route_map_obj = RouteMap(route_map_name)

    adv_network = "182.6.0.3/24"
    adv_network_ip = "182.6.0.0/24"

    next_hop_ip = "2.2.2.5"
    st.banner("Creating PREFIX LIST AND ROUTE MAP")
    ipapi.config_access_list(topo['dut_list'][1], name=prefix_name, ipaddress=prefix_ip, seq_num=prefix_seq)
    route_map_obj.add_permit_sequence(route_map_seq)
    # route_map_obj.add_sequence_match_peer(route_map_seq, peer)
    # route_map_obj.add_sequence_match_tag(route_map_seq, tag)
    route_map_obj.add_sequence_match_next_hop_prefix_list(route_map_seq, prefix_name)
    route_map_obj.add_sequence_set_ipv4_next_hop(route_map_seq, next_hop_ip)
    route_map_obj.execute_command(topo['dut_list'][1])

    st.banner("Verify the functioning of IPv4 ebgp aggregate address summary-only and as-set --- Start")
    st.log("Configure IPv4 eBGP peering on DUT1,DUT2 and DUT3 ")

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D2D1P1_ipv4'], "remote_as": bgp_4node_data.dut2_as, "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut2_as, "neighbor": topo['D1D2P1_ipv4'] , "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut3_as, "neighbor": topo['D2D3P1_ipv4'], "remote_as": bgp_4node_data.dut2_as, "config_type_list": ["neighbor", "activate"]}

    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=topo['D3D2P1_ipv4'], remote_as=bgp_4node_data.dut3_as, config_type_list=["neighbor", "activate"])
    output = st.exec_all([
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv4', neighbor=topo['D2D1P1_ipv4'], state='Established'),
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv4', neighbor=[topo['D1D2P1_ipv4'], topo['D3D2P1_ipv4']], state='Established'),
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv4', neighbor=topo['D2D3P1_ipv4'], state='Established')
      ])[0]
    if not all(output):
        err = st.error("Failed to form IPv4 eBGP peering")
        err_list.append(err)

    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut3_as, bgp_4node_data.network1, config='yes', network_import_check=True)
    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut3_as, bgp_4node_data.network2, config='yes', network_import_check=True)
    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as, address_range=bgp_4node_data.aggr_route,
                                        family="ipv4", config="add", summary=True, as_set=True)
    st.wait(5, 'wait time for the route learning in neighbor')
    if not bgpapi.get_ip_bgp_route(topo['dut_list'][0], network=bgp_4node_data.aggr_route):
        err = st.error("failed to learn adv IPv4 aggr route")
        err_list.append(err)
    n1 = ipapi.verify_ip_route(topo['dut_list'][0], shell='sonic', ip_address=bgp_4node_data.aggr_route)
    n2 = bgpapi.get_ip_bgp_route(topo['dut_list'][0], network=bgp_4node_data.aggr_route, as_path=str(bgp_4node_data.dut2_as) + " " + str(bgp_4node_data.dut3_as))
    if not (n1 and n2):
        err = st.error("Advertised IPv4 network verification is failed")
        err_list.append(err)

    st.banner("Verification of BGP aggregate address with route-map having set community--- Start")
    ipapi.config_route_map(topo['dut_list'][1],route_map="map1",config='yes',sequence="10",community="11:22")
    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as, address_range=bgp_4node_data.aggr_route,
                                        family="ipv4", config="add", summary=True, as_set=True,route_map="map1")
    st.wait(2, 'wait time for the route learning in neighbor')
    n2 = bgpapi.get_ip_bgp_route(topo['dut_list'][0], network=bgp_4node_data.aggr_route,
         as_path=str(bgp_4node_data.dut2_as) + " " + str(bgp_4node_data.dut3_as),community="11:22")
    if not n2:
        err = st.error("FAIL: IPv4 aggregate-address not found with the community attribute set by route-map map1 in D1")
        err_list.append(err)
    else:
        st.log("PASS: IPv4 aggregate-address found with the community attribute set by route-map map1 in D1")

    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as, address_range=bgp_4node_data.aggr_route,
                                        family="ipv4", config="delete", summary=True, as_set=True,route_map="map1")
    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as, address_range=bgp_4node_data.aggr_route,
                                        family="ipv4", config="add", summary=True, as_set=True)
    ipapi.config_route_map(topo['dut_list'][1],route_map="map1",config='no',sequence="10")
    st.banner("Verification of BGP aggregate address with route-map having set community--- End")

    dict4 = {"local_as": bgp_4node_data.dut2_as, "neighbor": topo['D1D2P1_ipv4'], "remote_as": bgp_4node_data.dut1_as,
             "config_type_list": ["neighbor", "activate", "routeMap"], "routeMap": route_map_name, "diRection": 'out'}
    bgpapi.config_bgp(topo['dut_list'][1], **dict4)
    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut3_as, adv_network, config='yes',
                                        network_import_check=True)
    st.wait(3, 'wait time for the route learning in neighbor')
    if not bgpapi.get_ip_bgp_route(topo['dut_list'][1], network=adv_network_ip):
        err = st.error("Verification of route map network advertisement failed.")
        err_list.append(err)
    if not bgpapi.fetch_ip_bgp_route(topo['dut_list'][0], family='ipv4',
                                     match={"network": adv_network_ip, "next_hop": next_hop_ip}):
        err = st.error("Verification of set next hop change when prefix list matched is failed.")
        err_list.append(err)

    first_as = n2[0]['as_path'].split()[0] if n2 else " "
    second_as = n2[0]['as_path'].split()[1] if n2 else " "

    if (first_as == str(bgp_4node_data.dut2_as)) and (second_as == str(bgp_4node_data.dut3_as)):
        st.log("IPv4 BGP aggr-route summary-only as-set verification is succesfful {} {}".format(first_as, second_as))
    else:
        err = st.error("IPv4v BGP aggr-route summary-only as-set verification is failed {} {}".format(first_as, second_as))
        err_list.append(err)
    st.banner("Verification of the functioning of IPv4 ebgp aggregate address summary-only and as-set is completed --- end")
    st.banner("Verification of the IPv4 BGP functioning of soft-reconfiguration inbound--- Start")

    bgpapi.config_bgp_neighbor_properties(topo['dut_list'][1], bgp_4node_data.dut2_as, topo['D1D2P1_ipv4'], family="ipv4", mode="unicast", soft_reconfig=True)
    ipapi.configure_loopback(topo['dut_list'][0], loopback_name=bgp_4node_data.loopback1, config="yes")
    ipapi.config_ip_addr_interface(topo['dut_list'][0], bgp_4node_data.loopback0, bgp_4node_data.loopback1_addr4_net, 32, family="ipv4")
    bgpapi.config_bgp_network_advertise(topo['dut_list'][0], bgp_4node_data.dut1_as, bgp_4node_data.loopback1_addr4, config='yes', addr_family='ipv4')
    if not bgpapi.get_ip_bgp_route(topo['dut_list'][1], family='ipv4', network=bgp_4node_data.loopback1_addr4):
        err = st.error("failed to learn neighbor adv IPv4 route")
        err_list.append(err)

    route_refresh_cnt_before = bgpapi.get_bgp_ipv4_neighbor_vtysh(topo['dut_list'][1], [topo['D1D2P1_ipv6'], 'routerefreshsent'])
    bgpapi.clear_ip_bgp_vtysh(topo['dut_list'][1], value="*", soft=True, dir="in")
    route_refresh_cnt_after = bgpapi.get_bgp_ipv4_neighbor_vtysh(topo['dut_list'][1], [topo['D1D2P1_ipv6'], 'routerefreshsent'])

    if route_refresh_cnt_after == route_refresh_cnt_before:
        st.log("Successfully verified the functioning of soft-reconfiguration inbound, before value:{} after value:{}".format(route_refresh_cnt_before, route_refresh_cnt_after))
    else:
        err = st.error("Failed to verify the functioning of the soft-reconfiguration inboud, before value:{} after value:{}".format(route_refresh_cnt_before, route_refresh_cnt_after))
        err_list.append(err)
    st.banner("Verification of the IPv4 BGP functioning of soft-reconfiguration inbound--- End")

    st.banner("Verify the functioning of IPv6 ebgp aggregate address summary-only and as-set --- Start")
    st.log("Configure IPv6 eBGP peering on DUT1,DUT2 and DUT3 ")

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D2D1P1_ipv6'], "remote_as": bgp_4node_data.dut2_as, "addr_family" :'ipv6', "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut2_as, "neighbor": topo['D1D2P1_ipv6'], "remote_as": bgp_4node_data.dut1_as, "addr_family" :'ipv6',"config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut3_as, "neighbor": topo['D2D3P1_ipv6'], "remote_as": bgp_4node_data.dut2_as, "addr_family" : 'ipv6', "config_type_list": ["neighbor", "activate"]}

    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=topo['D3D2P1_ipv6'], remote_as=bgp_4node_data.dut3_as,addr_family = 'ipv6', config_type_list=["neighbor", "activate"])
    output = st.exec_all([
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv6', neighbor=topo['D2D1P1_ipv6'], state='Established'),
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv6', neighbor=[topo['D1D2P1_ipv6'], topo['D3D2P1_ipv6']], state='Established'),
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv6', neighbor=topo['D2D3P1_ipv6'], state='Established')
      ])[0]
    if not all(output):
        err = st.error("Failed to form IPv6 eBGP peering")
        err_list.append(err)
    ipapi.config_route_map(topo['dut_list'][1], route_map='rmap_metric', config='yes', sequence='10', metric='50')
    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut3_as, bgp_4node_data.network3,config='yes', addr_family = 'ipv6',network_import_check=True)
    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut3_as, bgp_4node_data.network4,config='yes',addr_family = 'ipv6', network_import_check=True)
    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as, address_range=bgp_4node_data.aggr_route1,
                                        family="ipv6", config="add", summary=True, as_set=True)
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=topo['D1D2P1_ipv6'], config='yes', addr_family='ipv6', config_type_list=["routeMap"], routeMap='rmap_metric', diRection='out')
    st.wait(5, 'wait time for the route learning in neighbor')

    if not bgpapi.get_ip_bgp_route(topo['dut_list'][0],family='ipv6', network=bgp_4node_data.aggr_route1):
        err = st.error("failed to learn adv IPv6 aggr route")
        err_list.append(err)
    n1 = ipapi.verify_ip_route(topo['dut_list'][0],  family='ipv6',shell='sonic',ip_address=bgp_4node_data.aggr_route1)
    n2 = bgpapi.get_ip_bgp_route(topo['dut_list'][0],family='ipv6', network=bgp_4node_data.aggr_route1, as_path=str(bgp_4node_data.dut2_as) + " " + str(bgp_4node_data.dut3_as))
    if not (n1 and n2):
        err = st.error("Advertised IPv6 network verification is failed")
        err_list.append(err)

    first_as = n2[0]['as_path'].split()[0] if n2 else " "
    second_as = n2[0]['as_path'].split()[1] if n2 else " "

    if (first_as == str(bgp_4node_data.dut2_as)) and (second_as == str(bgp_4node_data.dut3_as)):
        st.log("IPv6 BGP aggr-route summary-only as-set verification is succesfful {} {}".format(first_as, second_as))
    else:
        err = st.error("IPv6 BGP aggr-route summary-only as-set verification is failed {} {}".format(first_as, second_as))
        err_list.append(err)

    st.banner("Configure the route-map with match source-protocol static and set metris 20 in D2 and verify in D1")
    ipapi.create_static_route(topo['dut_list'][1], topo['D2D3P1'], "1001::/96",family='ipv6')
    ipapi.config_route_map(topo['dut_list'][1],route_map='rmap_metric',config='yes',sequence='5',metric='20',match_source_protocol="static")
    bgpapi.config_bgp(dut=topo['dut_list'][1],local_as=bgp_4node_data.dut2_as,config_type_list=['redist'],redistribute='static',addr_family="ipv6")
    if not retry_api(ipapi.verify_ip_route,topo['dut_list'][0], family='ipv6',shell='sonic',ip_address="1001::/96",
            interface=topo['D1D2P1'],cost="20",retry_count=10, delay=2):
        err = st.error("GCOV verify step: Route-map match source-protocol static failed")
        err_list.append(err)
    else:
        st.log("GCOV verify step: Route-map match source-protocol static PASSED")

    st.banner("Remove the route-map with seq no 5 and remove the redistribute ipv6 static and ipv6 static route")
    ipapi.config_route_map(topo['dut_list'][1],route_map='rmap_metric',config='no',sequence='5')
    bgpapi.config_bgp(dut=topo['dut_list'][1],local_as=bgp_4node_data.dut2_as,config_type_list=['redist'],
                      redistribute='static',addr_family="ipv6",config="no")
    ipapi.delete_static_route(topo['dut_list'][1], topo['D2D3P1'], "1001::/96",family='ipv6')
    st.wait(5, 'wait time for the route learning in neighbor')

    st.banner("Verification of the functioning of IPv6 ebgp aggregate address summary-only and as-set is completed --- end")
    st.banner("Verification of the IPv6 BGP functioning of soft-reconfiguration inbound--- Start")

    bgpapi.config_bgp_neighbor_properties(topo['dut_list'][1], bgp_4node_data.dut2_as, topo['D1D2P1_ipv6'], family="ipv6", mode="unicast", soft_reconfig=True)
    ipapi.configure_loopback(topo['dut_list'][0], loopback_name=bgp_4node_data.loopback0, config="yes")
    ipapi.config_ip_addr_interface(topo['dut_list'][0], bgp_4node_data.loopback0, bgp_4node_data.loopback0_addr6_net, 128, family="ipv6")
    bgpapi.config_bgp_network_advertise(topo['dut_list'][0], bgp_4node_data.dut1_as, bgp_4node_data.loopback0_addr6, config='yes', addr_family='ipv6')
    if not bgpapi.get_ip_bgp_route(topo['dut_list'][1],family='ipv6', network=bgp_4node_data.loopback0_addr6):
        err = st.error("failed to learn neighbor adv IPv6 route")
        err_list.append(err)
    route_refresh_cnt_before1 = bgpapi.get_bgp_ipv6_neighbor_vtysh(topo['dut_list'][1], [topo['D1D2P1_ipv6'], 'routerefreshsent'])
    bgpapi.clear_ipv6_bgp_vtysh(topo['dut_list'][1], value="*", soft=True, dir="in")
    route_refresh_cnt_after1 = bgpapi.get_bgp_ipv6_neighbor_vtysh(topo['dut_list'][1], [topo['D1D2P1_ipv6'], 'routerefreshsent'])
    if route_refresh_cnt_after1 == route_refresh_cnt_before1:
        st.log("Successfully verified the IPv6 BGP "
               "functioning of soft-reconfiguration inbound, before value:{} after value:{}".format(route_refresh_cnt_before1,route_refresh_cnt_after1))
    else:
        err = st.error("Failed to verify the IPv6 BGP functioning of the soft-reconfiguration inboud, before value:{} after value:{}".format(route_refresh_cnt_before1,route_refresh_cnt_after1))
        err_list.append(err)
    st.banner("Verification of the IPv6 BGP functioning of soft-reconfiguration inbound--- End")

    if err_list:
        err = st.error("BGP aggr-route summary-only as-set verificaiton is failed.")
        err_list.insert(0, err)

    st.report_result(err_list, first_only=True)

@pytest.fixture(scope="function")
def hooks_test_ft_bgp_ebgp_aggr_addr_as_set():
    yield
    st.exec_all([[bgpapi.cleanup_router_bgp,topo['dut_list'][0]],[bgpapi.cleanup_router_bgp,topo['dut_list'][1]],[bgpapi.cleanup_router_bgp,topo['dut_list'][2]]])
    ipapi.config_route_map(topo['dut_list'][2], route_map='rmap_metric', config='no', sequence='10', metric='50')
    ipapi.configure_loopback(topo['dut_list'][0], loopback_name=bgp_4node_data.loopback0, config="no")
    ipapi.configure_loopback(topo['dut_list'][0], loopback_name=bgp_4node_data.loopback1, config="no")

@pytest.mark.inventory(feature='Regression', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_bgp_ibgp_RR_Loop'])
def test_ft_bgp_ibgp_RR_Loop(hooks_test_ft_bgp_ibgp_RR_Loop):
    """
    Verify the functioning of iBGP Route-Reflector cluster loop
    """
    err_list = []

    vars = st.get_testbed_vars()
    topo['D1D3P1'] = vars['D1D3P1']
    topo['D3D1P1'] = vars['D3D1P1']
    topo['D1D3P1_ipv4'] = "11.4.0.1"
    topo['D3D1P1_ipv4'] = "11.4.0.2"

    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("Verify the functioning of iBGP Route-Reflector cluster loop --- Start")
    st.log("Configure IPv4 iBGP peering on DUT1,DUT2 and DUT3 ")

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D2D1P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D1D2P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D2D3P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}

    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D3D1P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D3D2P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D1D3P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])

    dict1 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D2D1P1_ipv4']}
    dict2 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D3D2P1_ipv4']}
    dict3 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D1D3P1_ipv4']}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][1], topo['dut_list'][2]], bgpapi.create_bgp_route_reflector_client, [dict1, dict2, dict3])

    dict1 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D3D1P1_ipv4']}
    dict2 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D1D2P1_ipv4']}
    dict3 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D2D3P1_ipv4']}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][1], topo['dut_list'][2]], bgpapi.create_bgp_route_reflector_client, [dict1, dict2, dict3])

    output = st.exec_all([
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv4', neighbor=[topo['D2D1P1_ipv4'], topo['D3D1P1_ipv4']], state='Established'),
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv4', neighbor=[topo['D1D2P1_ipv4'], topo['D3D2P1_ipv4']], state='Established'),
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv4', neighbor=[topo['D2D3P1_ipv4'], topo['D1D3P1_ipv4']], state='Established')
      ])[0]
    if not all(output):
        err = st.error("Failed to form IPv4 eBGP peering")
        err_list.append(err)

    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut1_as, bgp_4node_data.network1, config='yes', network_import_check=True)
    st.wait(5, 'wait time for the route learning in neighbor')

    if not bgpapi.get_ip_bgp_route(topo['dut_list'][0], network=bgp_4node_data.network1):
        err = st.error("failed to learn adv IPv4 aggr route")
        err_list.append(err)
    if not bgpapi.get_ip_bgp_route(topo['dut_list'][1], network=bgp_4node_data.network1):
        err = st.error("failed to learn adv IPv4 aggr route")
        err_list.append(err)

    net1 = bgpapi.fetch_ip_bgp_route(topo['dut_list'][2],match={'next_hop': '0.0.0.0'},select=['network','next_hop'])
    if not net1:
        err = st.error("route not originated from source dut")
        err_list.append(err)

    if not (net1[0]['next_hop'] == '0.0.0.0'):
        st.error("adv route reached source routers, RR cluster loop verification failed")
    st.banner("Verify the functioning of iBGP Route-Reflector cluster loop --- end")

    if err_list:
        err = st.error("iBGP Route-Reflector cluster loop verificaiton is failed.")
        err_list.insert(0, err)

    st.report_result(err_list, first_only=True)

@pytest.fixture(scope="function")
def hooks_test_ft_bgp_ibgp_RR_Loop():
    yield
    st.exec_all([[bgpapi.cleanup_router_bgp, topo['dut_list'][0]], [bgpapi.cleanup_router_bgp, topo['dut_list'][1]], [bgpapi.cleanup_router_bgp, topo['dut_list'][2]]])
    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

@pytest.mark.inventory(feature='Regression', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_bgp_ebgp_community'])
def test_ft_bgp_ebgp_community():
    """  Verify the functioning of eBGP communities  """
    err_list = []

    vars = st.get_testbed_vars()
    topo['D1D3P1'] = vars['D1D3P1']
    topo['D3D1P1'] = vars['D3D1P1']
    topo['D1D3P1_ipv4'] = "11.4.0.1"
    topo['D3D1P1_ipv4'] = "11.4.0.2"

    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("Verify the functioning of eBGP communities --- Start")
    st.banner("Step1 -- Configure IPv4 iBGP peering on DUT1,DUT2,DUT3 and DUT4 ")

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D3D1P1_ipv4'], "remote_as": bgp_4node_data.dut3_as, "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut2_as, "neighbor": topo['D3D2P1_ipv4'], "remote_as": bgp_4node_data.dut3_as, "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut3_as, "neighbor": topo['D1D3P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict4 = {"local_as": bgp_4node_data.dut4_as, "neighbor": topo['D3D4P1_ipv4'], "remote_as": bgp_4node_data.dut3_as, "config_type_list": ["neighbor", "activate"]}

    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1),
                 ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2),
                 ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3),
                 ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][3], **dict4)])

    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D2D3P1_ipv4'], remote_as=bgp_4node_data.dut2_as, config_type_list=["neighbor", "activate"])
    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D4D3P1_ipv4'], remote_as=bgp_4node_data.dut4_as, config_type_list=["neighbor", "activate"])
    bgpapi.advertise_bgp_network(topo['dut_list'][0], bgp_4node_data.dut1_as, bgp_4node_data.network1, network_import_check=True)
    st.banner("Step2 -- BGP community configuration in DUT1 using ip prefix list and route-maps ")
    ipapi.config_access_list(topo['dut_list'][0], 'LOOPBACK', bgp_4node_data.network1, 'permit', seq_num="7")
    ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'SET_COMMUNITY', 'permit', '10', 'LOOPBACK')
    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10',community = '64984:0',metric=50)

    bgpapi.config_bgp(topo['dut_list'][0], local_as=bgp_4node_data.dut1_as, neighbor=topo['D3D1P1_ipv4'], config='yes', addr_family='ipv4', config_type_list=["routeMap"], routeMap='SET_COMMUNITY', diRection='out')

    bgpapi.config_bgp_neighbor_properties(topo['dut_list'][0], bgp_4node_data.dut1_as, topo['D3D1P1_ipv4'], family="ipv4",mode="unicast",community="standard")

    output = st.exec_all([ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv4', neighbor=topo['D3D1P1_ipv4'], state='Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv4', neighbor=topo['D3D2P1_ipv4'], state = 'Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv4', neighbor=[topo['D2D3P1_ipv4'], topo['D1D3P1_ipv4'], topo['D4D3P1_ipv4']], state='Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][3], family='ipv4', neighbor=topo['D3D4P1_ipv4'], state = 'Established')])[0]
    if not all(output):
        err = st.error("Failed to form IPv4 eBGP peering")
        err_list.append(err)

    bgpapi.config_bgp_community_list(topo['dut_list'][2], community_type='standard', community_name='comm_test', action='permit', community_num='64984:0')
    ipapi.config_route_map_match_ip_address(topo['dut_list'][2], 'SET_COMMUNITY_1', 'permit', '10',None, community='comm_test')
    ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY_1', sequence='10',metric=50)
    ipapi.config_route_map_set_aspath(topo['dut_list'][2], 'SET_COMMUNITY_1', 'permit', '10', "1,1,1,1")
    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D2D3P1_ipv4'], config='yes', addr_family='ipv4', config_type_list=["routeMap"], routeMap='SET_COMMUNITY_1', diRection='out')
    st.wait(5, 'wait time for the route learning in neighbor')

    if not bgpapi.get_ip_bgp_route(topo['dut_list'][1], network=bgp_4node_data.network1):
        err = st.error("failed to learn adv IPv4 aggr route")
        err_list.append(err)

    n2 = bgpapi.get_ip_bgp_route(topo['dut_list'][1], network=bgp_4node_data.network1, as_path=str(bgp_4node_data.dut3_as) + " " + "1 1 1 1"+" "+str(bgp_4node_data.dut1_as))
    if not n2:
        err = st.error("failed to learn IPv4 route")
        err_list.append(err)
    else:
        prepend_as = n2[0]['as_path']
        if (prepend_as == str(bgp_4node_data.dut3_as)+' 1 1 1 1 '+ str(bgp_4node_data.dut1_as)):
            st.log("BGP community based as-path prepend verification is completed successfully")
        else:
            err = st.error("BGP community based as-path prepend verification is failed")
            err_list.append(err)

    port_api.shutdown(topo['dut_list'][3],[topo['D4D3P1']])
    ipapi.config_ip_addr_interface(topo['dut_list'][1], topo['D2D4P1'], bgp_4node_data.d2d4_ip, 24, family="ipv4")
    ipapi.config_ip_addr_interface(topo['dut_list'][3], topo['D4D2P1'], bgp_4node_data.d4d2_ip, 24, family="ipv4")
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=bgp_4node_data.d4d2_ip,
            remote_as=bgp_4node_data.dut4_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='1')
    bgpapi.config_bgp(topo['dut_list'][3], local_as=bgp_4node_data.dut4_as, neighbor=bgp_4node_data.d2d4_ip,
            remote_as=bgp_4node_data.dut2_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='1')
    bgpapi.config_bgp_network_advertise(topo['dut_list'][3], bgp_4node_data.dut4_as, bgp_4node_data.d4network,
            config='yes',network_import_check=True)

    bgp4nodelib.as_path_filter_config(topo['dut_list'][1],"ACL1","MAP1","_1 1 1 1_","deny")
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=topo['D3D2P1_ipv4'],
           config='yes', addr_family='ipv4', config_type_list=["routeMap"], routeMap="MAP1", diRection='in')
    st.wait(5)
    n2 = bgpapi.get_ip_bgp_route(topo['dut_list'][1], network=bgp_4node_data.network1,
            as_path=str(bgp_4node_data.dut3_as) + " " + "1 1 1 1"+" "+str(bgp_4node_data.dut1_as))
    if not n2:
        st.log("PASS: IPv4 route {} not learnt as expected due to as path filtering deny rule".format(bgp_4node_data.network1))
    else:
        err_list.append(err)
        st.log("FAIL: IPv4 route {} learnt with some AS even if as path filtering deny rule applied".format(bgp_4node_data.network1))

    st.wait(5)
    bgp4nodelib.as_path_filter_config(topo['dut_list'][1],"ACL2","MAP2",str(bgp_4node_data.dut4_as),"permit")

    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=topo['D3D2P1_ipv4'],
           config='no', addr_family='ipv4', config_type_list=["routeMap"], routeMap="MAP1", diRection='in')
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=bgp_4node_data.d4d2_ip,
           config='yes', addr_family='ipv4', config_type_list=["routeMap"], routeMap="MAP2", diRection='in')
    st.wait(5)
    n2 = bgpapi.get_ip_bgp_route(topo['dut_list'][1], network=bgp_4node_data.d4network,
            as_path=str(bgp_4node_data.dut4_as))
    if n2:
        st.log("PASS: IPv4 route {} not learnt as expected due to as path filtering deny rule".format(bgp_4node_data.d4network))
    else:
        err_list.append(err)
        st.log("FAIL: IPv4 route {} learnt with AS {} even if as path filtering deny rule applied".format(bgp_4node_data.d4network, bgp_4node_data.dut4_as))

    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=bgp_4node_data.d4d2_ip,
           config='no', addr_family='ipv4', config_type_list=["routeMap"], routeMap="MAP2", diRection='in')
    bgp4nodelib.as_path_filter_config(topo['dut_list'][1],"ACL2","MAP2",str(bgp_4node_data.dut4_as),"permit","no")
    bgp4nodelib.as_path_filter_config(topo['dut_list'][1],"ACL1","MAP1","_1 1 1 1_","deny","no")

    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=bgp_4node_data.d4d2_ip,
            remote_as=bgp_4node_data.dut4_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='1',config="no")
    bgpapi.config_bgp(topo['dut_list'][3], local_as=bgp_4node_data.dut4_as, neighbor=bgp_4node_data.d2d4_ip,
            remote_as=bgp_4node_data.dut2_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='1',config="no")
    bgpapi.config_bgp_network_advertise(topo['dut_list'][3], bgp_4node_data.dut4_as, bgp_4node_data.d4network,
            config='no',network_import_check=True)
    ipapi.delete_ip_interface(topo['dut_list'][1], topo['D2D4P1'], bgp_4node_data.d2d4_ip, 24, family="ipv4")
    ipapi.delete_ip_interface(topo['dut_list'][3], topo['D4D2P1'], bgp_4node_data.d4d2_ip, 24, family="ipv4")
    port_api.noshutdown(topo['dut_list'][3],[topo['D4D3P1']])
    st.banner("Verify the functioning of eBGP communities  --- end")

    # Clear applied configs
    st.banner("Cleanup for TestFunction")
    st.exec_all([[bgpapi.cleanup_router_bgp, topo['dut_list'][0]], [bgpapi.cleanup_router_bgp, topo['dut_list'][1]],
                 [bgpapi.cleanup_router_bgp, topo['dut_list'][2]], [bgpapi.cleanup_router_bgp, topo['dut_list'][3]]])
    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', config='no')
    ipapi.config_access_list(topo['dut_list'][0], 'LOOPBACK', "", mode="", config='no')
    bgpapi.config_bgp_community_list(topo['dut_list'][2], community_type='standard', community_name='comm_test', action='permit', community_num='64984:0', config='no')
    ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY_1', sequence='10', metric=50, config='no')

    if err_list:
        err = st.error("BGP community based as-path prepend verification is failed.")
        err_list.insert(0, err)

    st.report_result(err_list, first_only=True)

@pytest.mark.inventory(feature='Regression', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_bgp_ebgp_4byte_aggr_addr'])
def test_ft_bgp_ebgp_4byte_aggr_addr():
    """

    Verify the functioning of ebgp 4byte aggregate address summary-only and as-set
    """
    err_list = []

    st.banner("Verify the functioning of IPv4 ebgp 4byte aggregate address summary-only and as-set --- Start")
    st.log("Configure IPv4 eBGP peering on DUT1,DUT2 and DUT3 ")

    dict1 = {"local_as": bgp_4node_data.dut1_as_4byte, "neighbor": topo['D2D1P1_ipv4'], "remote_as": bgp_4node_data.dut2_as_4byte, "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut2_as_4byte, "neighbor": topo['D1D2P1_ipv4'] , "remote_as": bgp_4node_data.dut1_as_4byte, "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut3_as_4byte, "neighbor": topo['D2D3P1_ipv4'], "remote_as": bgp_4node_data.dut2_as_4byte, "config_type_list": ["neighbor", "activate"]}

    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as_4byte, neighbor=topo['D3D2P1_ipv4'], remote_as=bgp_4node_data.dut3_as_4byte, config_type_list=["neighbor", "activate"])
    [output, _] = st.exec_all([ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv4', neighbor=topo['D2D1P1_ipv4'], state='Established'),
                               ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv4', neighbor=[topo['D1D2P1_ipv4'], topo['D3D2P1_ipv4']], state='Established'),
                               ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv4', neighbor=topo['D2D3P1_ipv4'], state='Established')])
    if not all(output):
        err = st.error("Failed to form IPv4 eBGP peering")
        err_list.append(err)
    st.banner("Verification of the functioning of outbound route filtering --- Start")

    dict1 = {"local_asn": bgp_4node_data.dut2_as_4byte, "neighbor_ip": topo['D3D2P1_ipv4'], "family": "ipv4", "mode": "unicast", "orf_dir": "both"}
    dict2 = {"local_asn": bgp_4node_data.dut3_as_4byte, "neighbor_ip": topo['D2D3P1_ipv4'], "family": "ipv4", "mode": "unicast", "orf_dir": "both"}
    st.exec_each2([topo['dut_list'][1], topo['dut_list'][2]], bgpapi.config_bgp_neighbor_properties, [dict1, dict2])
    bgpapi.config_bgp_network_advertise(topo['dut_list'][1], bgp_4node_data.dut2_as_4byte, bgp_4node_data.network6, config='yes', network_import_check=True)
    bgpapi.config_bgp_network_advertise(topo['dut_list'][1], bgp_4node_data.dut2_as_4byte, bgp_4node_data.network7, config='yes', network_import_check=True)
    bgpapi.config_bgp_network_advertise(topo['dut_list'][1], bgp_4node_data.dut2_as_4byte, bgp_4node_data.network5, config='yes', network_import_check=True)
    ipapi.config_access_list(topo['dut_list'][2], "orf_in", bgp_4node_data.network5
                             , mode='permit', config='yes', family='ipv4', seq_num='4')
    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as_4byte, neighbor=topo['D2D3P1_ipv4'], config='yes', addr_family='ipv4', config_type_list=["prefix_list"], prefix_list='orf_in', diRection='in')

    net1 = bgpapi.get_ip_bgp_route(topo['dut_list'][2], family='ipv4', network=bgp_4node_data.network5)
    if not net1: #match for the actual route in prefix list
        err = st.error("ORF filtered IPv4 network verification is failed")
        err_list.append(err)
    net2 = bgpapi.get_ip_bgp_route(topo['dut_list'][2], family='ipv4', network=bgp_4node_data.network6)
    net3 = bgpapi.get_ip_bgp_route(topo['dut_list'][2], family='ipv4', network=bgp_4node_data.network7)
    if (net2 or net3): #check for the un-matched routes in prefix list
        err = st.error("ORF filtered IPv4 network verification is not working,received non-match networks")
        err_list.append(err)

    st.banner("Verification of the functioning of outbound route filtering --- End")

    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut3_as_4byte, bgp_4node_data.network1, config='yes', network_import_check=True)
    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut3_as_4byte, bgp_4node_data.network2, config='yes', network_import_check=True)
    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as_4byte, address_range=bgp_4node_data.aggr_route,
                                        family="ipv4", config="add", summary=True, as_set=True)
    st.wait(5, 'wait time for the route learning in neighbor')
    if not bgpapi.get_ip_bgp_route(topo['dut_list'][0], network=bgp_4node_data.aggr_route):
        err = st.error("failed to learn adv IPv4 aggr route")
        err_list.append(err)
    n1 = ipapi.verify_ip_route(topo['dut_list'][0], shell='sonic', ip_address=bgp_4node_data.aggr_route)
    n2 = bgpapi.get_ip_bgp_route(topo['dut_list'][0], network=bgp_4node_data.aggr_route, as_path=str(bgp_4node_data.dut2_as_4byte) + " " + str(bgp_4node_data.dut3_as_4byte))
    if not (n1 and n2):
        err = st.error("Advertised IPv4 network verification is failed")
        err_list.append(err)

    first_as = n2[0]['as_path'].split()[0] if n2 else " "
    second_as = n2[0]['as_path'].split()[1] if n2 else " "

    if (first_as == str(bgp_4node_data.dut2_as_4byte)) and (second_as == str(bgp_4node_data.dut3_as_4byte)):
        st.log("IPv4 BGP aggr-route summary-only as-set verification is succesfful {} {}".format(first_as, second_as))
    else:
        err = st.error("IPv4v BGP aggr-route summary-only as-set verification is failed {} {}".format(first_as, second_as))
        err_list.append(err)
    st.banner("Verification of the functioning of IPv4 ebgp 4byte aggregate address summary-only and as-set is completed --- end")

    st.banner("Verify the functioning of IPv6 4byte ebgp aggregate address summary-only and as-set --- Start")
    st.log("Configure IPv6 eBGP peering on DUT1,DUT2 and DUT3 ")

    dict1 = {"local_as": bgp_4node_data.dut1_as_4byte, "neighbor": topo['D2D1P1_ipv6'], "remote_as": bgp_4node_data.dut2_as_4byte, "addr_family" :'ipv6', "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut2_as_4byte, "neighbor": topo['D1D2P1_ipv6'], "remote_as": bgp_4node_data.dut1_as_4byte, "addr_family" :'ipv6',"config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut3_as_4byte, "neighbor": topo['D2D3P1_ipv6'], "remote_as": bgp_4node_data.dut2_as_4byte, "addr_family" : 'ipv6', "config_type_list": ["neighbor", "activate"]}

    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as_4byte, neighbor=topo['D3D2P1_ipv6'], remote_as=bgp_4node_data.dut3_as_4byte,addr_family = 'ipv6', config_type_list=["neighbor", "activate"])
    [output, _] = st.exec_all([ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv6', neighbor=topo['D2D1P1_ipv6'], state='Established'),
                               ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv6', neighbor=[topo['D1D2P1_ipv6'], topo['D3D2P1_ipv6']], state='Established'),
                               ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv6', neighbor=topo['D2D3P1_ipv6'], state='Established')])
    if not all(output):
        err = st.error("Failed to form IPv6 eBGP peering")
        err_list.append(err)
    ipapi.config_route_map(topo['dut_list'][1], route_map='rmap_metric', config='yes', sequence='10', metric='50')
    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut3_as_4byte, bgp_4node_data.network3,config='yes', addr_family = 'ipv6',network_import_check=True)
    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut3_as_4byte, bgp_4node_data.network4,config='yes',addr_family = 'ipv6', network_import_check=True)
    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as_4byte, address_range=bgp_4node_data.aggr_route1,
                                        family="ipv6", config="add", summary=True, as_set=True)
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as_4byte, neighbor=topo['D1D2P1_ipv6'], config='yes', addr_family='ipv6', config_type_list=["routeMap"], routeMap='rmap_metric', diRection='out')
    st.wait(5, 'wait time for the route learning in neighbor')

    if not bgpapi.get_ip_bgp_route(topo['dut_list'][0],family='ipv6', network=bgp_4node_data.aggr_route1):
        err = st.error("failed to learn adv IPv6 aggr route")
        err_list.append(err)
    n1 = ipapi.verify_ip_route(topo['dut_list'][0],  family='ipv6',shell='sonic',ip_address=bgp_4node_data.aggr_route1)
    n2 = bgpapi.get_ip_bgp_route(topo['dut_list'][0],family='ipv6', network=bgp_4node_data.aggr_route1, as_path=str(bgp_4node_data.dut2_as_4byte) + " " + str(bgp_4node_data.dut3_as_4byte))
    if not (n1 and n2):
        err = st.error("Advertised IPv6 network verification is failed")
        err_list.append(err)

    first_as = n2[0]['as_path'].split()[0] if n2 else " "
    second_as = n2[0]['as_path'].split()[1] if n2 else " "

    if (first_as == str(bgp_4node_data.dut2_as_4byte)) and (second_as == str(bgp_4node_data.dut3_as_4byte)):
        st.log("IPv6 BGP 4byte aggr-route summary-only as-set verification is succesfful {} {}".format(first_as, second_as))
    else:
        err = st.error("IPv6 BGP 4byte aggr-route summary-only as-set verification is failed {} {}".format(first_as, second_as))
        err_list.append(err)
    st.banner("Verification of the functioning of IPv6 ebgp 4byte aggregate address summary-only and as-set is completed --- end")

    st.banner("Verification of BGP aggregate address with route-map having set community--- Start")
    ipapi.config_route_map(topo['dut_list'][1],route_map="map1",config='yes',sequence="10",community="11:22")
    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as_4byte, address_range=bgp_4node_data.aggr_route1,
                                        family="ipv6", config="add", summary=True, as_set=True,route_map="map1")
    st.wait(2, 'wait time for the route learning in neighbor')
    n2 = bgpapi.get_ip_bgp_route(topo['dut_list'][0],family='ipv6', network=bgp_4node_data.aggr_route1, as_path=str(bgp_4node_data.dut2_as_4byte) + " " + str(bgp_4node_data.dut3_as_4byte),community="11:22")
    if not n2:
        err = st.error("Verification of BGP IPv6 aggregate address with route-map having set community failed")
        err_list.append(err)
    else:
        st.log("Verification of BGP IPv6 aggregate address with route-map having set community PASSED")

    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as_4byte, address_range=bgp_4node_data.aggr_route1,
                                        family="ipv6", config="delete", summary=True, as_set=True,route_map="map1")
    bgpapi.create_bgp_aggregate_address(topo['dut_list'][1], local_asn=bgp_4node_data.dut2_as_4byte, address_range=bgp_4node_data.aggr_route1,
                                        family="ipv6", config="add", summary=True, as_set=True)
    ipapi.config_route_map(topo['dut_list'][1],route_map="map1",config='no')
    st.banner("Verification of BGP aggregate address with route-map having set community--- End")
    # Clear applied configs
    st.banner("Cleanup for TestFunction")
    st.exec_all([[bgpapi.cleanup_router_bgp,topo['dut_list'][0]],[bgpapi.cleanup_router_bgp,topo['dut_list'][1]],[bgpapi.cleanup_router_bgp,topo['dut_list'][2]]])
    ipapi.config_route_map(topo['dut_list'][2], route_map='rmap_metric', config='no', sequence='10', metric='50')

    if err_list:
        err = st.error("BGP 4byte aggr-route summary-only as-set verificaiton is failed.")
        err_list.insert(0, err)

    st.report_result(err_list, first_only=True)

@pytest.mark.inventory(feature='Regression', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_bgpv6_global_LL_nexthop'])
def test_ft_bgpv6_global_LL_nexthop(hooks_test_ft_bgpv6_global_LL_nexthop):

    err_list = []

    purpose = "Verify that if BGPv6 sends global next-hop when update source used as loopback else LL as next-hop while adv a route to neighbor"
    st.banner("{} --- Start".format(purpose))

    st.log("Configure IPv6 eBGP peering on DUT1,DUT2 and DUT3 ")
    dict1 = {"local_as": bgp_4node_data.dut1_as_4byte, "neighbor": topo['D2D1P1_ipv6'], "remote_as": bgp_4node_data.dut2_as_4byte, "addr_family": 'ipv6', "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut2_as_4byte, "neighbor": topo['D1D2P1_ipv6'], "remote_as": bgp_4node_data.dut1_as_4byte, "addr_family": 'ipv6', "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut3_as_4byte, "neighbor": topo['D2D3P1_ipv6'], "remote_as": bgp_4node_data.dut2_as_4byte, "addr_family": 'ipv6', "config_type_list": ["neighbor", "activate"]}
    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])
    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as_4byte, neighbor=topo['D3D2P1_ipv6'], remote_as=bgp_4node_data.dut3_as_4byte, addr_family='ipv6', config_type_list=["neighbor", "activate"])

    # verify IPv6 eBGP peering
    output = st.exec_all([ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv6', neighbor=topo['D2D1P1_ipv6'], state='Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv6', neighbor=[topo['D1D2P1_ipv6'], topo['D3D2P1_ipv6']], state='Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv6', neighbor=topo['D2D3P1_ipv6'], state='Established')])[0]
    if not all(output):
        err = st.error("Failed to form IPv6 eBGP peering")
        err_list.append(err)

    st.banner("Step1:Adv loopback network and verifying the next-hop as LL address in neighbor")
    ipapi.configure_loopback(topo['dut_list'][0], loopback_name=bgp_4node_data.loopback0, config="yes")
    ipapi.configure_loopback(topo['dut_list'][0], loopback_name=bgp_4node_data.loopback1, config="yes")
    ipapi.config_ip_addr_interface(topo['dut_list'][0], bgp_4node_data.loopback0, bgp_4node_data.loopback0_addr6_net, 128, family="ipv6")
    ipapi.config_ip_addr_interface(topo['dut_list'][0], bgp_4node_data.loopback1, bgp_4node_data.loopback1_addr6_net, 128, family="ipv6")
    bgpapi.config_bgp_network_advertise(topo['dut_list'][0], bgp_4node_data.dut1_as_4byte, bgp_4node_data.loopback1_addr6, config='yes', addr_family='ipv6')
    bgpapi.clear_ipv6_bgp_vtysh(topo['dut_list'][1])
    st.wait(5,"wait time for the adv network to learn in neighbor")
    dut1_LL = ipapi.get_link_local_addresses(topo['dut_list'][0], topo['D1D2P1'])
    if not dut1_LL:
        err= st.error("failed to get link local address on {}".format(topo['D1D2P1']), dut=topo['dut_list'][0])
        err_list.append(err)
    elif not bgpapi.fetch_ip_bgp_route(topo['dut_list'][1], family='ipv6',match={"network": bgp_4node_data.loopback1_addr6, "next_hop": dut1_LL[0]}):
        err = st.error("failed to learn neighbor adv IPv6 route")
        err_list.append(err)

    st.banner("Step2:Configure a static route in neighbor dut to reach to the loopback address in dut which is used as a update source interface loopback for the BGP neighborship")
    ipapi.create_static_route(topo['dut_list'][1], topo['D1D2P1_ipv6'], bgp_4node_data.loopback0_addr6,family='ipv6')
    dict1 = {"local_as": bgp_4node_data.dut1_as_4byte, "neighbor": topo['D2D1P1_ipv6'], "remote_as": bgp_4node_data.dut2_as_4byte, "addr_family": 'ipv6', "config_type_list": ["neighbor", "activate","update_src_intf"],"update_src_intf":bgp_4node_data.loopback0}
    dict2 = {"local_as": bgp_4node_data.dut2_as_4byte, "neighbor": bgp_4node_data.loopback0_addr6_net, "remote_as": bgp_4node_data.dut1_as_4byte, "addr_family": 'ipv6', "config_type_list": ["neighbor", "activate"]}
    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2)])

    st.banner("Step3:Check the BGP neighborship with the updated source interface loopback")
    if not retry_api(ip_bgp.check_bgp_session, topo['dut_list'][1], nbr_list=[bgp_4node_data.loopback0_addr6_net], state_list=['Established'], retry_count=25, delay=2):
        err = st.error("Failed to form IPv6 eBGP peering")
        err_list.append(err)
    bgpapi.clear_ipv6_bgp_vtysh(topo['dut_list'][1])
    st.wait(5, "wait time for the adv network to learn in neighbor")

    st.banner("Step4:Received network next-hop as global address in neighbor1 verification")
    if not bgpapi.fetch_ip_bgp_route(topo['dut_list'][1], family='ipv6',match={"network": bgp_4node_data.loopback1_addr6, "next_hop": topo['D1D2P1_ipv6']}):
        err = st.error("failed to learn neighbor adv IPv6 route")
        err_list.append(err)

    st.banner("Step5:Received network next-hop as LL address in neighbor2 verification")
    dut2_LL = ipapi.get_link_local_addresses(topo['dut_list'][1], topo['D2D3P1'])
    if not dut2_LL:
        st.error("failed to get link local address on {}".format(topo['D2D3P1']), dut=topo['dut_list'][1])
    elif not bgpapi.fetch_ip_bgp_route(topo['dut_list'][2], family='ipv6',match={"network": bgp_4node_data.loopback1_addr6, "next_hop": dut2_LL[0]}):
        err = st.error("failed to learn neighbor adv IPv6 route")
        err_list.append(err)

    st.banner("{} --- End".format(purpose))

    if err_list:
        err = st.error("{} --- Failed".format(purpose))
        err_list.insert(0, err)

    st.report_result(err_list, first_only=True)

@pytest.fixture(scope="function")
def hooks_test_ft_bgpv6_global_LL_nexthop():
    yield
    st.exec_all([[bgpapi.cleanup_router_bgp, topo['dut_list'][0]], [bgpapi.cleanup_router_bgp, topo['dut_list'][1]], [bgpapi.cleanup_router_bgp, topo['dut_list'][2]]])
    ipapi.delete_static_route(topo['dut_list'][1], topo['D1D2P1_ipv6'], bgp_4node_data.loopback0_addr6, family='ipv6')

@pytest.mark.inventory(feature='Regression', release='Cyrus4.0.0')
@pytest.mark.inventory(testcases=['test_bgp_add_path'])
def test_bgp_add_path(hooks_test_bgp_add_path):
    """
    Verify the BGP add path addpath-tx-all-paths
    """
    err_list = []
    techsupport_not_gen = True

    vars = st.get_testbed_vars()
    topo['D1D3P1'] = vars['D1D3P1']
    topo['D3D1P1'] = vars['D3D1P1']
    topo['D1D3P1_ipv4'] = "11.4.0.1"
    topo['D3D1P1_ipv4'] = "11.4.0.2"
    topo['D2D4P1_ipv4'] = "11.5.0.1"
    topo['D4D2P1_ipv4'] = "11.5.0.2"

    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {"interface_name": topo['D2D4P1'], "ip_address": topo['D2D4P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    dict2 = {"interface_name": topo['D4D2P1'], "ip_address": topo['D4D2P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    st.exec_each2([topo['dut_list'][1], topo['dut_list'][3]], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("Verify the functioning of BGP add path --- Start")
    st.log("Configure IPv4 iBGP peering on DUT1,DUT2 and DUT3 ")

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D2D1P1_ipv4'], "remote_as": bgp_4node_data.dut1_as,
             "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D1D2P1_ipv4'], "remote_as": bgp_4node_data.dut1_as,
              "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D2D3P1_ipv4'], "remote_as": bgp_4node_data.dut1_as,
             "config_type_list": ["neighbor", "activate"]}
    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp,
              topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D3D1P1_ipv4'], "remote_as": bgp_4node_data.dut1_as,
             "config_type_list": ["neighbor", "activate","connect"],"connect":"1"}
    dict2 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D3D2P1_ipv4'], "remote_as": bgp_4node_data.dut1_as,
             "config_type_list": ["neighbor", "activate","connect"],"connect":"1"}
    dict3 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D1D3P1_ipv4'], "remote_as": bgp_4node_data.dut1_as,
             "config_type_list": ["neighbor", "activate"]}
    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp,
              topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])

    dict1 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D2D1P1_ipv4']}
    dict2 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D3D2P1_ipv4']}
    dict3 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D1D3P1_ipv4']}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][1], topo['dut_list'][2]], bgpapi.create_bgp_route_reflector_client, [dict1, dict2, dict3])

    dict1 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D3D1P1_ipv4']}
    dict2 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D1D2P1_ipv4']}
    dict3 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D2D3P1_ipv4']}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][1], topo['dut_list'][2]], bgpapi.create_bgp_route_reflector_client, [dict1, dict2, dict3])

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D4D2P1_ipv4'], "remote_as": bgp_4node_data.dut1_as,
             "config_type_list": ["neighbor", "activate","connect","max_path_ibgp"],"connect":"1","max_path_ibgp":"8"}
    dict2 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D2D4P1_ipv4'], "remote_as": bgp_4node_data.dut1_as,
              "config_type_list": ["neighbor", "activate","connect","max_path_ibgp"],"connect":"1","max_path_ibgp":"8"}
    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict1),ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][3], **dict2)])

    dict1 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D4D2P1_ipv4']}
    dict2 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D2D4P1_ipv4']}
    st.exec_each2([topo['dut_list'][1], topo['dut_list'][3], topo['dut_list'][2]], bgpapi.create_bgp_route_reflector_client, [dict1, dict2, dict3])

    [output, _] = st.exec_all([ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv4', neighbor=[topo['D2D1P1_ipv4'], topo['D3D1P1_ipv4']], state='Established'),
                               ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv4', neighbor=[topo['D1D2P1_ipv4'], topo['D3D2P1_ipv4']], state='Established'),
                               ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv4', neighbor=[topo['D2D3P1_ipv4'], topo['D1D3P1_ipv4']], state='Established')])
    if not all(output):
        err = st.error("Failed to form IPv4 eBGP peering")
        err_list.append(err)

    if err_list and techsupport_not_gen:
        techsupport_not_gen = False
        st.generate_tech_support(topo['dut_list'][0:4], "test_bgp_add_path")

    for route1 in ["11.1.0.0/24","11.4.0.0/24",bgp_4node_data.network1]:
        bgpapi.config_bgp_network_advertise(topo['dut_list'][0],bgp_4node_data.dut1_as,route1, config='yes',network_import_check=True)
    for route1 in ["11.2.0.0/24","11.4.0.0/24",bgp_4node_data.network1]:
        bgpapi.config_bgp_network_advertise(topo['dut_list'][2],bgp_4node_data.dut1_as,route1, config='yes',network_import_check=True)
    for route1 in ["11.1.0.0/24","11.2.0.0/24","11.5.0.0/24"]:
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1],bgp_4node_data.dut1_as,route1,config='yes',network_import_check=True)
    bgpapi.config_bgp_network_advertise(topo['dut_list'][3],bgp_4node_data.dut1_as,"11.5.0.0/24",config='yes',network_import_check=True)

    bgpapi.config_bgp_addpath(topo['dut_list'][1],local_as=bgp_4node_data.dut1_as,neighbor=topo['D4D2P1_ipv4'],version="ipv4",
        input_param="addpath_tx_all_paths",config="yes")
    st.wait(5, 'wait time for the route learning in neighbor')

    if not bgpapi.get_ip_bgp_route(topo['dut_list'][0], network=bgp_4node_data.network1):
        err = st.error("failed to learn adv IPv4 aggr route")
        err_list.append(err)
    if not bgpapi.get_ip_bgp_route(topo['dut_list'][1], network=bgp_4node_data.network1):
        err = st.error("failed to learn adv IPv4 aggr route")
        err_list.append(err)

    net1 = bgpapi.fetch_ip_bgp_route(topo['dut_list'][1],match={'next_hop': '11.1.0.1'},select=['network','next_hop'])
    net2 = bgpapi.fetch_ip_bgp_route(topo['dut_list'][1],match={'next_hop': '11.2.0.2'},select=['network','next_hop'])
    if not net1 and not net2:
        err = st.error("route {} is not seen in dut2".format(bgp_4node_data.network1))
        err_list.append(err)
    else:
        if ipapi.verify_ip_route(topo['dut_list'][1],family="ipv4",shell="sonic",vrf_name=None,
                ip_address=bgp_4node_data.network1,nexthop="11.1.0.1") and \
                ipapi.verify_ip_route(topo['dut_list'][1],family="ipv4",shell="sonic",
                vrf_name=None, ip_address=bgp_4node_data.network1, nexthop="11.2.0.2"):
            st.log("PASS:D2 Route {} seen with the next-hops 11.1.0.1 and 11.2.0.2".format(bgp_4node_data.network1))
        else:
            err = st.error("FAIL:D2 Route {} not seen with the next-hops 11.1.0.1 and 11.2.0.2".format(bgp_4node_data.network1))
            err_list.append(err)

    net1 = bgpapi.fetch_ip_bgp_route(topo['dut_list'][3],match={'next_hop': '11.1.0.1'},select=['network','next_hop'])
    net2 = bgpapi.fetch_ip_bgp_route(topo['dut_list'][3],match={'next_hop': '11.2.0.2'},select=['network','next_hop'])
    if not net1 and not net2:
        err = st.error("route {} is not seen in dut4".format(bgp_4node_data.network1))
        err_list.append(err)
    else:
        if ipapi.verify_ip_route(topo['dut_list'][3],family="ipv4",shell="sonic",vrf_name=None,
                ip_address=bgp_4node_data.network1,nexthop="11.1.0.1") and \
                ipapi.verify_ip_route(topo['dut_list'][3],family="ipv4",shell="sonic",
                vrf_name=None,ip_address=bgp_4node_data.network1,nexthop="11.2.0.2"):
            st.log("PASS:D4 Route {} seen with the next-hops 11.1.0.1 and 11.2.0.2".format(bgp_4node_data.network1))
        else:
            err = st.error("FAIL:D4 Route {} not seen with the next-hops 11.1.0.1 and 11.2.0.2".format(bgp_4node_data.network1))
            err_list.append(err)

    if err_list and techsupport_not_gen:
        techsupport_not_gen = False
        st.generate_tech_support(topo['dut_list'][0:4], "test_bgp_add_path")

    bgpapi.config_bgp_addpath(topo['dut_list'][1],local_as=bgp_4node_data.dut1_as,neighbor=topo['D4D2P1_ipv4'], \
        version="ipv4",input_param="addpath_tx_all_paths",config="no")
    bgpapi.config_bgp_addpath(topo['dut_list'][1],local_as=bgp_4node_data.dut1_as,neighbor=topo['D4D2P1_ipv4'], \
        version="ipv4",input_param="addpath_tx_bestpath_per_as",config="yes")
    st.wait(5, 'wait time for the route learning in neighbor')

    net1 = bgpapi.fetch_ip_bgp_route(topo['dut_list'][3],match={'next_hop': '11.1.0.1'},select=['network','next_hop'])
    net2 = bgpapi.fetch_ip_bgp_route(topo['dut_list'][3],match={'next_hop': '11.2.0.2'},select=['network','next_hop'])
    if net2:
        err = st.error("Non Best route {} from D2 is still seen in dut4".format(bgp_4node_data.network1))
        err_list.append(err)
    else:
        st.log("Only Best route {} from D2 is seen in dut4 as per addpath-tx-bestpath-per-as config in D3".format(bgp_4node_data.network1))
        if ipapi.verify_ip_route(topo['dut_list'][3],family="ipv4",shell="sonic",vrf_name=None,
                ip_address=bgp_4node_data.network1,nexthop="11.1.0.1") and \
                not ipapi.verify_ip_route(topo['dut_list'][3],family="ipv4",shell="sonic",
                vrf_name=None,ip_address=bgp_4node_data.network1,nexthop="11.2.0.2"):
            st.log("PASS:D4 Route {} with NH 11.1.0.1 and without NH 11.2.0.2".format(bgp_4node_data.network1))
        else:
            err = st.error("FAIL:D4 Route {} with NH 11.1.0.1 and without NH 11.2.0.2".format(bgp_4node_data.network1))
            err_list.append(err)

    if err_list and techsupport_not_gen:
        techsupport_not_gen = False
        st.generate_tech_support(topo['dut_list'][0:4], "test_bgp_add_path")

    st.banner("Verify the functioning of BGP Add path --- end")

    if err_list:
        err = st.error("BGP Add Path addpath-tx-all-paths verificaiton is failed.")
        err_list.insert(0, err)

    st.report_result(err_list, first_only=True)

@pytest.fixture(scope="function")
def hooks_test_bgp_add_path():
    yield
    bgpapi.config_bgp_addpath(topo['dut_list'][1],local_as=bgp_4node_data.dut1_as,neighbor=topo['D4D2P1_ipv4'], \
        version="ipv4",input_param="addpath_tx_bestpath_per_as",config="no")
    st.banner("Cleanup for TestFunction")
    st.exec_all([[bgpapi.cleanup_router_bgp, topo['dut_list'][0]], [bgpapi.cleanup_router_bgp, topo['dut_list'][1]],
                 [bgpapi.cleanup_router_bgp, topo['dut_list'][2]], [bgpapi.cleanup_router_bgp, topo['dut_list'][3]]])
    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

@pytest.mark.inventory(feature='Regression', release='Buzznik3.5.1')
@pytest.mark.inventory(testcases=['ft_bgp_ebgp_community_map'])
@pytest.mark.inventory(release='Cyrus4.0.0', testcases=['test_ft_bgp_ebgp_community_sub'])
def test_ft_bgp_ebgp_community_map(hooks_test_ft_bgp_ebgp_community_map):
    """  Verify the functioning of eBGP communities  """
    err_list = []

    test_case_id = ["test_ft_bgp_ebgp_community_sub"]

    vars = st.get_testbed_vars()
    topo['D1D3P1'] = vars['D1D3P1']
    topo['D3D1P1'] = vars['D3D1P1']
    topo['D1D3P1_ipv4'] = "11.4.0.1"
    topo['D3D1P1_ipv4'] = "11.4.0.2"

    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("Verify the functioning of eBGP communities --- Start")
    st.banner("Step1 -- Configure IPv4/v6 BGP peering on DUT1,DUT2,DUT3 and DUT4 ")

    bgpapi.config_bgp(topo['dut_list'][1], local_as = bgp_4node_data.dut2_as, neighbor = topo['D3D2P1_ipv6'], addr_family = 'ipv6', remote_as = bgp_4node_data.dut3_as, config_type_list = ["neighbor", "activate"])
    bgpapi.config_bgp(topo['dut_list'][2], local_as = bgp_4node_data.dut3_as, neighbor = topo['D2D3P1_ipv6'], addr_family = 'ipv6', remote_as = bgp_4node_data.dut2_as, config_type_list = ["neighbor", "activate"])
    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D3D1P1_ipv4'], "remote_as": bgp_4node_data.dut3_as, "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut2_as, "neighbor": topo['D3D2P1_ipv4'], "remote_as": bgp_4node_data.dut3_as, "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut3_as, "neighbor": topo['D1D3P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict4 = {"local_as": bgp_4node_data.dut4_as, "neighbor": topo['D3D4P1_ipv4'], "remote_as": bgp_4node_data.dut3_as, "config_type_list": ["neighbor", "activate"]}

    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1),
                 ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2),
                 ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3),
                 ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][3], **dict4)])

    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D2D3P1_ipv4'], remote_as=bgp_4node_data.dut2_as, config_type_list=["neighbor", "activate"])
    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D4D3P1_ipv4'], remote_as=bgp_4node_data.dut4_as, config_type_list=["neighbor", "activate"])
    bgpapi.advertise_bgp_network(topo['dut_list'][0], bgp_4node_data.dut1_as, bgp_4node_data.network1, network_import_check=True)

    st.banner("Step2 -- BGP community configuration in DUT1 using ip prefix list and route-maps ")
    ipapi.config_access_list(topo['dut_list'][0], 'LOOPBACK', bgp_4node_data.network1, 'permit', seq_num="7")

    ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'SET_COMMUNITY', 'permit', '10', 'LOOPBACK')
    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10',community = '64984:0',metric=50)

    bgpapi.config_bgp(topo['dut_list'][0], local_as=bgp_4node_data.dut1_as, neighbor=topo['D3D1P1_ipv4'], config='yes', addr_family='ipv4', config_type_list=["routeMap"], routeMap='SET_COMMUNITY', diRection='out')

    output = st.exec_all([ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv4', neighbor=topo['D3D1P1_ipv4'], state='Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv4', neighbor=topo['D3D2P1_ipv4'], state = 'Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv4', neighbor=[topo['D2D3P1_ipv4'], topo['D1D3P1_ipv4'], topo['D4D3P1_ipv4']], state='Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][3], family='ipv4', neighbor=topo['D3D4P1_ipv4'], state = 'Established')])[0]
    if not all(output):
        err = st.error("Failed to form IPv4 eBGP peering")
        err_list.append(err)

    bgpapi.config_bgp_community_list(topo['dut_list'][2], community_type='standard', community_name='comm_test', action='permit', community_num='64984:0')
    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10',community = '64984:0 local-as')
    st.wait(30)
    st.banner("verifying  that the communities are added from the route for out-bound")
    n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2],route='172.16.2.2/32',community='64984:0 localAs')
    if not n2:
        st.error("failed to learn IPv4 route")
    else:
        prepend_as = n2[0]['community']
        if (prepend_as == '64984:0 localAs'):
            st.log("BGP community verification is successful")
        else:
            err = st.error("BGP community verification is failed")
            err_list.append(err)

    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10', delcommunity='local-as')
    st.wait(30)
    st.banner("verifying  that the sub set of communities removed or not")
    result1 = True
    n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route='172.16.2.2/32', community='64984:0')
    if not n2:
        st.error("failed to learn bgp route")
    else:
        prepend_as = n2[0]['community']
        if (prepend_as == '64984:0'):
            st.log("verifying that the sub set of BGP communities removed successful")
        else:
            err = st.error("verifying that the sub set of BGP communities remove failed")
            err_list.append(err)
            result1 = False
    if result1:
        st.banner("TC Pass: {}".format(test_case_id[0]))
        st.report_pass("test_case_id_passed", test_case_id[0])
    else:
        st.banner("TC Fail:  {}, {}".format(test_case_id[0], 'Community subset is not deleted'))
        st.report_fail("test_case_id_failed", test_case_id[0])

    st.banner("Applying route-map to a BGP neighbor in out bound direction")
    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10', community='none')
    st.wait(30)
    st.banner("verifying  that the communities are removed from the route for out-bound")
    n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2],route='172.16.2.2/32',community=' ')
    if n2:
        err = st.error("community attributes are not cleared using route-map community as none")
        err_list.append(err)
    else:
        st.log("BGP communities removed successfully with community none")

    st.banner("Applying route-map to a BGP neighbor in in bound direction")
    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10',community = '64984:0 local-as')
    ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY', sequence='10', community='none')
    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D1D3P1_ipv4'], config='yes', addr_family='ipv4', config_type_list=["routeMap"], routeMap='SET_COMMUNITY', diRection='in')
    st.wait(30)
    st.banner("verifying  that the communities are removed from the route for in-bound")
    n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2],route='172.16.2.2/32',community='64984:0 localAs')
    if n2:
        err = st.error("community attributes are not cleared using route-map community as none")
        err_list.append(err)
    else:
        st.log("BGP communities removed successfully with community none")

        ipapi.config_access_list(topo['dut_list'][1], 'LOOPBACK', topo['D2D1P1_ipv6'].split('::')[0] + "::/64",
                                 'permit', family='ipv6', seq_num="7")
        ipapi.config_route_map(topo['dut_list'][1], 'SET_COMMUNITY_1', sequence='10', community='64984:0 local-as',
                               metric=50)
        ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY_1', sequence='10', metric=50)

        bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=topo['D3D2P1_ipv6'],
                          config='yes', addr_family='ipv6', config_type_list=["routeMap", "redist"],
                          routeMap='SET_COMMUNITY_1', diRection='out', redistribute='connected')
        ipapi.config_route_map_match_ip_address(topo['dut_list'][2], 'SET_COMMUNITY_1', 'permit', '10', None,
                                                family='ipv6', community='comm_test')

        output = st.exec_all([ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer,
                                          topo['dut_list'][1], family='ipv6', neighbor=topo['D3D2P1_ipv6'],
                                          state='Established'),
                              ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer,
                                          topo['dut_list'][2], family='ipv6', neighbor=topo['D2D3P1_ipv6'],
                                          state='Established')])[0]
        if not all(output):
            err = st.error("Failed to form IPv6 eBGP peering")
            err_list.append(err)
        st.banner("verifying  that the communities are added from the v6 route for out-bound")
        n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route=topo['D2D1P1_ipv6'].split('::')[0] + "::/64",
                                         family='ipv6', community='64984:0 localAs')
        if not n2:
            st.error("failed to learn IPv6 route")
        else:
            prepend_as = n2[0]['community']
            if (prepend_as == '64984:0 localAs'):
                st.log("BGP community verification is successful fot v6")
            else:
                err = st.error("BGP community verification is failed for v6")
                err_list.append(err)
        st.banner("Applying route-map community none to BGP v6 routes in out bound direction")
        ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY_1', sequence='10', community='none')
        st.wait(30)
        st.banner("verifying  that the communities are removed from the route for out-bound")
        n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route=topo['D2D1P1_ipv6'].split('::')[0] + "::/64",
                                         family='ipv6', community=' ')
        if n2:
            err = st.error("community attributes are not cleared using route-map community as none")
            err_list.append(err)
        else:
            st.log("BGP communities removed successfully with community none")

        st.banner("Applying route-map to a BGP v6 route in in bound direction")
        ipapi.config_route_map(topo['dut_list'][1], 'SET_COMMUNITY', sequence='10', community='64984:0 local-as')
        ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY', sequence='10', community='none')
        bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D2D3P1_ipv6'],
                          config='yes', addr_family='ipv6', config_type_list=["routeMap"], routeMap='SET_COMMUNITY',
                          diRection='in')
        st.wait(30)
        st.banner("verifying  that the communities are removed from the v6 route for in-bound")
        n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route='172.16.2.2/32', community='64984:0 localAs')
        if n2:
            err = st.error("community attributes are not cleared using route-map community as none")
            err_list.append(err)
        else:
            st.log("BGP communities removed successfully with community none")

    if err_list:
        err = st.error("BGP community based as-path prepend verification is failed.")
        err_list.insert(0, err)

    st.report_result(err_list, first_only=True)

@pytest.fixture(scope="function")
def hooks_test_ft_bgp_ebgp_community_map():
    yield
    st.exec_all([[bgpapi.cleanup_router_bgp, topo['dut_list'][0]], [bgpapi.cleanup_router_bgp, topo['dut_list'][1]],
                 [bgpapi.cleanup_router_bgp, topo['dut_list'][2]], [bgpapi.cleanup_router_bgp, topo['dut_list'][3]]])
    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', config='no')
    ipapi.config_access_list(topo['dut_list'][0], 'LOOPBACK', "", mode="", config='no')
    bgpapi.config_bgp_community_list(topo['dut_list'][2], community_type='standard', community_name='comm_test', action='permit', community_num='64984:0', config='no')
    ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY_1', sequence='10', metric=50, config='no')

