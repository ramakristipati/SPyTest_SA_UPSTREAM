import pytest
import re

from spytest import st, tgapi, SpyTestDict

import apis.system.snmp as snmp_obj
import apis.system.basic as basic_obj
import apis.system.box_services as box_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.system.interface as intf_obj
from apis.system.connection import execute_command
from apis.system.connection import connect_to_device
import apis.system.reboot as reboot
import apis.system.logging as log_obj
import apis.system.in_memory as imlog_obj
import apis.security.user as user_api
import apis.routing.ip as ip_api

import utilities.utils as util_obj
from utilities.utils import ensure_service_params
from utilities.common import random_vlan_list

imlog_data = imlog_obj.imlog_data
data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def snmp_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1T1:2")
    initialize_variables()
    snmp_pre_config()
    vlan_preconfig()
    snmp_traffic_config()
    snmp_trap_pre_config()

    yield
    snmp_post_config()
    vlan_postconfig()
    snmp_trap_post_config()


@pytest.fixture(scope="function", autouse=True)
def snmp_func_hooks(request):
    global ipaddress
    ipaddress = st.get_mgmt_ip(vars.D1)
    yield


def initialize_variables():
    data.clear()
    data.ro_community = 'test_123'
    data.location = 'hyderabad'
    data.contact = "Admin"
    data.sysname = "Sonic_device"
    data.mgmt_int = 'eth0'
    data.wait_time = 30
    data.filter_cli = "-One"
    data.oid_sysName = '1.3.6.1.2.1.1.5.0'
    data.oid_syUpTime = '1.3.6.1.2.1.25.1.1.0'
    data.oid_sysLocation = '1.3.6.1.2.1.1.6.0'
    data.oid_sysDescr = '1.3.6.1.2.1.1.1.0'
    data.oid_sysContact = '1.3.6.1.2.1.1.4.0'
    data.oid_sysObjectId = '1.3.6.1.2.1.1.2.0'
    data.oid_mib_2 ='1.3.6.1.2.1'
    data.oid_if_mib_all = '1.3.6.1.2.1.31'
    data.oid_entity_mib_all = '1.3.6.1.2.1.47'
    data.oid_entity_sensor_mib = '1.3.6.1.2.1.99'
    data.oid_dot1q_mib = '1.3.6.1.2.1.17.7'
    data.oid_dot1db_mib = '1.3.6.1.2.1.17'
    data.oid_root_node_walk = '.'
    data.oid_IP_MIB_ipAddressRowStatus_ipv6='1.3.6.1.2.1.4.34.1.10.2'
    data.oid_IP_MIB_ipAddressStorageType_ipv6 = '1.3.6.1.2.1.4.34.1.11'
    data.oid_IP_MIB_ifDescr = '1.3.6.1.2.1.55.1.5.1.2'
    data.oid_IP_MIB_IfAdminStatus = '1.3.6.1.2.1.55.1.5.1.9'
    data.oid_IPV6_MIB_ipv6IpForwarding = '1.3.6.1.2.1.4.25.0'
    data.oid_IPV6_MIB_ipv6IpDefaultHopLimit = '1.3.6.1.2.1.4.26'
    data.oid_IPV6_MIB_ipv6ScopeZoneIndexTable = '1.3.6.1.2.1.4.36'
    data.oid_ipcidr_route_table = '1.3.6.1.2.1.4.24.4'
    data.oid_ip_fwd_table = '1.3.6.1.2.1.4.24.2'
    data.af_ipv4 = "ipv4"
    data.af_ipv6 = "ipv6"
    data.loopback_addr = '67.66.66.66'
    data.loopback0= 'Loopback0'
    data.oid_dot1d_Base = '1.3.6.1.2.1.17.1'
    data.oid_dot1d_Base_Bridge_Address = '1.3.6.1.2.1.17.1.1'
    data.oid_dot1d_Base_Num_Ports = '1.3.6.1.2.1.17.1.2'
    data.oid_dot1d_Base_Type = '1.3.6.1.2.1.17.1.3'
    data.oid_dot1d_Base_Port = '1.3.6.1.2.1.17.1.4.1.1'
    data.oid_dot1d_Base_PortIf_Index = '1.3.6.1.2.1.17.1.4.1.2'
    data.oid_dot1d_Base_Port_Delay_Exceeded_Discards = '1.3.6.1.2.1.17.1.4.1.4'
    data.oid_dot1d_Base_Port_Mtu_Exceeded_Discards = '1.3.6.1.2.1.17.1.4.1.5'
    data.oid_dot1d_Tp_Aging_Time = '1.3.6.1.2.1.17.4.2'
    data.oid_dot1q_Vlan_Version_Number = '1.3.6.1.2.1.17.7.1.1.1'
    data.oid_dot1q_Max_VlanId = '1.3.6.1.2.1.17.7.1.1.2'
    data.oid_dot1q_Max_Supported_Vlans = '1.3.6.1.2.1.17.7.1.1.3'
    data.oid_dot1q_Num_Vlans = '1.3.6.1.2.1.17.7.1.1.4'
    data.oid_dot1q_Vlan_Num_Deletes = '1.3.6.1.2.1.17.7.1.4.1'
    data.oid_dot1q_Fdb_Dynamic_Count = '1.3.6.1.2.1.17.7.1.2.1.1.2'
    data.oid_dot1q_Tp_Fdb_Address = '1.3.6.1.2.1.17.7.1.2.2.1.1'
    data.oid_dot1q_Tp_Fdb_Port = '1.3.6.1.2.1.17.7.1.2.2.1.2'
    data.oid_dot1q_Tp_Fdb_Status = '1.3.6.1.2.1.17.7.1.2.2.1.3'
    data.oid_dot1q_Vlan_Index = '1.3.6.1.2.1.17.7.1.4.2.1.2'
    data.oid_dot1q_Vlan_Current_Egress_Ports = '1.3.6.1.2.1.17.7.1.4.2.1.4'
    data.oid_dot1q_Vlan_Current_Untagged_Ports = '1.3.6.1.2.1.17.7.1.4.2.1.5'
    data.oid_dot1q_Vlan_Static_Name = '1.3.6.1.2.1.17.7.1.4.3.1.1'
    data.oid_dot1q_Vlan_Static_Egress_Ports = '1.3.6.1.2.1.17.7.1.4.3.1.2'
    data.oid_dot1q_Vlan_Static_Untagged_Ports = '1.3.6.1.2.1.17.7.1.4.3.1.4'
    data.oid_dot1q_Vlan_Static_Row_Status = '1.3.6.1.2.1.17.7.1.4.3.1.5'
    data.oid_dot1q_Pvid = '1.3.6.1.2.1.17.7.1.4.5.1.1'
    data.source_mac = "00:0a:01:00:00:01"
    data.source_mac1 = "00:0a:02:00:00:01"
    data.vlan = str(random_vlan_list()[0])
    data.dot1q_Vlan_Static_Table = '1.3.6.1.2.1.17.7.1.4.3'
    data.dot1q_Vlan_Current_Table = '1.3.6.1.2.1.17.7.1.4.2'
    data.dot1q_Tp_Fdb_Table = '1.3.6.1.2.1.17.7.1.2.2'
    data.dot1q_Fdb_Table = '1.3.6.1.2.1.17.7.1.2.1'
    data.nsNotifyShutdown='8072.4.0.2'
    data.filter = '-Oqv'
    data.brcmSonicConfigChange = '2.1.2.0.1'
    data.oid_ifx_table = '1.3.6.1.2.1.31.1.1'
    data.oid_ip_System_Stats_Table = '1.3.6.1.2.1.4.31.1'
    data.oid_ip_IfStats_Table = '1.3.6.1.2.1.4.31.3'
    data.oid_ip_Address_Table = '1.3.6.1.2.1.4.34'
    data.oid_ip_NetToPhysical_Table = '1.3.6.1.2.1.4.35'
    data.oid_icmp_Msgs = '1.3.6.1.2.1.5'
    data.oid_tcp_mib = '1.3.6.1.2.1.6'
    data.oid_udp_mib = '1.3.6.1.2.1.7'
    data.oid_snmpv2_mib = '1.3.6.1.2.1.11'
    data.oid_host_resource_mib = '1.3.6.1.2.1.25'
    data.oid_framework_mib = '1.3.6.1.6.3.10'
    data.oid_mpd_mib = '1.3.6.1.6.3.11'
    data.oid_target_mib = '1.3.6.1.6.3.12'
    data.oid_notification_mib = '1.3.6.1.6.3.13'
    data.oid_user_based_sm_mib = '1.3.6.1.6.3.15'
    data.oid_view_based_acm_mib = '1.3.6.1.6.3.16'
    data.oid_ent_physical_table = '1.3.6.1.2.1.47.1.1.1'
    data.oid_ent_phy_sensor_table = '1.3.6.1.2.1.99.1.1'
    data.oid_dot3_stats_table = '1.3.6.1.2.1.10.7.2'
    data.oid_net_snmp_agent_mib = '1.3.6.1.4.1.8072.1'
    data.oid_net_snmp_vacm_mib = '1.3.6.1.4.1.8072.1.9'
    data.oid_ucd_diskio_mib = '1.3.6.1.4.1.2021.13.15'
    data.oid_ucd_memory = '1.3.6.1.4.1.2021.4'
    data.oid_ucd_la_table = '1.3.6.1.4.1.2021.10'
    data.oid_ucd_system_stats = '1.3.6.1.4.1.2021.11'
    data.oid_serial_no = '1.3.6.1.4.1.674.10895.3000.1.2.100.8.1.2.1'
    data.oid_service_tag = '1.3.6.1.4.1.674.10895.3000.1.2.100.8.1.4.1'
    data.user_key='Broadcom@123$'
    data.auth_type = 'md5'
    data.user_name = 'broadcom'
    data.group_name = 'broadcom'
    data.user_pwd = 'Broadcom@123$'
    data.ip6_addr = "5551::1"
    data.vlan_name = "Vlan"+str(data.vlan)
    data.vlan_ip = "192.168.10.2"
    data.oid_if_name = '1.3.6.1.2.1.31.1.1.1.1'
    data.oid_if_high_speed = '1.3.6.1.2.1.31.1.1.1.15'

def snmp_pre_config():
    """
    SNMP pre config
    """
    global ipaddress
    ipaddress_list = basic_obj.get_ifconfig_inet(vars.D1, data.mgmt_int)
    st.log("Checking Ip address of the Device ")
    if not ipaddress_list:
        st.report_env_fail("ip_verification_fail")
    ipaddress = ipaddress_list[0]
    st.log("Device ip addresse - {}".format(ipaddress))
    snmp_obj.set_snmp_config(vars.D1, snmp_rocommunity= data.ro_community, snmp_location=data.location)
    ip_api.configure_loopback(vars.D1, loopback_name=data.loopback0, config="yes")
    ip_api.config_ip_addr_interface(vars.D1, data.loopback0, data.loopback_addr, 32, family=data.af_ipv4)
    if not ip_api.ping(vars.D1, ipaddress, family='ipv4', external=True):
        st.error("Ping reachability is failed between SNMP server and Device.")
    if not snmp_obj.poll_for_snmp(vars.D1, data.wait_time, 1, ipaddress=ipaddress,
                                  oid=data.oid_sysName, community_name=data.ro_community):
        st.log("Post SNMP config , snmp is not working")
        st.report_fail("operation_failed")

def vlan_preconfig():
    if not vlan_obj.create_vlan(vars.D1, data.vlan):
        st.report_fail("vlan_create_fail", data.vlan)
    mac_obj.config_mac(vars.D1, data.source_mac, data.vlan, vars.D1T1P1)
    st.log("Adding TGen-1 connected interface to newly created vlan in un tagging mode.")
    if not vlan_obj.add_vlan_member(vars.D1, data.vlan, vars.D1T1P1, tagging_mode=False):
            st.report_fail("vlan_untagged_member_fail", vars.D1T1P1, data.vlan)
    st.log("Adding TGen-2 connected interface to newly created vlan in tagging mode.")
    if not vlan_obj.add_vlan_member(vars.D1, data.vlan, vars.D1T1P2, tagging_mode=True):
            st.report_fail("vlan_untagged_member_fail", vars.D1T1P2, data.vlan)


def snmp_traffic_config():
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    data.streams = {}
    stream = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create',
                                  transmit_mode='continuous', length_mode='fixed', rate_pps=100, frame_size=72,
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, mac_src='00:0a:01:00:00:01',
                                  mac_src_step='00:00:00:00:00:01', mac_src_mode='increment', mac_src_count=10,
                                  mac_dst='00:0a:12:00:00:01', vlan="enable")
    data.streams['stream1'] = stream['stream_id']
    stream = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], mode='create',
                                  transmit_mode='continuous', length_mode='fixed', rate_pps=10,
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, mac_src='00:0a:12:00:00:01',
                                  mac_dst='00:0a:01:00:00:01', vlan="enable")
    data.streams['stream2'] = stream['stream_id']
    intf_obj.clear_interface_counters(vars.D1)
    tg.tg_traffic_control(action='run', stream_handle=[data.streams['stream1'], data.streams['stream2']])
    st.wait(2)
    total_mac_learnt=mac_obj.get_mac(vars.D1)
    st.log("Toal number of mac addreses present are {}" .format(total_mac_learnt))


def snmp_trap_pre_config():
    global capture_file, ssh_conn_obj
    ip = ensure_service_params(vars.D1, "snmptrap", "ip")
    username = ensure_service_params(vars.D1, "snmptrap", "username")
    password = ensure_service_params(vars.D1, "snmptrap", "password")
    path = ensure_service_params(vars.D1, "snmptrap", "path")

    # Connect to the linux machine and check

    ssh_conn_obj = connect_to_device(ip, username, password)
    if not ssh_conn_obj:
        st.report_fail("ssh_connection_failed", ip)

    # enable traps on DUT
    snmp_obj.config_snmp_trap(vars.D1, version=2, ip_addr=ip, community= data.ro_community)

    # start capture on the linux machine
    capture_file = path


def snmp_post_config():
    """
    SNMP post config
    """
    snmp_obj.restore_snmp_config(vars.D1)
    ip_api.configure_loopback(vars.D1, loopback_name=data.loopback0, config="no")


def vlan_postconfig():
    mac_obj.clear_mac(vars.D1, port=vars.D1T1P1, vlan=data.vlan)
    vlan_obj.delete_vlan_member(vars.D1, data.vlan, [vars.D1T1P1], tagging_mode=False)
    vlan_obj.delete_vlan_member(vars.D1, data.vlan, [vars.D1T1P2], tagging_mode=True)
    vlan_obj.delete_vlan(vars.D1, data.vlan)


def snmp_trap_post_config():
    snmp_obj.config_snmp_trap(vars.D1, version=2, ip_addr=None, no_form=True)
    snmp_obj.clear_snmp_trapd_logs(vars.D1, ssh_conn_obj)


def device_eth0_ip_addr():
    """
    To get the ip address of device after reboot.
    """
    ipaddress = st.get_mgmt_ip(vars.D1)
    st.log("Device ip address - {}".format(ipaddress))
    if not ip_api.ping(vars.D1, ipaddress, family='ipv4', external=True):
        st.error("Ping reachability is failed between SNMP server and Device.")


@pytest.mark.snmp_sysName
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_snmp_sysName'])
def test_ft_snmp_sysName():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysName MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.log("Ensuring minimum topology")
    hostname = basic_obj.get_hostname(vars.D1)
    get_snmp_output= snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysName,
                                                 community_name=data.ro_community)
    st.log("hostname Device('{}') and SNMP('{}')".format(hostname, get_snmp_output[0]))
    if not get_snmp_output[0] == hostname:
        st.report_fail("sysName_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_sysUpTime
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_snmp_test_syUpTime'])
def test_ft_snmp_test_syUpTime():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysUpTime MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.log("Ensuring minimum topology")
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_syUpTime,
                                                  community_name=data.ro_community)
    uptime_cli_sec = box_obj.get_system_uptime_in_seconds(vars.D1)
    days, hours,minutes, seconds = re.findall(r"(\d+):(\d+):(\d+):(\d+).\d+", get_snmp_output[0])[0]
    get_snmp_output = util_obj.convert_time_to_seconds(days, hours,minutes, seconds)
    st.log("Up time value from DUT is :{} & get_snmp_output value is :{} &"
           " get_snmp_output tolerance value is : {}"
           .format(uptime_cli_sec, get_snmp_output, get_snmp_output + 3))
    if not (get_snmp_output >= uptime_cli_sec or get_snmp_output+3 >= uptime_cli_sec):
        st.report_fail("sysUptime_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_sysLocation
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_snmp_sysLocation'])
def test_ft_snmp_sysLocation():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysLocation MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    location_output = snmp_obj.get_snmp_config(vars.D1)[0]["snmp_location"]
    st.log("System Location from the device is : {} ".format(location_output))
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress,
                                                  oid=data.oid_sysLocation, community_name=data.ro_community)
    st.log("System Location from the SNMP output: {} ".format(get_snmp_output[0]))
    if not get_snmp_output[0] == location_output:
        st.log(" Up time is not matching between device sysuptime and snmp uptime ")
        st.report_fail("sysLocation_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_sysDescr
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_snmp_sysDescr'])
def test_ft_snmp_sysDescr():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysDescr MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    result = dict()
    descrip_output= basic_obj.show_version(vars.D1)['version'].strip("'")
    hwsku = basic_obj.get_hwsku(vars.D1)
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysDescr,
                                                  community_name=data.ro_community)
    st.log("SNMP GET output: {}".format(get_snmp_output))
    get_snmp_output = get_snmp_output[0]
    get_snmp_output=get_snmp_output.split(" - ")
    for entry in get_snmp_output:
        key, value = entry.split(":")
        if 'version' in key.lower():
            result['version'] = value.strip(" SONiC.")
        elif 'hwsku' in key.lower():
            result['hwsku'] = value.strip()
        elif 'distribution' in key.lower():
            result['distribution'] = value.strip()
        elif 'kernel' in key.lower():
            result['kernel'] = value.lower()
    if not (hwsku == result['hwsku'] and result['version'] in descrip_output):
        st.log("SNMP GET Output after processing is: {}".format(result))
        st.log("Version output is: {}".format(descrip_output))
        st.log("hwsku: {}".format(hwsku))
        st.report_fail("sysDescr_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_sysContact
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_snmp_sysContact'])
def test_ft_snmp_sysContact():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysContact MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    contact_output = ""
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysContact,
                                                  community_name=data.ro_community)
    get_snmp_output = get_snmp_output[0]
    st.log("System Contact from the SNMP output: {} ".format(get_snmp_output))
    st.log("System Contact from the DUT output: {} ".format(contact_output))
    if not contact_output == get_snmp_output:
        st.log(" Contact  is not matching between device Contact and snmp Contact ")
        st.report_fail("sysContact_verification_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_mib_2
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn008'])
def test_ft_snmp_mib_2():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on mib_2 MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_mib_2,
                                                   community_name=data.ro_community, timeout=60, retry=2)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_if_mib_all
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn009'])
def test_ft_snmp_if_mib_all():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on if_mib_all MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_if_mib_all,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("Fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_entity_mib_all
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn010'])
def test_ft_snmp_entity_mib_all():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on entity_mib_all MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_entity_mib_all,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_entity_sensor
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn011'])
def test_ft_snmp_entity_sensor_mib():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on entity_sensor_mib MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    if not snmp_obj.verify_trans_info(vars.D1):
        st.report_unsupported("msg","As DB does not have sensor entries, it is unsupported")
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_entity_sensor_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_dot1q_dot1db
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn012'])
@pytest.mark.inventory(testcases=['FtOpSoSySnFn013'])
def test_ft_snmp_dot1q_dot1db_mib():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on dot1q MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    snmp_obj.poll_for_snmp_walk(vars.D1, data.wait_time, 3, ipaddress=ipaddress,
                           oid=data.oid_dot1q_mib, community_name=data.ro_community)
    get_snmp_output_dot1q = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output_dot1q:
        st.report_fail("get_snmp_output_fail")
    get_snmp_output_dot1db = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1db_mib,
                                                   community_name=data.ro_community)
    if not get_snmp_output_dot1db:
        st.report_fail("get_snmp_output_fail")

    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_root_node_walk
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn015'])
def test_ft_snmp_root_node_walk():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on entity_sensor_mib MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """

    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_root_node_walk,
                                                  community_name=data.ro_community, timeout=60, retry=3)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_md5_snmpd_conf
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn047'])
def test_ft_snmp_md5_snmpd_conf():
    st.log("Verify md5sum of snmpd.conf")
    md5_before = st.config(vars.D1, 'docker exec -ti snmp md5sum /etc/snmp/snmpd.conf')
    md5_before = md5_before.rstrip('\n')
    st.log("md5_before = [%s]" % md5_before)
    st.config(vars.D1, 'snmp-server contact "Sonic"', type="klish", skip_tmpl=True, skip_error_check=True)
    st.wait(10)
    md5_after = st.config(vars.D1, 'docker exec -ti snmp md5sum /etc/snmp/snmpd.conf')
    md5_after = md5_after.rstrip('\n')
    st.log("md5_after = [%s]" % md5_after)
    st.config(vars.D1,'no snmp-server contact' , type="klish", skip_tmpl=True, skip_error_check=True)
    if md5_before == md5_after:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_ipAddressRowStatus_ipv6
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn016'])
def test_ft_snmp_ipAddressRowStatus_ipv6():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on IP-MIB::ipAddressRowStatus.ipv6 MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    ip_api.config_ip_addr_interface(vars.D1, data.loopback0, data.ip6_addr, "128", family=data.af_ipv6)
    st.wait(2, "waiting for configured route to install")
    ip_api.get_interface_ip_address(vars.D1, family=data.af_ipv6)

    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IP_MIB_ipAddressRowStatus_ipv6,
                                                  community_name=data.ro_community, timeout=6, retry=0)

    ip_api.delete_ip_interface(vars.D1, data.loopback0, data.ip6_addr, "128", family=data.af_ipv6)

    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipAddressStorageType_ipv6
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn017'])
def test_ft_snmp_ipAddressStorageType_ipv6():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on IP-MIB::ipAddressStorageType.ipv6 MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IP_MIB_ipAddressStorageType_ipv6,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipv6IpForwarding_and_DefaultHopLimit
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn020'])
def test_ft_snmp_ipv6_If_Forward_default_HopLimit():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on  ipv6IpForwarding and ipv6IpDefaultHopLimit MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IPV6_MIB_ipv6IpForwarding,
                                                  community_name=data.ro_community)
    get_snmp_output_1 = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IPV6_MIB_ipv6IpDefaultHopLimit,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    if not get_snmp_output_1:
        st.report_fail("get_snmp_output_fail")

    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipv6IpForwarding_and_DefaultHopLimit
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn021'])
def test_ft_snmp_ipv6scope_index_table():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on ipv6ScopeZoneIndexTable MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IPV6_MIB_ipv6ScopeZoneIndexTable,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipcidrroutetable
@pytest.mark.community_unsupported
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn014'])
def test_ft_snmp_ipcidr_route_table():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk walk on ipCidrroutetable MIB functions properly
    Reference Test Bed : D1 --- Mgmt Network
    """
    snmp_obj.poll_for_snmp_walk(vars.D1, data.wait_time,3, ipaddress=ipaddress,
                                oid=data.oid_ipcidr_route_table, community_name=data.ro_community)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ipcidr_route_table,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_ipcidrroutetable
@pytest.mark.community_unsupported
@pytest.mark.inventory(feature='Regression', release='Cyrus4.0.0')
@pytest.mark.inventory(testcases=['test_snmp_ip_forward_table'])
def test_ft_snmp_ip_forward_table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that snmpwalk walk on ipForwardTable MIB functions properly
    Reference Test Bed : D1 --- Mgmt Network
    """
    snmp_obj.config_agentx(vars.D1)
    snmp_obj.poll_for_snmp_walk(vars.D1, data.wait_time,3, ipaddress=ipaddress,
                                oid=data.oid_ip_fwd_table, community_name=data.ro_community)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ip_fwd_table,
                                                   community_name=data.ro_community, timeout=2, retry=1, filter=data.filter)
    snmp_obj.config_agentx(vars.D1, config='no')
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ifXTable'])
def test_ft_snmp_ifx_table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for ifXTable Object gives list of interface entries on the switch.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ifx_table,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ip_System_Stats_Table'])
def test_ft_snmp_ip_System_Stats_Table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for ipSystemStatsTable Object gives the table containing system wide, IP version specific traffic statistics.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ip_System_Stats_Table,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ip_IfStats_Table'])
def test_ft_snmp_ip_IfStats_Table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for ipIfStatsTable Object gives the table containing per-interface traffic statistics.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ip_IfStats_Table,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ip_Address_Table'])
def test_ft_snmp_ip_Address_Table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for ipAddressTable Object gives table contains addressing information relevant to the entity's interfaces.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ip_Address_Table,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ip_NetToPhysical_Table'])
def test_ft_snmp_ip_NetToPhysical_Table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for ipNetToPhysicalTable Object gives each entry contains one IP address to physical address equivalence.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ip_NetToPhysical_Table,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_icmp_Msgs'])
def test_ft_snmp_icmp_Msgs():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for icmpMsgs Object gives Internet Control Message Protocol related information.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_icmp_Msgs,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_tcp_mib'])
def test_ft_snmp_tcp_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for TCP-MIB Object gives Transmission Control Protocol related information.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_tcp_mib,
                                                  community_name=data.ro_community, timeout=60, retry=2)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_udp_mib'])
def test_ft_snmp_udp_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for UDP-MIB Object gives User Datagram Protocol related information.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_udp_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_snmpv2_mib'])
def test_ft_snmp_snmpv2_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for SNMPv2-MIB Object gives system SNMP variables.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_snmpv2_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_host_resource_mib'])
def test_ft_snmp_host_resource_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for HOST-RESOURCES-MIB Object gives a uniform set of objects useful for the management of host computers.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_host_resource_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_framework_mib'])
def test_ft_snmp_framework_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for SNMP-FRAMEWORK-MIB Object gives The SNMP Management Architecture information.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_framework_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_mpd_mib'])
def test_ft_snmp_mpd_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for SNMP-MPD-MIB Object gives the compliance statement for SNMP entities which implement the SNMP-MPD-MIB.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_mpd_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_target_mib'])
def test_ft_snmp_target_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for SNMP-TARGET-MIB Object it defines MIB objects which provide mechanisms to remotely configure the parameters.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_target_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_notification_mib'])
def test_ft_snmp_notification_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for SNMP-NOTIFICATION-MIB Object defines MIB objects which provide mechanisms to remotely configure the parameters.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_notification_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_user_based_sm_mib'])
def test_ft_snmp_user_based_sm_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for SNMP-USER-BASED-SM-MIB Object gives the management information definitions for the SNMP User-based Security Model.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_user_based_sm_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_view_based_acm_mib'])
def test_ft_snmp_view_based_acm_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for SNMP-VIEW-BASED-ACM-MIB Object gives the management information definitions for the View-based Access Control Model for SNMP.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_view_based_acm_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ent_physical_table'])
def test_ft_snmp_ent_physical_table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for entPhysicalTableObject gives the Information about a particular physical entity.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ent_physical_table,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ent_phy_sensor_table'])
def test_ft_snmp_ent_phy_sensor_table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for entPhySensorTable gives The type of data returned by the associated entPhySensorValue object.
    Reference Test Bed : D1 --- Mgmt Network
    """
    if not snmp_obj.verify_trans_info(vars.D1):
        st.report_unsupported("msg","As DB does not have sensor entries, it is unsupported")
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ent_phy_sensor_table,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_dot3_stats_table'])
def test_ft_snmp_dot3_stats_table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify snmpwalk for dot3StatsTable gives Statistics for a collection of ethernet-like interfaces attached to a particular system.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot3_stats_table,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_net_snmp_agent_mib'])
def test_ft_net_snmp_agent_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify snmpwalk for NET-SNMP-AGENT-MIB is successfull.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_net_snmp_agent_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_net_snmp_vacm_mib'])
def test_ft_net_snmp_vacm_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify snmpwalk for NET-SNMP-VACM-MIB defines Net-SNMP extensions to the standard VACM view table.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_net_snmp_vacm_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ucd_diskio_mib'])
def test_ft_snmp_ucd_diskio_mib():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify snmpwalk for UCD-DISKIO-MIB defines objects for disk IO statistics.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ucd_diskio_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ucd_memory'])
def test_ft_snmp_ucd_memory():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify snmpwalk for UCD-MEMORY-MIB it gives Memory Statistics.
    Reference Test Bed : D1 --- Mgmt Network
    """
    res = dict()
    report_flag=0
    get_snmp_output = snmp_obj.walk_snmp_operation(filter='-On',ipaddress=ipaddress, oid=data.oid_ucd_memory,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.log("snmp_output = {}".format(get_snmp_output))
    output=basic_obj.get_free_output(vars.D1)
    st.log("DUT Cli output = {}".format(output))
    for val in get_snmp_output:
        out = re.findall(r"3.6.1.4.1.2021.(4.5|4.6|4.11|4.100).0 = INTEGER: (\d+)", val)
        if out:
            for i in out:
                res[i[0]] = i[1]
    st.log("SNMP memory values are = {}".format(res))
    for val in output:
        if int(val['total']) != int(res['4.5']):
            st.log('Total memory values is not as expected ')
            report_flag+=1
        if not abs(int(val['available']))-abs(int(res['4.6'])) < 0.01*int(val['available']):
            st.log('Avaliable memory values is not as expected ')
            report_flag+=1
        if not abs(int(val['free']))-abs(int(res['4.11'])) < 0.01*int(val['free']):
            st.log('Free memory values is not as expected ')
            report_flag+=1
    if report_flag==0:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("get_snmp_output_fail")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ucd_la_table'])
def test_ft_snmp_ucd_la_table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify snmpwalk for UCD-LaTable-MIB it gives the 1,5 and 15 minute load averages.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ucd_la_table,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_new
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_ucd_system_stats'])
def test_ft_snmp_ucd_system_stats():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify snmpwalk for UCD-SystemStats-MIB it gives the CPU related information.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ucd_system_stats,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPBr001'])
def test_ft_snmp_dot1d_base_bridge_address():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBaseBridgeAddress Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1d_Base_Bridge_Address,
                                                   community_name=data.ro_community)
    mac_address = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    if not str(mac_address) in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1dBaseBridgeAddress")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPBr002'])
def test_ft_snmp_dot1d_base_num_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBaseNumPorts Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1d_Base_Num_Ports,
                                                   community_name=data.ro_community,filter=data.filter)
    if str(2) not in get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBaseNumPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPBr003'])
def test_ft_snmp_dot1d_base_type():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBaseType Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1d_Base_Type,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBaseType")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPBr004'])
def test_ft_snmp_dot1d_base_port():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBasePort Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Base_Port,
                                                   community_name=data.ro_community,filter=data.filter)
    intf_name1=util_obj.get_interface_number_from_name(st.get_other_names(vars.D1, [vars.D1T1P1])[0]) if '/' in vars.D1T1P1 else util_obj.get_interface_number_from_name(vars.D1T1P1)
    intf_name2=util_obj.get_interface_number_from_name(st.get_other_names(vars.D1, [vars.D1T1P2])[0]) if '/' in vars.D1T1P2 else util_obj.get_interface_number_from_name(vars.D1T1P2)
    if (intf_name1.get('number') not in str(get_snmp_output)) and (intf_name2.get('number') not in str(get_snmp_output)):
        st.report_fail("snmp_output_failed", "dot1dBasePort")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPBr005'])
def test_ft_snmp_dot1d_base_port_ifindex():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBasePortIfIndex Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Base_PortIf_Index,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBasePortIfIndex")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPBr006'])
def test_ft_snmp_dot1d_base_port_delay_exceeded_discards():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBasePortDelayExceededDiscards Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Base_Port_Delay_Exceeded_Discards,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBasePortDelayExceededDiscards")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPBr007'])
def test_ft_snmp_dot1d_base_port_mtu_exceeded_discards():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBasePortMtuExceededDiscards Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Base_Port_Mtu_Exceeded_Discards,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBasePortMtuExceededDiscards")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPBr008'])
def test_ft_snmp_dot1d_tp_aging_time():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dTpAgingTime Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Tp_Aging_Time,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dTpAgingTime")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr001'])
def test_ft_snmp_dot1q_fdb_dynamic_count():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qFdbDynamicCount Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    count = mac_obj.get_mac_count(vars.D1)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1q_Fdb_Dynamic_Count,
                                                   community_name=data.ro_community)

    if str(count-1) not in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1qFdbDynamicCount")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr003'])
def test_ft_snmp_dot1q_tp_fdb_port():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qTpFdbPort Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1q_Tp_Fdb_Port,
                                                   community_name=data.ro_community, filter=data.filter)
    mac_obj.get_mac(vars.D1)
    intf_name=util_obj.get_interface_number_from_name(st.get_other_names(vars.D1, [vars.D1T1P2])[0]) if '/' in vars.D1T1P2 else util_obj.get_interface_number_from_name(vars.D1T1P2)

    st.log('FDB interface CLI output is {}' .format(int(intf_name.get('number'))))
    st.log('FDB interface SNMP output is {}' .format(int(get_snmp_output[-1])))

    if int(intf_name.get('number'))+1 != int(get_snmp_output[-1]):
        st.report_fail("snmp_output_failed", "dot1qTpFdbPort")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr004'])
def test_ft_snmp_dot1q_tp_fdb_status():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qTpFdbStatus Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1q_Tp_Fdb_Status,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qTpFdbStatus")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr006'])
def test_ft_snmp_dot1q_vlan_current_egress_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanCurrentEgressPorts Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1q_Vlan_Current_Egress_Ports,
                                                   community_name=data.ro_community, filter=data.filter)
    k=get_snmp_output[0][1:-1].split(" ")
    flag=0
    for i in range(len(k)):
      if str(k[i]) != '00':
        flag+=1
    if not flag:
        st.report_fail("snmp_output_failed", "dot1qVlanCurrentEgressPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr007'])
def test_ft_snmp_dot1q_vlan_current_untagged_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanCurrentUntaggedPorts Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=  data.oid_dot1q_Vlan_Current_Untagged_Ports,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanCurrentUntaggedPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr010'])
def test_ft_snmp_dot1q_vlan_static_untagged_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanStaticUntaggedPorts Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=  data.oid_dot1q_Vlan_Static_Untagged_Ports,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanStaticUntaggedPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr011'])
def test_ft_snmp_dot1q_vlan_static_row_status():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanStaticRowStatus Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=   data.oid_dot1q_Vlan_Static_Row_Status,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanStaticRowStatus")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr012'])
def test_ft_snmp_dot1q_pvid():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qPvid Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=   data.oid_dot1q_Pvid,
                                                   community_name=data.ro_community,filter=data.filter)
    if str(data.vlan) not in str(get_snmp_output):
        st.report_fail("snmp_output_failed", "dot1qPvid")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr008'])
def test_ft_snmp_dot1q_vlan_static_name():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanStaticName Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Vlan_Static_Name,
                                                   community_name=data.ro_community,filter=data.filter)
    if data.vlan not in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1qVlanStaticName")
    st.report_pass("test_case_passed")


@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr009'])
def test_ft_snmp_dot1q_vlan_static_egress_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanStaticEgressPorts Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Vlan_Static_Egress_Ports,
                                                   community_name=data.ro_community,filter=data.filter)
    k = get_snmp_output[0][1:-1].split(" ")
    flag = 0
    for i in range(len(k)):
        if str(k[i]) != '00':
            flag += 1
    if not flag:
        st.report_fail("snmp_output_failed", "dot1qVlanStaticEgressPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_dot1q_scale_and_performance
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr013'])
def test_ft_snmp_dot1q_vlan_version_number():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanVersionNumber Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Vlan_Version_Number,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanVersionNumber")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_scale_and_performance
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr014'])
def test_ft_snmp_dot1q_max_vlanid():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qMaxVlanId Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Max_VlanId,
                                                   community_name=data.ro_community,filter=data.filter)
    if st.get_datastore(vars.D1, "constants","default")['MAX_VLAN_ID'] not in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1qMaxVlanId")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_scale_and_performance
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr015'])
def test_ft_snmp_dot1q_max_supported_vlans():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qMaxSupportedVlans Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Max_Supported_Vlans,
                                                   community_name=data.ro_community,filter=data.filter)
    if st.get_datastore(vars.D1, "constants", "default")['MAX_SUPPORTED_VLANS'] not in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1qMaxSupportedVlans")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_scale_and_performance
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr016'])
def test_ft_snmp_dot1q_num_vlans():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qNumVlans Object functions properly.
    """
    count=vlan_obj.get_vlan_count(vars.D1)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Num_Vlans,
                                                   community_name=data.ro_community,filter=data.filter)
    if str(count) not in get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qNumVlans")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_scale_and_performance
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr017'])
def test_ft_snmp_dot1q_vlan_num_deletes():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanNumDeletes Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Vlan_Num_Deletes,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanNumDeletes")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr019'])
def test_ft_snmp_vlan_static_table():
   """
   Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
   Verify that the dot1qVlanStaticEntry Object functions properly.
   """
   get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.dot1q_Vlan_Static_Table,
                                                       community_name=data.ro_community)
   out = snmp_obj.get_oids_from_walk_output(get_snmp_output)
   out = [str(x) for x in out]
   for x in out:
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                          community_name=data.ro_community)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qVlanStaticTable")
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                         community_name=data.ro_community,get_next=True)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qVlanStaticTable")
   st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr005'])
def test_ft_snmp_dot1q_vlan_index():
   """
   Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
   Verify that the dot1qVlanIndex Object functions properly.
   """
   get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.dot1q_Vlan_Current_Table,
                                                       community_name=data.ro_community)
   out = snmp_obj.get_oids_from_walk_output(get_snmp_output)
   out = [str(x) for x in out]
   for x in out:
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                          community_name=data.ro_community)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qVlanIndex")
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                         community_name=data.ro_community,get_next=True)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qVlanIndex")
   st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr002'])
def test_ft_snmp_dot1q_tp_fdb_address():
   """
   Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
   Verify that the dot1qTpFdbAddress Object functions properly.
   """
   snmp_obj.poll_for_snmp_walk(vars.D1, data.wait_time,1, ipaddress=ipaddress,
                               oid=data.dot1q_Tp_Fdb_Table, community_name=data.ro_community)
   get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.dot1q_Tp_Fdb_Table,
                                                       community_name=data.ro_community)
   out = snmp_obj.get_oids_from_walk_output(get_snmp_output)
   out = [str(x) for x in out]
   for x in out:
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                          community_name=data.ro_community)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qTpFdbAddress")
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                         community_name=data.ro_community,get_next=True)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qTpFdbAddress")
   st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPQBr018'])
def test_ft_snmp_dot1q_fdb_table():
   """
   Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
   Verify that the dot1qFdbEntry Object functions properly.
   """
   get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.dot1q_Fdb_Table,
                                                       community_name=data.ro_community)
   out = snmp_obj.get_oids_from_walk_output(get_snmp_output)
   out = [str(x) for x in out]
   for x in out:
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                          community_name=data.ro_community)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qFdbTable")
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                         community_name=data.ro_community,get_next=True)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qFdbTable")
   st.report_pass("test_case_passed")

@pytest.mark.snmp_trap
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPTrap002'])
@pytest.mark.inventory(release='Buzznik+', testcases=['SNMPTrap006'])
def test_ft_snmp_link_down_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when a link is down.
    """
    snmp_obj.ensure_snmp_trapd(vars.D1, ssh_conn_obj)
    snmp_obj.clear_snmp_trapd_logs(vars.D1, ssh_conn_obj)

    # trigger trap on DUT
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    #checking device IP
    device_eth0_ip_addr()

    # get data from capture
    result1 = 0
    for _ in range(0, 6):
        st.wait(10)
        read_cmd = "cat {}".format(capture_file)
        output = execute_command(ssh_conn_obj, read_cmd)
        trap_lines = output.split("\n")[:-1]
        result1 = any(data.brcmSonicConfigChange in x for x in trap_lines)
        if result1 == 1:
            break

    st.banner('Verifying trap generation of linkUp and brcmSonicConfigChange')
    if not result1:
        st.report_tc_fail("SNMPTrap006", "snmptrap_not_generated", "brcmSonicConfigChange")
    else:
        st.report_tc_pass("SNMPTrap006", "snmptrap_generated", "brcmSonicConfigChange")

    result2 = any('linkDown' in x for x in trap_lines)
    if not result2:
        st.report_fail('test_case_failed')
    else:
        st.report_pass('test_case_passed')

@pytest.mark.snmp_trap
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPTrap001'])
def test_ft_snmp_link_up_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when a link is UP.
    """
    snmp_obj.ensure_snmp_trapd(vars.D1, ssh_conn_obj)

    # trigger trap on DUT
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)

    # get data from capture
    read_cmd = "cat {}".format(capture_file)

    output = execute_command(ssh_conn_obj, read_cmd)
    trap_lines = output.split("\n")[:-1]

    result = any('linkUp' in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmp_output_failed", "linkUp")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.snmp_trap
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPTrap004'])
@pytest.mark.inventory(feature='In-Memory Debug Log', release='Buzznik3.2.0', testcases=['FtOpSoSysImLogFn012'])
def test_ft_snmp_coldstart_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when rps reboot is performed.
    """
    snmp_obj.ensure_snmp_trapd(vars.D1, ssh_conn_obj)

    # generate logs before reboot
    st.log("Generate one log each of INFO and DEBUG level and verify logs are moved to disk on performing cold reboot")
    for i in range(2):
        imlog_data.log_msg_id = log_obj.generate_log_from_cmd(vars.D1, imlog_data.log_level_list[i],
                                                              no_of_logs=1, log_msg_id=imlog_data.log_msg_id)

    # trigger trap on DUT
    st.reboot(vars.D1)

    # Get the ip address of the switch after reboot
    device_eth0_ip_addr()

    # get data from capture
    result = 0
    for _ in range(0, 6):
        st.wait(10)
        read_cmd = "cat {}".format(capture_file)
        output = execute_command(ssh_conn_obj, read_cmd)
        trap_lines = output.split("\n")[:-1]
        result = any('coldStart' in x for x in trap_lines)
        if result == 1:
            break

    # verify logs after reboot
    imlog_result = 0
    st.log("Verify generated logs are present on disk")
    for i in range(2):
        for sequence in range(4):
            if imlog_obj.search_log_in_file(vars.D1, log_level=imlog_data.log_level_list[i],
                                                log_msg_id=imlog_data.log_msg_id, log_msg_id_offset=1-i,
                                                file_sequence=sequence):
                imlog_result = 0
                break
    if imlog_result == 0:
        st.log("Pass: Logs are moved to disk after cold reboot")
        st.report_tc_pass("FtOpSoSysImLogFn012", "test_case_passed")
    else:
        st.error("Fail: Logs are not present in disk after cold reboot")
        st.log("Collecting Techsupport")
        st.generate_tech_support(vars.D1, "FtOpSoSysImLogFn012")
        st.report_tc_fail("FtOpSoSysImLogFn012", "test_case_failed")
    if result == 0:
        st.report_fail("snmp_output_failed", "coldStart")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.snmp_trap
@pytest.mark.inventory(feature='SNMP MIB and Traps', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPTrap005'])
def test_ft_snmp_nsnotifyshutdown_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when snmp docker is restarted.
    """
    snmp_obj.ensure_snmp_trapd(vars.D1, ssh_conn_obj)

    # trigger trap on DUT
    basic_obj.docker_operation(vars.D1,"snmp","restart")

    # get data from capture
    read_cmd = "cat {}".format(capture_file)
    output = execute_command(ssh_conn_obj,read_cmd)
    trap_lines = output.split("\n")[:-1]

    result = any(data.nsNotifyShutdown in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmp_output_failed", "nsNotifyShutdown")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.snmp_trap
@pytest.mark.inventory(feature='warmboot', release='Buzznik')
@pytest.mark.inventory(testcases=['SNMPTrap003'])
@pytest.mark.inventory(release='Buzznik3.2.0', testcases=['FtOpSoSysImLogFn014'])
def test_ft_snmp_warmstart_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when reboot is performed.
    """
    snmp_obj.ensure_snmp_trapd(vars.D1, ssh_conn_obj)

    # generate logs before reboot
    st.log("Generate one log each of INFO and DEBUG level and verify logs are moved to disk on performing warm reboot")
    for i in range(2):
        imlog_data.log_msg_id = log_obj.generate_log_from_cmd(vars.D1, imlog_data.log_level_list[i],
                                                              no_of_logs=1, log_msg_id=imlog_data.log_msg_id)

    # trigger trap on DUT
    reboot.config_save(vars.D1)
    reboot.warm_reboot(vars.D1)

    # Get the ip address of the switch after reboot
    device_eth0_ip_addr()

    # get data from capture
    result = 0
    for _ in range(0, 6):
        st.wait(10)
        read_cmd = "cat {}".format(capture_file)
        output = execute_command(ssh_conn_obj, read_cmd)
        trap_lines = output.split("\n")[:-1]
        result = any('warmStart' in x for x in trap_lines)
        if result == 1:
            break

    # verify logs after reboot
    imlog_result = 1
    st.log("Verify generated logs are present on disk")
    for i in range(2):
        for sequence in range(4):
            if imlog_obj.search_log_in_file(vars.D1, log_level=imlog_data.log_level_list[i],
                                                log_msg_id=imlog_data.log_msg_id, log_msg_id_offset=1-i,
                                                file_sequence=sequence):
                imlog_result = 0
                break
    if imlog_result == 0:
        st.log("Pass: Logs are moved to disk after warm reboot")
        st.report_tc_pass("FtOpSoSysImLogFn014", "test_case_passed")
    else:
        st.error("Fail: Logs are not present in disk after warm reboot")
        st.log("Collecting Techsupport")
        st.generate_tech_support(vars.D1, "FtOpSoSysImLogFn014")
        st.report_tc_fail("FtOpSoSysImLogFn014", "test_case_failed")

    if result == 0:
        st.report_fail("snmp_output_failed", "warmStart")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.snmp_docker_restart
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['FtOpSoSySnFn023'])
def test_ft_snmp_docker_restart():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysName MIB object functions properly after docker restart
    Reference Test Bed : D1--- Mgmt Network
    """
    service_name = "snmp"
    basic_obj.service_operations_by_systemctl(vars.D1, service_name, 'restart')
    if not basic_obj.poll_for_system_status(vars.D1, service_name, 30, 1):
        st.report_fail("service_not_running", service_name)
    if not basic_obj.verify_service_status(vars.D1, service_name):
        st.report_fail("snmp_service_not_up")
    hostname =basic_obj.get_hostname(vars.D1)
    get_snmp_output= snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysName,
                                                 community_name=data.ro_community)
    st.log("hostname Device('{}') and SNMP('{}')".format(hostname, get_snmp_output[0]))
    if not get_snmp_output[0] == hostname:
        st.report_fail("sysName_verification_fail_after_docker_restart")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_counters
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_counters01'])
def test_ft_snmp_basic_counters():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify snmp basic counters.
    Reference Test Bed : D1 --- Mgmt Network
    """
    if basic_obj.is_campus_build(vars.D1):
        st.report_unsupported("module_unsupported", 'snmp counters not supported on campus build')

    snmp_obj.clear_snmp_counters(vars.D1)
    # simulating snmp counters
    snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysName,
                                 community_name=data.ro_community, timeout=6, retry=0, filter=data.filter,)
    st.wait(3)
    output = snmp_obj.verify_snmp_counters(vars.D1, map={"snmp_packets_input": 1, "requested_variables": 1,
                                                         "get_request_pdus": 1, "get_next_pdus": 1,
                                                         "snmp_packets_output": 1, "response_pdus": 1})

    if not output:
        st.report_fail("snmp_counter_not_incremented")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_counters
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_counters02'])
def test_ft_snmp_trap_counter():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify snmp trap pdus.
    Reference Test Bed : D1 --- Mgmt Network
    """
    if basic_obj.is_campus_build(vars.D1):
        st.report_unsupported("module_unsupported", 'snmp counters not supported on campus build')

    snmp_obj.clear_snmp_counters(vars.D1)
    # simulating trap pdu
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    st.wait(5)
    result = snmp_obj.verify_snmp_counters(vars.D1, map={"trap_pdus":1})

    if not result:
        st.report_fail("snmp_counter_not_incremented")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_counters
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_counters03'])
def test_ft_snmp_counter_negative_tests():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify snmp trap pdus.
    Reference Test Bed : D1 --- Mgmt Network
    """
    if basic_obj.is_campus_build(vars.D1):
        st.report_unsupported("module_unsupported", 'snmp counters not supported on campus build')
    snmp_obj.clear_snmp_counters(vars.D1)
    # simulating snmp counters

    snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysName,
                                 community_name="test_test", filter=data.filter, timeout=6, retry=0, report=False)
    snmp_obj.walk_snmp_operation(ipaddress=ipaddress, version='1', oid=data.oid_sysName,
                                 community_name=data.ro_community, timeout=6, retry=0, filter=data.filter, report=False)
    st.wait(3, 'a small delay is needed to increment the respective counter')
    output = snmp_obj.verify_snmp_counters(vars.D1, map={"unknown_community_name": 1, "snmp_version_errors": 1})

    if not output:
        st.report_fail("snmp_counter_not_incremented")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_service_tag
@pytest.mark.inventory(feature='Regression', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_service_tag'])
def test_ft_snmp_service_tag():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    *Verify service tag of a device.
    Reference Test Bed : D1 --- Mgmt Network
    """

    st.log("Service Tag can be seen only on Dell platforms")

    plat_summary = basic_obj.get_platform_summary(vars.D1)
    hwsku = plat_summary.get("hwsku", None)
    asic = plat_summary.get("asic", None)
    if not (("Dell" in hwsku or "DELL" in hwsku) or asic == "vs"):
        st.report_unsupported('test_case_unsupported', "Test supports only on Dell platform")

    cli_output_SN, cli_output_ST = None, None
    plat_eep_op = basic_obj.get_platform_syseeprom(vars.D1)
    for tlv in plat_eep_op:
        if 'Serial Number' in tlv['tlv_name']:
            cli_output_SN = tlv['value']
        if 'Service Tag' in tlv['tlv_name']:
            cli_output_ST = tlv['value']

    if cli_output_SN is None or cli_output_ST is None:
        st.report_fail("test_case_failed")

    snmp_output_SN=snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_serial_no,
                                 community_name=data.ro_community, filter=data.filter, timeout=6, retry=0, report=False)
    snmp_output_ST=snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_service_tag,
                                 community_name=data.ro_community, filter=data.filter, timeout=6, retry=0, report=False)

    if not ((cli_output_SN in snmp_output_SN[0]) and (cli_output_ST in snmp_output_ST[0])):
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_primary_key_enc
@pytest.mark.inventory(feature='Primary encryption key', release='Cyrus4.0.0')
@pytest.mark.inventory(testcases=['FtSwPrimaryKeyEncryptionFunc028'])
def test_ft_snmp_primary_key_enc():
    """
    Author : Pavan Kasula<pavan.kasula@broadcom.com>
    *Verify service tag of a device.
    Reference Test Bed : D1 --- Mgmt Network
    """
    if basic_obj.is_campus_build(vars.D1):
        st.report_unsupported("module_unsupported", 'snmp counters not supported on campus build')
    output = 0
    snmp_obj.clear_snmp_counters(vars.D1)
    # simulating snmp counters

    snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysName,
                                 community_name="test_test", filter=data.filter, timeout=6, retry=0, report=False)
    snmp_obj.walk_snmp_operation(ipaddress=ipaddress, version='1', oid=data.oid_sysName,
                                 community_name=data.ro_community, timeout=6, retry=0, filter=data.filter, report=False)
    st.wait(3, 'a small delay is needed to increment the respective counter')
    result = snmp_obj.verify_snmp_counters(vars.D1, map={"unknown_community_name": 1, "snmp_version_errors": 1})
    if not result:
        st.error("snmp_counter_not_incremented")
        output += 1

    user_api.config_primary_key_encryption(vars.D1, key = data.user_key)

    result = user_api.verify_primary_key(vars.D1, status='True')
    if not result:
        st.error("Primary key is not configured in device")
        output += 1

    st.log('configure SNMPv3 Authentication ')
    snmp_obj.config(vars.D1, {"user": {"name": data.user_name, "group" : data.group_name, "auth":data.auth_type, "auth_pwd":data.user_pwd, "no_form":False}})
    result  = ip_api.verify_running_config(vars.D1,sub_cmd='',return_output='',skip_tmpl=True,cli_type='klish')
    st.log("encrption key++++++++++++++++++>{}".format(result))
    try:
        snmp_enc_password = re.search(r'.*snmp-server.*auth-password\s(\S+)\s.*', result).group(1)
        st.log("encrption key++++++++++++++++++>{}".format(snmp_enc_password))
    except Exception as e:
        output += 1
        snmp_enc_password = ''
        st.log('SNMPv3 server auth password is not encrypted')
        st.error("Exception is {}".format(e))

    if len(snmp_enc_password) !=0 and snmp_enc_password != data.user_pwd:
        st.log('SNMPv3 server auth password is encrypted')
    else:
        output += 1
        st.log('SNMPv3 server auth password is not encrypted')

    snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysName,
                                 community_name="test_test", filter=data.filter, timeout=6, retry=0, report=False)
    snmp_obj.walk_snmp_operation(ipaddress=ipaddress, version='1', oid=data.oid_sysName,
                                 community_name=data.ro_community, timeout=6, retry=0, filter=data.filter, report=False)
    st.wait(3, 'a small delay is needed to increment the respective counter')
    result = snmp_obj.verify_snmp_counters(vars.D1, map={"unknown_community_name": 1, "snmp_version_errors": 1})
    if not result:
        st.error("snmp_counter_not_incremented")
        output += 1

    user_api.config_primary_key_encryption(vars.D1, key=data.user_key, config_mode = 'del_key')
    snmp_obj.config(vars.D1, {"user": {"name": data.user_name, "group" : data.group_name, "auth":data.auth_type, "auth_pwd":data.user_pwd, "no_form":True}})
    if output >= 1:
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_ceta
@pytest.mark.inventory(feature='SNMP CETA', release='Cyrus4.0.2')
@pytest.mark.inventory(testcases=['test_snmp_if_high_speed'])
def test_ft_snmp_if_high_speed():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify port speed for vlan is zero and it displays correctly.
    """
    vlan_obj.show_vlan_brief(vars.D1)
    ip_api.config_ip_addr_interface(vars.D1, data.vlan_name, data.vlan_ip, 18, family=data.af_ipv4)
    st.wait(70, 'Delay is added as configured vlan route to install')
    ip_api.verify_interface_ip_address(vars.D1, "Vlan"+str(data.vlan), data.vlan_ip, family="ipv4")
    st.log("fetching vlan name and speed through snmp walk operation")
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_if_name,
                                                   community_name=data.ro_community,filter=data.filter)
    get_snmp_output1 = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_if_high_speed,
                                                   community_name=data.ro_community,filter=data.filter)

    if not (str(get_snmp_output[-1]).strip('"') == data.vlan_name and (get_snmp_output1[-2:]) == ['0','0']):
        st.report_fail("snmp_output_failed", "ifName")
    st.report_pass("test_case_passed")

