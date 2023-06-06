import pytest

from spytest import st,tgapi

import apis.system.lldp as lldp_obj
import apis.system.snmp as snmp_obj
import apis.system.basic as basic_obj
import apis.system.interface as intf_obj
from spytest.dicts import SpyTestDict
import apis.routing.ip as ip
import apis.system.reboot as sysreboot_obj
import apis.system.logging as syslog_obj
import apis.debug.knet as knet_api

from utilities.common import filter_and_select, make_list, exec_all, ExecAllFunc
from utilities.utils import report_tc_fail, retry_api

@pytest.fixture(scope="module", autouse=True)
def lldp_snmp_module_hooks(request):
    global vars,tg,tg_ph_1
    vars = st.ensure_min_topology("D1D2:2","D1T1:1")
    global_vars()
    tg, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    lldp_snmp_pre_config()
    yield
    lldp_snmp_post_config()


@pytest.fixture(scope="function", autouse=True)
def lldp_snmp_func_hooks(request):
    global_vars()
    if st.get_func_name(request) == "test_lldp_verify_counters":
        if not lldp_obj.lldp_config(vars.D1, status='disabled'):
            st.report_fail("msg", "Failed to disable LLDP at Global level")
    yield
    if st.get_func_name(request) == "test_lldp_verify_counters":
        if not lldp_obj.lldp_config(vars.D1, status='enable'):
            st.report_fail("msg", "Failed to enable LLDP at Global level")
    elif st.get_func_name(request) == "test_ft_lldp_non_default_config":
        st.log("Unconfig section")
        lldp_obj.lldp_config(vars.D2, capability='management-addresses-advertisements', config='yes')
        lldp_obj.lldp_config(vars.D2, capability='capabilities-advertisements', config='yes')
        lldp_obj.lldp_config(vars.D2, interface=vars.D2D1P2, status='rx-and-tx')
        lldp_obj.lldp_config(vars.D2, hostname='sonic')
        lldp_obj.lldp_config(vars.D2, txinterval=30)
        lldp_obj.lldp_config(vars.D2, txhold=6)


def global_vars():
    global data
    data = SpyTestDict()
    data.queue_id = {'PKT_TYPE_LLDP': 18}
    data.ro_community = 'test_community'
    data.mgmt_int = 'eth0'
    data.wait_time = 30
    data.location = 'hyderabad'
    data.oid_sysName = '1.3.6.1.2.1.1.5.0'
    data.oid_lldplocportid = '1.0.8802.1.1.2.1.3.7.1.3'
    data.oid_lldplocsysname = '1.0.8802.1.1.2.1.3.3'
    data.oid_lldplocsysdesc = '1.0.8802.1.1.2.1.3.4'
    data.oid_lldplocportdesc = '1.0.8802.1.1.2.1.4.1'
    data.oid_locmanaddrtable = '1.0.8802.1.1.2.1.1.7'
    data.oid_locmanaddrsubtype = '1.0.8802.1.1.2.1.3.8.1.1'
    data.oid_locmanaddroid = '1.0.8802.1.1.2.1.3.8.1.6'
    data.oid_locmanaddrlen = '1.0.8802.1.1.2.1.3.8.1.3'
    data.oid_locmanaddrlfld = '1.0.8802.1.1.2.1.3.8.1.5'
    data.oid_locmanaddrentry = '1.0.8802.1.1.2.1.3.8.1'
    data.oid_configmanaddrtable = '1.0.8802.1.1.2.1.1.7'
    data.oid_configmanaddrentry = '1.0.8802.1.1.2.1.1.7.1'
    data.oid_lldp_rem_man_addr_table = '1.0.8802.1.1.2.1.4.2'
    data.filter = '-Oqv'
    data.string = ["leaf1",'"connected to leaf2"']
    data.rate_pps = tgapi.normalize_pps(1000)

def lldp_snmp_pre_config():
    """
    LLDP Pre Config
    """
    global lldp_value
    global ipaddress
    global lldp_value_remote, lldp_value_gran
    global lldp_total_value
    data.ipaddress_d1 = basic_obj.get_ifconfig_inet(vars.D1, data.mgmt_int)
    data.ipaddress_d2 = basic_obj.get_ifconfig_inet(vars.D2, data.mgmt_int)
    if not data.ipaddress_d1:
        err = st.error(" Ip address is not a valid one or the ip is not presented on the device")
        st.report_result(err)
    ipaddress = data.ipaddress_d1[0]
    if not intf_obj.poll_for_interfaces(vars.D1,iteration_count=60,delay=1):
        st.report_fail("interfaces_not_up_after_poll")
    if not intf_obj.poll_for_interfaces(vars.D2,iteration_count=60,delay=1):
        st.report_fail("interfaces_not_up_after_poll")
    if not lldp_obj.poll_lldp_neighbors(vars.D1, iteration_count=30, delay=1, interface=vars.D1D2P1):
        st.report_fail("lldp_neighbors_info_not_found_after_poll")
    if not lldp_obj.poll_lldp_neighbors(vars.D2, iteration_count=30, delay=1, interface=vars.D2D1P1):
        st.report_fail("lldp_neighbors_info_not_found_after_poll")
    st.log(" Getting Ip address of the Device")
    lldp_value = check_for_mgmt_ip(vars.D1, iter_cnt=10, intf=vars.D1D2P1)
    st.debug('LLDP neighbors in main DUT on port: {} is: {}'.format(vars.D1D2P1, lldp_value))
    lldp_value_remote = check_for_mgmt_ip(vars.D2, iter_cnt=10, intf=vars.D2D1P1)
    st.debug('LLDP neighbors in remote DUT on port: {} is: {}'.format(vars.D2D1P1, lldp_value_remote))
    st.log(" LLDP Neighbors value is: {} ".format(lldp_value))
    st.log(" Remote LLDP Neighbors value is: {} ".format(lldp_value_remote))
    if not lldp_value:
        err = st.error("No lldp entries are available")
        st.report_result(err)
    if not lldp_value_remote:
        err = st.error(" No lldp entries are available in Remote")
        st.report_result(err)

    lldp_value = lldp_value[0]
    lldp_total_value = lldp_value_remote
    lldp_value_remote = lldp_value_remote[0]
    lldp_value_gran = lldp_value['chassis_mgmt_ip']
    if not data.ipaddress_d2[0] == lldp_value_gran:
        err = st.error("LLDP info IP {} and device IP {} are not matching".format(lldp_value_gran, data.ipaddress_d2[0]))
        st.report_result(err)

    # TODO : Need to check the below once the infra defect SONIC-5374 is Fixed
    '''
    mac_output = basic_obj.get_platform_syseeprom(vars.D1, 'Serial Number', 'Value')
    lldp_value_mac = lldp_value['chassis_id_value']
    st.log("lldp_value_gran is :{}".format(lldp_value_gran))
    if not mac_output == lldp_value_mac:
        st.report_fail(" MAC Addresses are not matching ")
    '''
    snmp_obj.set_snmp_config(vars.D1, snmp_rocommunity=data.ro_community, snmp_location=data.location)
    if not ip.ping_poll(vars.D1, data.ipaddress_d1[0], family='ipv4',iter=5, count=1):
        st.report_fail("ping_fail", data.ipaddress_d1[0])
    if not snmp_obj.poll_for_snmp(vars.D1, 30 , 1 , ipaddress= data.ipaddress_d1[0],
                                  oid=data.oid_sysName, community_name=data.ro_community):
        err = st.error("Post SNMP config , snmp is not working")
        st.report_result(err)

def check_for_mgmt_ip(dut, iter_cnt, intf):
    i = 1
    while True:
        rv = lldp_obj.get_lldp_neighbors(dut, intf)
        if rv and len(rv) > 0 and 'chassis_mgmt_ip' in rv[0] and rv[0]['chassis_mgmt_ip']:
            return rv
        if i > iter_cnt:
            st.log(" Max {} tries Exceeded for lldp neighbors polling .Exiting ...".format(i))
            return rv
        i += 1
        st.wait(1)


def get_lldp_tx_counter(dut, ports, counter):
    ports = make_list(ports)
    retval = dict()
    lldp_details = lldp_obj.get_lldp_statistics(dut, ports=ports)
    for port in ports:
        lldp_counter = filter_and_select(lldp_details, [counter], {'interface': port})
        if not (lldp_counter and isinstance(lldp_counter, list) and isinstance(lldp_counter[0], dict) and counter in lldp_counter[0]):
            st.debug("LLDP statistics output is: {}".format(lldp_details))
            st.report_fail("lldp_invalid")
        retval[port] = int(lldp_counter[0][counter]) if isinstance(lldp_counter[0][counter], int) else 0
    return retval


def verify_lldp_neighbor(dut, port, present=True):
    if present:
        if not lldp_obj.get_lldp_neighbors(dut, port):
            st.log("LLDP neighbor data not present")
            return False
    else:
        if lldp_obj.get_lldp_neighbors(dut, port):
            st.log("LLDP neighbor data present")
            return False
    return True

def poll_wait_for_desc():
    st.log("verifing the portdescription on D1 and D2")
    output = lldp_obj.get_lldp_neighbors(vars.D1, interface=vars.D1D2P1)
    output1 = lldp_obj.get_lldp_neighbors(vars.D2, interface=vars.D2D1P1)
    if not (output[0]['portdescr'].strip('"') == data.string[1].strip('"') and output1[0]['portdescr'] == data.string[0]):
        return False
    return True


def lldp_snmp_post_config():
    """
    LLDP Post Config
    """
    snmp_obj.restore_snmp_config(vars.D1)



@pytest.mark.lldp_LocManAddrOID
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='KNET Debug Counter', release='Cyrus4.0.0')
@pytest.mark.inventory(feature='Regression', release='Arlo+', testcases=['ft_lldp_LocManAddrOID'])
@pytest.mark.inventory(testcases=['CPU_KNET_DEBUG_FUNC_001'])
def test_ft_lldp_LocManAddrOID():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrOID MIB object functions properly.
    Verify the LLDP protocol CPU pkt counter.
    Reference Test Bed : D1 --- Mgmt Network
    """
    lldp_knet_tc = True
    if not retry_api(knet_api.validate_knet_counters, vars.D1, pkt_type='PKT_TYPE_LLDP', queue=data.queue_id['PKT_TYPE_LLDP'], tx_queue=True, intf=vars.D1D2P1):
        lldp_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_313_LLDP", "msg", "Failed to validate KNET counters for LLDP")
    if not retry_api(knet_api.validate_clear_knet_counters, vars.D1, pkt_type='PKT_TYPE_LLDP', queue=data.queue_id['PKT_TYPE_LLDP']):
        lldp_knet_tc = False
        report_tc_fail("CPU_KNET_DEBUG_FUNC_313_LLDP", "msg", "Failed to validate KNET counters clear")
    if lldp_knet_tc:
        st.report_tc_pass("CPU_KNET_DEBUG_FUNC_313_LLDP", "msg", "Succcessfully verified the LLDP protocol CPU pkt counter")
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddroid,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_LocManAddrLen
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_lldp_LocManAddrLen'])
def test_ft_lldp_LocManAddrLen():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrLen MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrlen,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_LocManAddrlfld
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_lldp_LocManAddrlfld'])
def test_ft_lldp_LocManAddrlfld():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrlfld MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrlfld,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_LocManAddrEntry
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_lldp_LocManAddrEntry'])
def test_ft_lldp_LocManAddrEntry():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrEntry MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrentry,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_ConfigManAddrEntry
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_lldp_ConfigManAddrEntry'])
def test_ft_lldp_ConfigManAddrEntry():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the ConfigManAddrEntry MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrentry,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_lldplocportid
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_lldp_lldplocportid'])
def test_ft_lldp_lldplocportid():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the syntax check of the object lldplocportid.
    Reference Test Bed : D1 <---> D2
    """
    cli_output = ''
    lldp_value_remote_val = lldp_obj.get_lldp_neighbors(vars.D2, interface=vars.D2D1P1)
    output = lldp_value_remote_val[-1]
    cli_output = '"{}"'.format(output['portid_value'])

    snmp_output = snmp_obj.walk_snmp_operation(ipaddress= ipaddress, oid= data.oid_lldplocportid,community_name= data.ro_community,filter=data.filter)
    if not snmp_output:
        st.report_fail(" No SNMP Entries are available")

    st.log("lldp CLI port is : {} ".format(cli_output))
    st.log("lldp SNMP output is : {} ".format(snmp_output))
    if not cli_output in snmp_output:
        st.error("Port ID in CLI is not matching with Port ID in SNMP")
        st.report_fail("lldp_snmp_not_matching")
    st.log("Port ID in CLI is matching with Port ID in SNMP")
    st.report_pass("test_case_passed")


@pytest.mark.lldp_lldplocsysname
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_lldp_lldplocsysname'])
def test_ft_lldp_lldplocsysname():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the syntax check of the object lldplocsysname.
    Reference Test Bed : D1 <---> D2
    """
    snmp_output = snmp_obj.get_snmp_operation(ipaddress= ipaddress, oid= data.oid_lldplocsysname,
                                              community_name=data.ro_community)
    if not snmp_output:
        st.report_fail(" No SNMP Entries are available")
    snmp_output = snmp_output[0]
    st.log(" Getting LLDP port description:{} from the snmp output ".format(snmp_output))
    cli_output = lldp_value_remote['chassis_name']
    st.log(" lldp value port is : {} ".format(cli_output))
    if not cli_output in snmp_output:
        st.report_fail("lldp_snmp_not_matching")
    st.log(" LLDP value is passed ")
    st.report_pass("test_case_passed")


@pytest.mark.lldp_lldplocsysdesc
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_lldp_lldplocsysdesc'])
def test_ft_lldp_lldplocsysdesc():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the syntax check of the object lldplocsysdesc.
    Reference Test Bed : D1 <---> D2
    """
    snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid= data.oid_lldplocsysdesc,
                                              community_name=data.ro_community)
    if not snmp_output:
        st.report_fail(" No SNMP Entries are available")
    snmp_output = snmp_output[0]
    st.log(" Getting LLDP port description:{} from the snmp output ".format(snmp_output))
    cli_output = lldp_value_remote['chassis_descr']
    st.log(" lldp value port is : {} ".format(cli_output))
    if not cli_output in snmp_output:
        st.report_fail("lldp_snmp_not_matching")
    st.log(" LLDP value is passed ")
    st.report_pass("test_case_passed")

@pytest.mark.lldp_lldplocportdesc
@pytest.mark.inventory(feature='Regression', release='Buzznik')
@pytest.mark.inventory(testcases=['CETA_SONIC_19257'])
@pytest.mark.inventory(release='Buzznik+', testcases=['FtOpSoSwlldpSn012'])
def test_ft_lldp_lldplocportdesc():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the syntax check of the object lldplocsysdesc.
    Reference Test Bed : D1 <---> D2
    """
    result = True
    snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_lldplocportdesc,
                                              community_name=data.ro_community,filter=data.filter)
    if not snmp_output:
        st.report_fail(" No SNMP Entries are available")
    st.log(" Getting LLDP port description:{} from the snmp output ".format(snmp_output))
    cli_output = lldp_value['portdescr']
    st.log(" lldp value port is : {} ".format(cli_output))
    if not cli_output in str(snmp_output):
        st.report_fail("lldp_snmp_not_matching")
    if not intf_obj.interface_properties_set(vars.D1,vars.D1D2P1, property="description", value=data.string[0]):
        st.log("configuring port description failed on D1")
    if not intf_obj.interface_properties_set(vars.D2,vars.D2D1P1, property="description", value=data.string[1]):
        st.log("configuring port description failed on D2")
    if not st.poll_wait(poll_wait_for_desc,20):
        result = False
        report_tc_fail("CETA_SONIC_19257", "msg", "Failed to validate portdescription")
    if not result:
        st.report_fail("test_case_failed")
    st.log(" LLDP value is passed ")
    st.report_pass("test_case_passed")

@pytest.mark.lldp_remote
@pytest.mark.community
@pytest.mark.inventory(feature='SNMP Agent Optimization', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_snmp_lldp_prem_manaddr_table'])
def test_ft_lldp_rem_man_addr_table():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify the syntax check of the object LLDPRemManAddrTable.
    Reference Test Bed : D1 <---> D2
    """
    snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_lldp_rem_man_addr_table,
                                              community_name=data.ro_community,filter=data.filter)
    if not snmp_output:
        st.report_fail(" No SNMP Entries are available")

    st.log(" LLDP value is passed ")
    st.report_pass("test_case_passed")


@pytest.mark.lldp_non_default_config
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoSwlldpFn004'])
@pytest.mark.inventory(testcases=['FtOpSoSwlldpFn008'])
@pytest.mark.inventory(testcases=['FtOpSoSwlldpFn009'])
@pytest.mark.inventory(testcases=['FtOpSoSwlldpFn010'])
@pytest.mark.inventory(testcases=['FtOpSoSwlldpFn011'])
def test_ft_lldp_non_default_config():
    """
     Author : Prasad Darnasi <prasad.darnasi@broadcom.com>
     Verify non default LLDP neighbor config.
     Reference Test Bed : D1 <--2--> D2
     """
    tc_fall = 0
    lldp_obj.lldp_config(vars.D2, txinterval= 5)
    lldp_obj.lldp_config(vars.D2, txhold = 1)
    lldp_obj.lldp_config(vars.D2, capability= 'management-addresses-advertisements' , config= 'no')
    lldp_obj.lldp_config(vars.D2, capability= 'capabilities-advertisements', config='no')
    lldp_obj.lldp_config(vars.D2, interface = vars.D2D1P2, status = 'disabled')
    lldp_obj.lldp_config(vars.D2, hostname = 'SonicTest')

    st.wait(25, "Waiting until  TTL expires")
    lldp_value = lldp_obj.get_lldp_neighbors(vars.D1, interface=vars.D1D2P1)
    lldp_value_1 = lldp_obj.get_lldp_neighbors(vars.D1, interface=vars.D1D2P2)

    if lldp_value:
        lldp_value_gran_new = lldp_value[0]['chassis_mgmt_ip']
        lldp_value_capability_new = lldp_value[0]['chassis_capability_router']
        lldp_value_chassis_name_new = lldp_value[0]['chassis_name']
    else:
        tc_fall = 1
        st.error('Failed: LLDP neighbor information not found')

    if not tc_fall:
        if lldp_value_gran_new is lldp_value_gran:
            tc_fall = 1
            st.log('Failed: LLDP neighbor management is seen even though disabled ')
        if lldp_value_capability_new:
            tc_fall = 1
            st.log('Failed: LLDP neighbor capabilities are present even though disabled')
        if lldp_value_chassis_name_new != 'SonicTest':
            tc_fall = 1
            st.log('Failed: LLDP neighbor system name is not changed to non default ')
        if lldp_value_1:
            tc_fall = 1
            st.log('Failed: LLDP neighbor interface is still seen even though LLDP disabled on that ')

    if tc_fall:
        st.report_fail('LLDP_non_default_config_is_failed')

    st.log("LLDP neighbor values are advertised as configured ")
    st.report_pass("test_case_passed")


@pytest.mark.lldp_docker_restart
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['FtOpSoSwlldpFn013'])
def test_ft_lldp_docker_restart():
    """
     Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
     Verify the LLDP functionality after docker restart.
     Reference Test Bed : D1 <--2--> D2
     """
    st.log("Checking the LLDP functionality with docker restart")
    service_name = "lldp"
    basic_obj.service_operations_by_systemctl(vars.D1, service_name, 'stop')
    basic_obj.service_operations_by_systemctl(vars.D1,service_name,'restart')
    if not basic_obj.poll_for_system_status(vars.D1,service_name,30,1):
        st.report_fail("service_not_running", service_name)
    if not basic_obj.verify_service_status(vars.D1, service_name):
        st.report_fail("lldp_service_not_up")
    if not intf_obj.poll_for_interfaces(vars.D1,iteration_count=30,delay=1):
        st.report_fail("interfaces_not_up_after_poll")
    if not lldp_obj.poll_lldp_neighbors(vars.D1, iteration_count=30, delay=1, interface=vars.D1D2P1):
        st.report_fail("lldp_neighbors_info_not_found_after_poll")
    lldp_info = lldp_obj.get_lldp_neighbors(vars.D1, interface=vars.D1D2P1)
    if not lldp_info:
        st.error("No lldp entries are available")
        st.report_fail("operation_failed")
    lldp_value_dut1 = lldp_info[0]
    lldp_output_dut1 = lldp_value_dut1['chassis_name']
    hostname_cli_output = basic_obj.get_hostname(vars.D2)
    if lldp_output_dut1 != hostname_cli_output:
        st.report_fail("lldp_cli_not_matching")
    st.log("LLDP and CLI output values are : LLDP:{} , CLI:{} ".format(lldp_output_dut1,hostname_cli_output))
    st.report_pass("test_case_passed")


@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['lldp_verify_counters'])
def test_lldp_verify_counters():
    """
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify LLDP PDUs are not transmitted when the feature is disabled.
    """
    lldp_details = get_lldp_tx_counter(vars.D1, [vars.D1D2P1, vars.D1D2P2], 'transmitted')
    lldp_port1_pre_tx = lldp_details[vars.D1D2P1]
    lldp_port2_pre_tx = lldp_details[vars.D1D2P2]
    if not st.poll_wait(verify_lldp_neighbor, 130, vars.D2, vars.D2D1P1, False):
        st.report_fail("msg", "Observed LLDP neighbor details even if LLDP disabled globally")
    if lldp_obj.get_lldp_neighbors(vars.D2, vars.D2D1P2):
        st.report_fail("msg", "Observed LLDP neighbor details even if LLDP disabled globally")
    lldp_details = get_lldp_tx_counter(vars.D1, [vars.D1D2P1, vars.D1D2P2], 'transmitted')
    lldp_port1_post_tx = lldp_details[vars.D1D2P1]
    lldp_port2_post_tx = lldp_details[vars.D1D2P2]
    if not (lldp_port1_post_tx == lldp_port1_pre_tx and lldp_port2_post_tx == lldp_port2_pre_tx):
        st.report_fail("msg", "LLDP PDUs are transmitted even feature is disabled")
    exec_all(True, [ExecAllFunc(lldp_obj.lldp_config, vars.D1, status='enable'), ExecAllFunc(intf_obj.clear_interface_counters, vars.D2)])
    if not st.poll_wait(verify_lldp_neighbor, 130, vars.D2, vars.D2D1P1):
        st.report_fail("msg", "LLDP neighbor details not observed")
    if not lldp_obj.get_lldp_neighbors(vars.D2, vars.D2D1P2):
        st.report_fail("msg", "LLDP neighbor details not observed")
    rx_drop1 = intf_obj.get_interface_counters(vars.D2, vars.D2D1P1, 'rx_drp')
    rx_drop2 = intf_obj.get_interface_counters(vars.D2, vars.D2D1P2, 'rx_drp')
    if not (rx_drop1 and rx_drop2 and isinstance(rx_drop1, list) and isinstance(rx_drop2, list) and isinstance(rx_drop1[0], dict) and isinstance(rx_drop2[0], dict) and rx_drop1[0].get('rx_drp') and rx_drop2[0].get('rx_drp') and rx_drop1[0]['rx_drp'] == '0' and rx_drop1[0]['rx_drp'] == '0'):
       st.report_fail("msg", "Invalid rx_drp counters observed")
    st.report_pass("test_case_passed")

@pytest.mark.inventory(feature='Regression', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_lldp_config_reload'])
def test_lldp_config_reload():
    """
    Author: Pavan Kumar <pavankumar.tambarapu@broadcom.com>
    Coverage for SONIC-17360 to verify if lldp service exited gracefully after config reload..
    """
    st.log('config reload the dut and verify if the lldp exited gracefully')
    st.log('Clear existing log messages')
    syslog_obj.sonic_clear(vars.D1)
    sysreboot_obj.config_reload(vars.D1)
    if basic_obj.retry_api(syslog_obj.show_logging, vars.D1, keyword='lldp',filter_list=r'SIGKILL\|SIGTERM',retry_count=5, delay=5):
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")

@pytest.mark.inventory(feature='Regression', release='Cyrus4.0.0')
@pytest.mark.inventory(testcases=['ft_lldp_with_remote_server'])
def test_ft_lldp_with_remote_server():
    server_src_mac = "94:40:c9:8f:4e:cc"
    interface_name = vars.D1T1P1
    st.log('sending lldp packets for from server and checking lldp table output')
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="94:40:C9:8F:4E:CC", mac_dst="01:80:C2:00:00:0E",
                         mode='create', transmit_mode='continuous', l2_encap='ethernet_ii', data_pattern_mode='fixed',
                         data_pattern='02 25 07 33 36 33 38 33 31 35 30 2D 33 36 33 30 2D 35 41 34 33 2D 34 41 33 30 2D 33 32 33 32 33 30 34 32 34 36 34 36 04 07 03 94 40 C9 8F 4E CC 06 02 00 64 08 14 50 43 49 2D 45 20 53 6C 6F 74 20 32 2C 20 50 6F 72 74 20 31 0C 19 50 72 6F 4C 69 61 6E 74 20 44 4C 33 32 35 20 47 65 6E 31 30 20 50 6C 75 73 10 0C 05 01 0A 58 9C 68 01 00 00 00 00 00 10 0E 07 06 94 40 C9 3A 1A 68 01 00 00 00 00 00 00 00 00',
                         ethernet_value='88CC',frame_size='152', rate_pps=data.rate_pps)['stream_id']
    st.banner("Sending lldp packets...")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(10)
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])
    st.banner("Displaying LLDP output after sending neighbor info from the server")
    lldp_obj.get_lldp_table(vars.D1, interface=None)
    st.banner("Now Verify whether the lldp table is updated with expected interface {} and remote port-id: {}".format(interface_name,server_src_mac))
    if lldp_obj.get_lldp_table(vars.D1, interface=interface_name,mac=server_src_mac):
        st.log("LLDP table is updated with the expected server neighborship")
        st.report_pass("test_case_passed")
    else:
        st.error("LLDP table is not updated with the expected neighbor")
        st.report_fail("test_case_failed")
