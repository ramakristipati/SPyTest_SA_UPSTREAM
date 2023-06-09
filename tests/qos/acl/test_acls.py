import pprint
import pytest
import json
import re

from spytest import st, tgapi, SpyTestDict
from utilities.common import random_vlan_list, filter_and_select, make_list

import apis.switching.vlan as vlan_obj
import apis.qos.acl as acl_obj
import tests.qos.acl.acl_json_config as acl_data
import tests.qos.acl.acl_rules_data as acl_rules_data
import tests.qos.acl.acl_utils as acl_utils
import tests.qos.acl.acl_lib as acl_lib
import apis.switching.portchannel as pc_obj
import apis.routing.ip as ipobj
import apis.system.gnmi as gnmiapi
from apis.system.interface import clear_interface_counters,get_interface_counters
from apis.system.rest import rest_status
import apis.system.config_session as ses_api
import apis.system.config_replace as rep_api
import apis.system.basic as basic_obj
import utilities.utils as utils_obj


import utilities.common as utils

try:
    from apis.yang.utils.common import Operation
except ImportError:
    pass

YANG_MODEL = "sonic-acl:sonic-acl"
pp = pprint.PrettyPrinter(indent=4)

vars = dict()
data = SpyTestDict()
data.rate_pps = 100
data.frame_size = 512
data.pkts_per_burst = 10
data.tx_timeout = 2
data.TBD = 10
data.portChannelName = "PortChannel1"
data.tg_type = 'ixia'
data.cli_type = ""

#### Gnmi replace vars ####
data.create_acl_name = 'create_mac_acl'
data.create_type = 'mac'
data.create_seq = 50
data.create_action = 'DROP'
data.create_src_mac = 'aa:bb:cc:dd:ee:ff'
data.create_src_mac_mask = 'ff:ff:ff:00:00:00'
data.create_dst_mac = 'a1:b1:c1:d1:e1:f1'
data.create_dst_mac_mask = 'ff:ff:ff:00:00:00'
data.create_vlan = '10'
data.create_dei = 1
data.create_pcp = 1
data.create_pcpmask = 1
data.def_dst_mac = 'any'
data.repl_action = 'ACCEPT'
data.repl_src_mac_1 = 'bb:cc:dd:ee:ff:bb'
data.repl_src_mac_2 = '00:0a:01:00:00:05'
data.repl_src_mac_mask = 'ff:ff:ff:00:00:00'
data.repl_dst_mac = '00:0a:01:00:11:06'
data.repl_dst_mac_mask = 'ff:ff:ff:00:00:00'
data.repl_dei = 0
data.repl_pcp = 0
data.repl_pcpmask = 0


def print_log(msg):
    utils.print_log(msg)

def get_handles():
    '''
    ######################## Topology ############################

               +---------+                  +-------+
               |         +------------------+       |
      TG1 -----|  DUT1   |  portchannel     |  DUT2 +----- TG2
               |         +------------------+       |
               +---------+                  +-------+

    ##############################################################
    '''
    global vars, tg_port_list
    vars = st.ensure_min_topology("D1D2:2", "D1T1:2", "D2T1:1")
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    tg3, tg_ph_3 = tgapi.get_handle_byname("T1D1P2")
    if tg1.tg_type == 'stc': data.tg_type = 'stc'
    tg_port_list = [tg_ph_1, tg_ph_2, tg_ph_3]
    tg1.tg_traffic_control(action="reset", port_handle=tg_ph_1)
    tg2.tg_traffic_control(action="reset", port_handle=tg_ph_2)
    tg3.tg_traffic_control(action="reset", port_handle=tg_ph_3)
    return (tg1, tg2, tg3, tg_ph_1, tg_ph_2, tg_ph_3)





def apply_module_configuration():
    print_log("Applying module configuration")

    data.vlan = str(random_vlan_list()[0])
    data.dut1_lag_members = [vars.D1D2P1, vars.D1D2P2]
    data.dut2_lag_members = [vars.D2D1P1, vars.D2D1P2]

    # create portchannel
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.create_portchannel, vars.D1, data.portChannelName, cli_type=data.cli_type),
        utils.ExecAllFunc(pc_obj.create_portchannel, vars.D2, data.portChannelName, cli_type=data.cli_type),
    ])

    # add portchannel members
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.add_portchannel_member, vars.D1, data.portChannelName, data.dut1_lag_members, data.cli_type),
        utils.ExecAllFunc(pc_obj.add_portchannel_member, vars.D2, data.portChannelName, data.dut2_lag_members, data.cli_type),
    ])

    # create vlan
    utils.exec_all(True, [
        utils.ExecAllFunc(vlan_obj.create_vlan, vars.D1, data.vlan, data.cli_type),
        utils.ExecAllFunc(vlan_obj.create_vlan, vars.D2, data.vlan, data.cli_type),
    ])

    # add vlan members
    utils.exec_all(True, [
        utils.ExecAllFunc(vlan_obj.add_vlan_member, vars.D1, data.vlan, [vars.D1T1P1, vars.D1T1P2,
                          data.portChannelName], True, cli_type=data.cli_type),
        utils.ExecAllFunc(vlan_obj.add_vlan_member, vars.D2, data.vlan, [vars.D2T1P1, data.portChannelName], True,
                          cli_type=data.cli_type),
    ])




def clear_module_configuration():
    print_log("Clearing module configuration")

    # delete vlan members
    utils.exec_all(True, [
        utils.ExecAllFunc(vlan_obj.delete_vlan_member, vars.D1, data.vlan, [vars.D1T1P1, vars.D1T1P2,
                          data.portChannelName], True, cli_type=data.cli_type),
        utils.ExecAllFunc(vlan_obj.delete_vlan_member, vars.D2, data.vlan, [vars.D2T1P1, data.portChannelName], True,
                          cli_type=data.cli_type),
    ])

    # delete portchannel members
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.delete_portchannel_member, vars.D1, data.portChannelName, data.dut1_lag_members,
                          data.cli_type),
        utils.ExecAllFunc(pc_obj.delete_portchannel_member, vars.D2, data.portChannelName, data.dut2_lag_members,
                          data.cli_type),
    ])
    # delete portchannel
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.delete_portchannel, vars.D1, data.portChannelName),
        utils.ExecAllFunc(pc_obj.delete_portchannel, vars.D2, data.portChannelName),
    ])
    # delete vlan
    utils.exec_all(True, [
        utils.ExecAllFunc(vlan_obj.delete_vlan, vars.D1, data.vlan, data.cli_type),
        utils.ExecAllFunc(vlan_obj.delete_vlan, vars.D2, data.vlan, data.cli_type),
    ])
    # delete acl tables and rules
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])


def add_port_to_acl_table(config, table_name, port):
    config['ACL_TABLE'][table_name]['ports'] = []
    config['ACL_TABLE'][table_name]['ports'].append(port)


def change_acl_rules(config, rule_name, attribute, value):
    config["ACL_RULE"][rule_name][attribute] = value


def apply_acl_config(dut, config):
    json_config = json.dumps(config)
    json.loads(json_config)
    st.apply_json2(dut, json_config)


def create_streams(tx_tg, rx_tg, rules, match, mac_src, mac_dst,dscp=None,pcp=None, dei=None,ether_type_val=None, return_stream=False):
    # use the ACL rule definitions to create match/non-match traffic streams
    # instead of hardcoding the traffic streams
    my_args = {
        'port_handle': data.tgmap[tx_tg]['handle'], 'mode': 'create', 'frame_size': data.frame_size,
        'transmit_mode': 'continuous', 'length_mode': 'fixed',
        'l2_encap': 'ethernet_ii_vlan', 'duration': '1',
        'vlan_id': data.vlan, 'vlan': 'enable', 'rate_pps': data.rate_pps,
        'high_speed_result_analysis': 0, 'mac_src': mac_src, 'mac_dst': mac_dst,
        'port_handle2': data.tgmap[rx_tg]['handle']
    }
    if dscp:
        my_args.update({"ip_dscp": dscp})
    if pcp:
        my_args.update({"vlan_user_priority": pcp})
    if dei:
        my_args.update({"vlan_cfi": dei})
    if ether_type_val:
        my_args.update({"l2_encap": 'ethernet_ii_vlan'})
        my_args.update({"l3_protocol": "ipv4"})

    for rule, attributes in rules.items():
        if ("IP_TYPE" in attributes) or ("ETHER_TYPE" in attributes):
            continue
        if match in rule:
            params = {}
            tmp = dict(my_args)
            for key, value in attributes.items():
                params.update(acl_utils.get_args(key, value, attributes, data.rate_pps, data.tg_type))
            tmp.update(params)
            stream = data.tgmap[tx_tg]['tg'].tg_traffic_config(**tmp)
            stream_id = stream['stream_id']
            s = {}
            s[stream_id] = attributes
            s[stream_id]['TABLE'] = rule
            if return_stream:
                return s
            data.tgmap[tx_tg]['streams'].update(s)


def transmit(tg):
    print_log("Transmitting streams")
    data.tgmap[tg]['tg'].tg_traffic_control(action='clear_stats', port_handle=tg_port_list)
    data.tgmap[tg]['tg'].tg_traffic_control(action='run', stream_handle = list(data.tgmap[tg]['streams'].keys()), duration=1)
    data.tgmap[tg]['tg'].tg_traffic_control(action='stop', stream_handle = list(data.tgmap[tg]['streams'].keys()))


def verify_acl_hit_counters(dut, table_name, counters_dict, acl_type="ip", **kwargs):
    acl_rule_counters = acl_obj.show_acl_counters(dut, acl_table=table_name, acl_type=acl_type, **kwargs)
    _ = [acl_rule_counter.update({"rule_no": int(re.sub(r"[a-z|A-Z]", "", acl_rule_counter["rulename"])), "access_list_name": acl_rule_counter["tablename"]}) for acl_rule_counter in acl_rule_counters if acl_rule_counter.get("rulename") and acl_rule_counter.get("tablename")]
    st.debug("acl_rule_counters after processing: {}".format(acl_rule_counters))
    if acl_rule_counters:
        for rule_type, rules_list in counters_dict.items():
            for rule_dict in make_list(rules_list):
                entries = filter_and_select(acl_rule_counters, ['packetscnt', 'bytescnt'], rule_dict)
                if entries and isinstance(entries[0], dict) and entries[0].get('packetscnt') and entries[0].get('bytescnt'):
                    if rule_type == 'hit_rules':
                        if not (int(entries[0]['packetscnt']) >= 50 and int(entries[0]['bytescnt']) >= 50*data.frame_size):
                            st.error("ACL hit counter not incremented for ACL Rule: {}".format(rule_dict))
                            return False
                    else:
                        if not (int(entries[0]['packetscnt']) == 0 and int(entries[0]['bytescnt']) == 0):
                            st.error("ACL hit counter incremented for ACL Rule: {}".format(rule_dict))
                            return False
                else:
                    st.error("Counter entry: {} not found".format(rule_dict))
                    return False
    return True


def verify_packet_count(tx, tx_port, rx, rx_port, table):
    result = True
    tg_tx = data.tgmap[tx]
    tg_rx = data.tgmap[rx]
    exp_ratio = 0
    action = "DROP"
    attr_list = []
    traffic_details = dict()
    action_list = []
    index = 0
    for s_id, attr in tg_tx['streams'].items():
        if table in attr['TABLE']:
            index = index + 1
            if attr["PACKET_ACTION"] == "FORWARD":
                exp_ratio = 1
                action = "FORWARD"
            else:
                exp_ratio = 0
                action = "DROP"
            traffic_details[str(index)] = {
                    'tx_ports': [tx_port],
                    'tx_obj': [tg_tx["tg"]],
                    'exp_ratio': [exp_ratio],
                    'rx_ports': [rx_port],
                    'rx_obj': [tg_rx["tg"]],
                    'stream_list': [[s_id]]
                }
            attr_list.append(attr)
            action_list.append(action)
    result_all = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock',
                                    comp_type='packet_count', return_all=1, delay_factor=1, retry=1)
    for result1, action, attr in zip(result_all[1], action_list, attr_list):
        result = result and result1
        if result1:
            if action == "FORWARD":
                msg = "Traffic successfully forwarded for the rule: {}".format(json.dumps(attr))
                print_log(msg)
            else:
                msg = "Traffic successfully dropped for the rule: {}".format(json.dumps(attr))
                print_log(msg)
        else:
            if action == "FORWARD":
                msg = "Traffic failed to forward for the rule: {}".format(json.dumps(attr))
                print_log(msg)
            else:
                msg = "Traffic failed to drop for the rule: {}".format(json.dumps(attr))
                print_log(msg)
    return result


def initialize_topology():
    print_log("Initializing Topology")
    (tg1, tg2, tg3, tg_ph_1, tg_ph_2, tg_ph_3) = get_handles()
    data.tgmap = {
        "tg1": {
            "tg": tg1,
            "handle": tg_ph_1,
            "streams": {}
        },
        "tg2": {
            "tg": tg2,
            "handle": tg_ph_2,
            "streams": {}
        },
        "tg3": {
            "tg": tg3,
            "handle": tg_ph_3,
            "streams": {}
        }
    }
    data.vars = vars

@pytest.fixture(scope="module", autouse=True)
def acl_v4_module_hooks(request):
    # initialize topology
    initialize_topology()

    # apply module configuration
    apply_module_configuration()
    change_acl_rules(acl_data.acl_json_config_d1, "L3_IPV4_INGRESS|rule6", "PACKET_ACTION", "REDIRECT:" + vars.D1T1P2)
    change_acl_rules(acl_data.acl_json_config_d1, "L2_MAC_INGRESS|macrule1", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_d1, "L2_MAC_INGRESS|macrule2", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_d1, "L2_MAC_EGRESS|macrule3", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_d1, "L2_MAC_EGRESS|macrule4", "VLAN", data.vlan)
    acl_config1 = acl_data.acl_json_config_d1
    add_port_to_acl_table(acl_config1, 'L3_IPV4_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config1, 'L3_IPV4_EGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config1, 'L2_MAC_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config1, 'L2_MAC_EGRESS', vars.D1T1P1)
    acl_config2 = acl_data.acl_json_config_d2
    add_port_to_acl_table(acl_config2, 'L3_IPV6_INGRESS', vars.D2T1P1)
    add_port_to_acl_table(acl_config2, 'L3_IPV6_EGRESS', vars.D2T1P1)

    def config_dut1():
        acl_obj.apply_acl_config(vars.D1, acl_config1)

    def config_dut2():
        acl_obj.apply_acl_config(vars.D2, acl_config2)

    def tg_config():
    # create streams
        print_log('Creating streams')
        create_streams("tg1", "tg2", acl_config1['ACL_RULE'], "L3_IPV4_INGRESS", \
                       mac_src="00:0a:01:00:00:01", mac_dst="00:0a:01:00:11:02", dscp=62)
        create_streams("tg1", "tg2", acl_config2['ACL_RULE'], "L3_IPV6_EGRESS", \
                       mac_src="00:0a:01:00:00:01", mac_dst="00:0a:01:00:11:02")
        create_streams("tg2", "tg1", acl_config2['ACL_RULE'], "L3_IPV6_INGRESS", \
                       mac_src="00:0a:01:00:11:02", mac_dst="00:0a:01:00:00:01")
        create_streams("tg2", "tg1", acl_config1['ACL_RULE'], "L3_IPV4_EGRESS", \
                       mac_src="00:0a:01:00:11:02", mac_dst="00:0a:01:00:00:01",dscp=61)
        create_streams("tg1", "tg2", acl_config1['ACL_RULE'], "L2_MAC_INGRESS|macrule1", \
                       mac_src="00:0a:01:00:00:03", mac_dst="00:0a:01:00:11:04", pcp=4, dei=1)
        create_streams("tg2", "tg1", acl_config1['ACL_RULE'], "L2_MAC_EGRESS|macrule3", \
                       mac_src="00:0a:01:00:11:04", mac_dst="00:0a:01:00:00:03", pcp=4, dei=1)
        create_streams("tg1", "tg2", acl_config1['ACL_RULE'], "L2_MAC_INGRESS|macrule2", \
                       mac_src="00:0a:01:00:00:05", mac_dst="00:0a:01:00:11:06", pcp=4, dei=1,ether_type_val=0x0800)
        create_streams("tg2", "tg1", acl_config1['ACL_RULE'], "L2_MAC_EGRESS|macrule4", \
                       mac_src="00:0a:01:00:11:06", mac_dst="00:0a:01:00:00:05", pcp=4, dei=1)
        print_log('Completed module configuration')

    utils.exec_all(True, [utils.ExecAllFunc(tg_config), utils.ExecAllFunc(config_dut1), utils.ExecAllFunc(config_dut2)],
                   first_on_main=True)

    yield
    clear_module_configuration()

@pytest.fixture(scope="function", autouse=True)
def acl_function_hooks(request):
    yield
    if st.get_func_name(request) == "test_ft_acl_ingress_ipv4":
        acl_obj.delete_acl_table(vars.D1, acl_type="ip", acl_table_name=['L3_IPV4_INGRESS'])
    elif st.get_func_name(request) == "test_ft_acl_egress_ipv6":
        acl_obj.delete_acl_table(vars.D2, acl_type="ipv6", acl_table_name=['L3_IPV6_EGRESS'])
    elif st.get_func_name(request) == "test_ft_acl_ingress_ipv4_rollback_usecase_004" or st.get_func_name(request) == "test_ft_acl_egress_ipv4_rollback_usecase_004" or st.get_func_name(request) == "test_ft_acl_egress_ipv6_rollback_usecase_004" or st.get_func_name(request) == "test_ft_acl_ingress_ipv6_rollback_usecase_004":
        st.set_module_params(conf_session=0)

def verify_rule_priority(dut, table_name, acl_type="ip"):
    acl_rule_counters = acl_obj.show_acl_counters(dut, acl_table=table_name, acl_rule='PermitAny7', acl_type=acl_type)
    if len(acl_rule_counters) == 1:
        if (int(acl_rule_counters[0]['packetscnt']) != 0):
            print_log("ACL Rule priority test failed")
            return False
        else:
            return True
    else:
        return True


def clear_and_verify_acl_counters(dut, acl_table, acl_type='ip', **kwargs):
    if not acl_obj.clear_acl_counter(dut, acl_table=acl_table, acl_type=acl_type, **kwargs):
        st.error("Failed to clear ACL counters")
        return False
    acl_rule_counters = acl_obj.show_acl_counters(dut, acl_table=acl_table, acl_type=acl_type)
    for acl_rule_counter in acl_rule_counters:
        if not(acl_rule_counter.get('packetscnt') and acl_rule_counter.get('bytescnt') and int(acl_rule_counter['packetscnt']) == 0 and int(acl_rule_counter['bytescnt']) == 0):
            st.error("ACL counters are not cleared")
            return False
    return True

@pytest.mark.inventory(feature='Config Replace', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['CONF_ROLLBACK_ACL_INGRESS_IPV4_USECASE_004'])
def test_ft_acl_ingress_ipv4_rollback_usecase_004():
    '''
    IPv4 Ingress ACL is applied on DUT1 port connected to TG Port#1
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    To verify the rules being modified or added newly in the ACL using config replace
    '''
    result = True
    err_list = []
    acl_obj.delete_acl_table(vars.D1, acl_type= "mac", acl_table_name=['L2_MAC_INGRESS', 'L2_MAC_EGRESS'])
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 1:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    stats1 = data.tgmap['tg3']['tg'].tg_traffic_stats(port_handle=data.tgmap['tg3']['handle'], mode='aggregate')
    total_rx1 = int(stats1[data.tgmap['tg3']['handle']]['aggregate']['rx']['total_pkts'])
    st.log("total_rx1={}".format(total_rx1))
    if total_rx1 > 100:
        print_log("Traffic successfully redirected")
    else:
        result = False
        err = "step 2:Traffic Successfully not redirected"
        st.error('test_step_failed:' + err)
        err_list.append(err)

    st.log("##################################################")
    st.log("### Step 3: Create a config session")
    st.set_module_params(conf_session=1)

    acl_obj.delete_acl_rule(dut=vars.D1,acl_type='ip', acl_table_name='L3_IPV4_INGRESS', acl_rule_name ='rule1')
    acl_obj.create_acl_rule(dut=vars.D1,acl_type="ip",table_name='L3_IPV4_INGRESS',packet_action="deny",rule_name='rule1',src_ip="1.1.1.1/32",dst_ip="2.2.2.2/32",description='RULE FOR L3_IPV4_INGRESS L3_IPV4_INGRESS|rule1')
    st.log("#############################################################")
    st.log("### Step 4: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D1, "home://dut1_no_acl_db.json")
    st.set_module_params(conf_session=0)

    st.log("##################################################")
    st.log("### Step 5: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 6: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D1, "home://dut1_no_acl_db.json")

    st.log("##################################################")
    st.log("### Step 7: Commit config in  config session with timer 100sec")
    ses_api.config_commit(vars.D1, timeout=100, expect_mode='mgmt-config')
    st.wait(5)

    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    if not result1:
        print_log("Traffic successfully not forwarded")
    else:
        result = False
        err = "step 8:Traffic Successfully  forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.wait(160, "wait time to expires commit timer 100 Sec and config reload timer 60Sec")
    if not utils_obj.retry_api(basic_obj.get_system_status_all_brief, vars.D1, retry_count=12, delay=20):
        result = False
        err = "System is not Ready After Config Reload after commit timer expires"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 10:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    stats1 = data.tgmap['tg3']['tg'].tg_traffic_stats(port_handle=data.tgmap['tg3']['handle'], mode='aggregate')
    total_rx1 = int(stats1[data.tgmap['tg3']['handle']]['aggregate']['rx']['total_pkts'])
    st.log("total_rx1={}".format(total_rx1))
    if total_rx1 > 100:
        print_log("Traffic successfully redirected")
    else:
        result = False
        err = "step 11:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
    st.log("##################################################")
    st.log("### Step 12: Create a config session")
    st.set_module_params(conf_session=1)
    acl_obj.create_acl_rule(dut=vars.D1,acl_type="ip",table_name='L3_IPV4_INGRESS',packet_action="deny",rule_name='rule100',ip_protocol="tcp",src_ip="100.100.100.1/32",dst_ip="200.200.200.2/32")
    st.log("#############################################################")
    st.log("### Step 13: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D1, "home://dut1_no_acl_db.json")
    st.set_module_params(conf_session=0)
    st.log("##################################################")
    st.log("### Step 14: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 15: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D1, "home://dut1_no_acl_db.json")
    config = ["seq 100 deny tcp host 100.100.100.1 host 200.200.200.2"]
    if not ses_api.verify_config_session_diff(vars.D1, config=config, exec_mode="mgmt-user", verify_run_config=False):
        result = False
        err = "step 16:Config not applied "
        st.error('test_step_failed:' + err)
        err_list.append(err)

    st.log("##################################################")
    st.log("### Step 17: Commit config in  config session")
    ses_api.config_commit(vars.D1)
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 18:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    stats1 = data.tgmap['tg3']['tg'].tg_traffic_stats(port_handle=data.tgmap['tg3']['handle'], mode='aggregate')
    total_rx1 = int(stats1[data.tgmap['tg3']['handle']]['aggregate']['rx']['total_pkts'])
    st.log("total_rx1={}".format(total_rx1))
    if total_rx1 > 100:
        print_log("Traffic successfully redirected")
    else:
        result = False
        err = "step 19:Traffic Successfully not redirected"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.set_module_params(conf_session=0)

    st.log("##################################################")
    st.log("### Step 20: Create a config session")
    st.set_module_params(conf_session=1)
    acl_obj.delete_acl_rule(dut=vars.D1,acl_type='ip', acl_table_name='L3_IPV4_INGRESS', acl_rule_name ='rule100')
    st.log("#############################################################")
    st.log("### Step 21: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D1, "home://dut1_no_acl_db.json")
    st.set_module_params(conf_session=0)
    st.log("##################################################")
    st.log("### Step 22: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 23: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D1, "home://dut1_no_acl_db.json")
    st.log("##################################################")
    st.log("### Step 24: Commit config in  config session")
    ses_api.config_commit(vars.D1)

    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 25:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    stats1 = data.tgmap['tg3']['tg'].tg_traffic_stats(port_handle=data.tgmap['tg3']['handle'], mode='aggregate')
    total_rx1 = int(stats1[data.tgmap['tg3']['handle']]['aggregate']['rx']['total_pkts'])
    st.log("total_rx1={}".format(total_rx1))
    if total_rx1 > 100:
        print_log("Traffic successfully redirected")
    else:
        result = False
        err = "step 26:Traffic Successfully not redirected"
        st.error('test_step_failed:' + err)
        err_list.append(err)

    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err_list[0])

@pytest.mark.acl_test345654
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn097'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn136'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn156'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn157'])
@pytest.mark.inventory(testcases=['ft_acl_rule_upgrade'])
@pytest.mark.inventory(testcases=['ft_acl_show_commands'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_drop_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_drop_dst_port_range'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_drop_ip_proto_src_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_drop_ip_proto_src_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_drop_src_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_drop_src_port'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_drop_src_port_range'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_dst_port_range'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_ip_proto_src_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_ip_proto_src_dst_port'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_ip_proto_src_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_ip_proto_src_port'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_l4_dst_port'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_l4_src_port'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_src_and_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_src_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_src_port_range'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_fwd_vlan_l4_dst_port_ip_proto'])
@pytest.mark.inventory(testcases=['ft_acl_v4_ing_drop_dst_port'])
@pytest.mark.inventory(testcases=['ft_acl_v4_ingress_create'])
@pytest.mark.inventory(testcases=['ft_acl_v4_ingress_drop_ip_protocol_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_ingress_drop_ip_protocol_src_port'])
@pytest.mark.inventory(testcases=['ft_acl_v4_ingress_forward_ip_protocol_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_rule_update_full'])
@pytest.mark.inventory(testcases=['ft_aclshow'])
@pytest.mark.inventory(testcases=['ft_ipv4_acl_in_srcip_dstip_port_redirect'])
@pytest.mark.inventory(testcases=['ft_ipv4_acl_in_srcip_dstport_redirect'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_dstip_l4dstport_range_forward'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_ip_protocol'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_l4ports_forward'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_l4srcport_range_l4dstport_range_forward'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_srcip_dstip_drop'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_srcip_dstip_forward'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_srcip_dstip_redirect'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_srcip_ipprotocol_forward'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_srcip_l4dst_port_drop'])
@pytest.mark.inventory(testcases=['ipv4acl_ingress_tcpflas_drop'])
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik', testcases=['ft_acl_v4_in_intf'])
def test_ft_acl_ingress_ipv4():
    '''
    IPv4 Ingress ACL is applied on DUT1 port connected to TG Port#1
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    acl_obj.delete_acl_table(vars.D1, acl_type= "mac", acl_table_name=['L2_MAC_INGRESS', 'L2_MAC_EGRESS'])
    # acl_obj.delete_acl_table(vars.D1, acl_table_name='L2_MAC_EGRESS')
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV4_INGRESS"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    print_log('Verifing IPv4 Ingress ACL hit counters')
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': i} for i in [1,2,4,5,6]]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': 7}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_INGRESS", counters_dict)
    result3 = verify_rule_priority(vars.D1, "L3_IPV4_INGRESS")
    stats1 = data.tgmap['tg3']['tg'].tg_traffic_stats(port_handle=data.tgmap['tg3']['handle'], mode='aggregate')
    total_rx1 = int(stats1[data.tgmap['tg3']['handle']]['aggregate']['rx']['total_pkts'])
    st.log("total_rx1={}".format(total_rx1))
    if total_rx1 > 100:
        print_log("Traffic successfully redirected")
    else:
        st.report_fail("test_case_failed")
    if not acl_obj.clear_acl_counter(vars.D1, acl_table='L3_IPV4_INGRESS', acl_type='ip'):
        st.report_fail("msg", "Failed to clear ACL counters")
    counters_dict = {'non_hit_rules': [{'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': i} for i in list(range(1,3))+list(range(4,8))]}
    result4 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_INGRESS", counters_dict)
    acl_utils.report_result(result1 and result2 and result3 and result4)

@pytest.mark.inventory(feature='Config Replace', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['CONF_ROLLBACK_ACL_EGRESS_IPV4_USECASE_004'])
def test_ft_acl_egress_ipv4_rollback_usecase_004():
    '''
    IPv4 Egress ACL is applied on DUT1 port connected to TG Port#1
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    To verify the rules being modified or added newly in the ACL using config replace
    '''
    result = True
    err_list = []
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 1:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)

    st.log("##################################################")
    st.log("### Step 2: Create a config session")
    st.set_module_params(conf_session=1)

    acl_obj.delete_acl_rule(dut=vars.D1,acl_type='ip', acl_table_name='L3_IPV4_EGRESS', acl_rule_name ='rule1')
    acl_obj.create_acl_rule(dut=vars.D1,acl_type="ip",table_name='L3_IPV4_EGRESS',packet_action="deny",rule_name='rule1',src_ip="192.138.10.1/32",dst_ip="55.46.45.2/32",description='RULE FOR L3_IPV4_EGRESS L3_IPV4_EGRESS|rule1')
    st.log("#############################################################")
    st.log("### Step 3: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D1, "home://dut1_no_acl_db.json")
    st.set_module_params(conf_session=0)

    st.log("##################################################")
    st.log("### Step 4: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 5: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D1, "home://dut1_no_acl_db.json")

    st.log("##################################################")
    st.log("### Step 7: Commit config in  config session with timer 100sec")
    ses_api.config_commit(vars.D1, timeout=100, expect_mode='mgmt-config')
    st.wait(5)
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    if not result1:
        print_log("Traffic successfully not  forwarded")
    else:
        result = False
        err = "step 7:Traffic Successfully   forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.wait(160, "wait time to expires commit timer 100 Sec and config reload timer 60Sec")
    if not utils_obj.retry_api(basic_obj.get_system_status_all_brief, vars.D1, retry_count=12, delay=20):
        result = False
        err = "System is not Ready After Config Reload after commit timer expires"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    if result1:
        print_log("Traffic successfully   forwarded")
    else:
        result = False
        err = "step 7:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.log("##################################################")
    st.log("### Step 9: Create a config session")
    st.set_module_params(conf_session=1)
    acl_obj.create_acl_rule(dut=vars.D1,acl_type="ip",table_name='L3_IPV4_EGRESS',packet_action="permit",rule_name='rule100',ip_protocol="tcp",src_ip="100.100.100.1/32",dst_ip="200.200.200.2/32")
    st.log("#############################################################")
    st.log("### Step 10: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D1, "home://dut1_no_acl_db.json")
    st.set_module_params(conf_session=0)
    st.log("##################################################")
    st.log("### Step 11: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 12: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D1, "home://dut1_no_acl_db.json")
    config = ["seq 100 permit tcp host 100.100.100.1 host 200.200.200.2"]
    if not ses_api.verify_config_session_diff(vars.D1, config=config, exec_mode="mgmt-user", verify_run_config=False):
        result = False
        err = "step 13:Config not applied "
        st.error('test_step_failed:' + err)
        err_list.append(err)

    st.log("##################################################")
    st.log("### Step 14 Commit config in  config session with timer 100sec")
    ses_api.config_commit(vars.D1, timeout=100, expect_mode='mgmt-config')
    st.wait(160, "wait time to expires commit timer 100 Sec and config reload timer 60Sec")
    if not utils_obj.retry_api(basic_obj.get_system_status_all_brief, vars.D1, retry_count=12, delay=20):
        result = False
        err = "System is not Ready After Config Reload after commit timer expires"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 15:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.log("##################################################")
    st.log("### Step 16: Create a config session")
    st.set_module_params(conf_session=1)
    acl_obj.delete_acl_rule(dut=vars.D1,acl_type='ip', acl_table_name='L3_IPV4_EGRESS', acl_rule_name ='rule100')
    st.log("#############################################################")
    st.log("### Step 17: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D1, "home://dut1_no_acl_db.json")
    st.set_module_params(conf_session=0)
    st.log("##################################################")
    st.log("### Step 18: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 19: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D1, "home://dut1_no_acl_db.json")
    st.log("##################################################")
    st.log("### Step 20: Commit config in  config session")
    ses_api.config_commit(vars.D1)

    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 21:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)

    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err_list[0])

@pytest.mark.acl_test
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_acl_egress_fwd_src_ipv4'])
@pytest.mark.inventory(testcases=['ft_acl_v4_deny_all_after_forward_rule'])
@pytest.mark.inventory(testcases=['ft_acl_v4_eg_drop_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_eg_drop_src_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_eg_drop_src_ip_and_dst_port'])
@pytest.mark.inventory(testcases=['ft_acl_v4_eg_fwd_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_eg_fwd_src_and_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v4_eg_fwd_src_ip'])
def test_ft_acl_egress_ipv4():
    '''
    IPv4 Egress ACL is applied on DUT1 port connected to TG Port#1
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    '''
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV4_EGRESS"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    print_log('Verifing IPv4 Egress ACL hit counters')
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV4_EGRESS', 'rule_no': i} for i in range(1,4)]}
    counters_dict['non_hit_rules'] = [{'access_list_name': 'L3_IPV4_EGRESS', 'rule_no': i} for i in range(4,6)]
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_EGRESS", counters_dict)
    if not acl_obj.clear_acl_counter(vars.D1, acl_table='L3_IPV4_EGRESS', acl_type='ip'):
        st.report_fail("msg", "Failed to clear ACL counters")
    counters_dict = {'non_hit_rules': [{'access_list_name': 'L3_IPV4_EGRESS', 'rule_no': i} for i in list(range(1,4))+list(range(4,6))]}
    result3 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_EGRESS", counters_dict)
    acl_utils.report_result(result1 and result2 and result3)


@pytest.mark.inventory(feature='Config Replace', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['CONF_ROLLBACK_ACL_EGRESS_IPV6_USECASE_004'])
def test_ft_acl_egress_ipv6_rollback_usecase_004():
    '''
    IPv6 Egress ACL is applied on DUT2 port connected to TG Port #2
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    To verify the rules being modified or added newly in the ACL using config replace
    '''
    result = True
    err_list = []
    acl_obj.delete_acl_table(vars.D1, acl_type= "mac", acl_table_name=['L2_MAC_INGRESS', 'L2_MAC_EGRESS'])
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 1:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)

    st.log("##################################################")
    st.log("### Step 2: Create a config session")
    st.set_module_params(conf_session=1)

    acl_obj.delete_acl_rule(dut=vars.D2,acl_type='ipv6', acl_table_name='L3_IPV6_EGRESS', acl_rule_name ='rule1')
    acl_obj.create_acl_rule(dut=vars.D2,acl_type="ipv6",table_name='L3_IPV6_EGRESS',packet_action="deny",rule_name='rule1',src_ip="2001::10/128",dst_ip="3001::10/128",description='RULE FOR L3_IPV6_EGRESS L3_IPV6_EGRESS|rule1')
    st.log("#############################################################")
    st.log("### Step 3: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D2, "home://dut2_no_acl_db.json")
    st.set_module_params(conf_session=0)

    st.log("##################################################")
    st.log("### Step 4: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 5: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D2, "home://dut2_no_acl_db.json")

    st.log("##################################################")
    st.log("### Step 6 Commit config in  config session with timer 100sec")
    ses_api.config_commit(vars.D2, timeout=100, expect_mode='mgmt-config')
    st.wait(5)
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    if not result1:
        print_log("Traffic successfully not  forwarded")
    else:
        result = False
        err = "step 7:Traffic Successfully  forwarded - not expected"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.wait(160, "wait time to expires commit timer 100 Sec and config reload timer 60Sec")
    if not utils_obj.retry_api(basic_obj.get_system_status_all_brief, vars.D2, retry_count=12, delay=20):
        result = False
        err = "System is not Ready After Config Reload after commit timer expires"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    if result1:
        print_log("Traffic successfully  forwarded")
    else:
        result = False
        err = "step 7:Traffic Successfully not forwarded - not expected"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.log("##################################################")
    st.log("### Step 9: Create a config session")
    st.set_module_params(conf_session=1)
    acl_obj.create_acl_rule(dut=vars.D2,acl_type="ipv6",table_name='L3_IPV6_EGRESS',packet_action="permit",rule_name='rule100',ip_protocol="tcp",src_ip="6001::10/128",dst_ip="7001::10/128")
    st.log("#############################################################")
    st.log("### Step 10: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D2, "home://dut2_no_acl_db.json")
    st.set_module_params(conf_session=0)
    st.log("##################################################")
    st.log("### Step 11: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 12: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D2, "home://dut2_no_acl_db.json")
    config = ["seq 100 permit tcp host 6001::10 host 7001::10"]
    if not ses_api.verify_config_session_diff(vars.D2, config=config, exec_mode="mgmt-user", verify_run_config=False):
        result = False
        err = "step 13:Config not applied "
        st.error('test_step_failed:' + err)
        err_list.append(err)

    st.log("##################################################")
    st.log("### Step 14: Commit config in  config session")
    ses_api.config_commit(vars.D2)
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 15:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)

    st.log("##################################################")
    st.log("### Step 16: Create a config session")
    st.set_module_params(conf_session=1)
    acl_obj.delete_acl_rule(dut=vars.D2,acl_type='ipv6', acl_table_name='L3_IPV6_EGRESS', acl_rule_name ='rule100')
    st.log("#############################################################")
    st.log("### Step 17: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D2, "home://dut2_no_acl_db.json")
    st.set_module_params(conf_session=0)
    st.log("##################################################")
    st.log("### Step 18: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 19: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D2, "home://dut2_no_acl_db.json")
    st.log("##################################################")
    st.log("### Step 20: Commit config in  config session")
    ses_api.config_commit(vars.D2)

    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 21:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)

    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err_list[0])

@pytest.mark.acl_test678
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_acl_v6_eg_drop_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_eg_drop_src_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_eg_fwd_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_eg_fwd_src_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_eg_fwd_src_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_eg_redirect_sip_dip_routingports'])
@pytest.mark.inventory(testcases=['ft_acl_v6_eg_redirect_srcip_dstip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_in_create'])
def test_ft_acl_egress_ipv6():
    '''
    IPv6 Egress ACL is applied on DUT2 port connected to TG Port #2
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    utils.exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    if not clear_and_verify_acl_counters(vars.D2, "L3_IPV6_EGRESS", acl_type="ipv6"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    print_log('Verifying IPv6 Egress ACL hit counters')
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV6_EGRESS', 'rule_no': i} for i in [1, 4]]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L3_IPV6_EGRESS', 'rule_no': 6}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D2, "L3_IPV6_EGRESS", counters_dict, acl_type="ipv6")
    if not acl_obj.clear_acl_counter(vars.D2, acl_table='L3_IPV6_EGRESS', acl_type='ipv6'):
        st.report_fail("msg", "Failed to clear ACL counters")
    counters_dict = {'non_hit_rules': [{'access_list_name': 'L3_IPV6_EGRESS', 'rule_no': i} for i in [1,4,6]]}
    result3 = st.poll_wait(verify_acl_hit_counters, 15, vars.D2, "L3_IPV6_EGRESS", counters_dict, acl_type="ipv6")
    acl_utils.report_result(result1 and result2 and result3)

@pytest.mark.inventory(feature='Config Replace', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['CONF_ROLLBACK_ACL_INGRESS_IPV6_USECASE_004'])
def test_ft_acl_ingress_ipv6_rollback_usecase_004():
    '''
    IPv6 Ingress ACL is applied on DUT2 port connected to TG Port #2
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    To verify the rules being modified or added newly in the ACL using config replace
    '''
    result = True
    err_list = []
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 1:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)

    st.log("##################################################")
    st.log("### Step 2: Create a config session")
    st.set_module_params(conf_session=1)

    acl_obj.delete_acl_rule(dut=vars.D2,acl_type='ipv6', acl_table_name='L3_IPV6_INGRESS', acl_rule_name ='rule1')
    acl_obj.create_acl_rule(dut=vars.D2,acl_type="ipv6",table_name='L3_IPV6_INGRESS',packet_action="deny",rule_name='rule1',src_ip="2001::10/128",dst_ip="3001::10/128",description='RULE FOR L3_IPV6_INGRESS L3_IPV6_INGRESS|rule1')
    st.log("#############################################################")
    st.log("### Step 3: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D2, "home://dut2_no_acl_db.json")
    st.set_module_params(conf_session=0)

    st.log("##################################################")
    st.log("### Step 4: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 5: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D2, "home://dut2_no_acl_db.json")

    st.log("##################################################")
    st.log("### Step 6: Commit config in  config session with timer 100sec")
    ses_api.config_commit(vars.D2, timeout=100, expect_mode='mgmt-config')

    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    if not result1:
        print_log("Traffic successfully not forwarded")
    else:
        result = False
        err = "step 7:Traffic Successfully forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.wait(160, "wait time to expires commit timer 100 Sec and config reload timer 60Sec")
    if not utils_obj.retry_api(basic_obj.get_system_status_all_brief, vars.D2, retry_count=12, delay=20):
        result = False
        err = "System is not Ready After Config Reload after commit timer expires"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 8:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.set_module_params(conf_session=0)
    st.log("##################################################")
    st.log("### Step 9: Create a config session")
    st.set_module_params(conf_session=1)
    acl_obj.create_acl_rule(dut=vars.D2,acl_type="ipv6",table_name='L3_IPV6_INGRESS',packet_action="permit",rule_name='rule100',ip_protocol="tcp",src_ip="6001::10/128",dst_ip="7001::10/128")
    st.log("#############################################################")
    st.log("### Step 10: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D2, "home://dut2_no_acl_db.json")
    st.set_module_params(conf_session=0)
    st.log("##################################################")
    st.log("### Step 11: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 12: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D2, "home://dut2_no_acl_db.json")
    config = ["seq 100 permit tcp host 6001::10 host 7001::10"]
    if not ses_api.verify_config_session_diff(vars.D2, config=config, exec_mode="mgmt-user", verify_run_config=False):
        result = False
        err = "step 13:Config not applied "
        st.error('test_step_failed:' + err)
        err_list.append(err)

    st.log("##################################################")
    st.log("### Step 14: Commit config in  config session")
    ses_api.config_commit(vars.D2)
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 15:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)
    st.set_module_params(conf_session=0)

    st.log("##################################################")
    st.log("### Step 16: Create a config session")
    st.set_module_params(conf_session=1)
    acl_obj.delete_acl_rule(dut=vars.D2,acl_type='ipv6', acl_table_name='L3_IPV6_INGRESS', acl_rule_name ='rule100')
    st.log("#############################################################")
    st.log("### Step 17: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D2, "home://dut2_no_acl_db.json")
    st.set_module_params(conf_session=0)
    st.log("##################################################")
    st.log("### Step 18: Create a config session")
    st.set_module_params(conf_session=1)
    st.log("#############################################################")
    st.log("### Step 19: Replace the running config with the specified path config db")
    rep_api.config_replace_in_config_session(vars.D2, "home://dut2_no_acl_db.json")
    st.log("##################################################")
    st.log("### Step 20: Commit config in  config session")
    ses_api.config_commit(vars.D2)
    st.set_module_params(conf_session=0)

    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    if result1:
        print_log("Traffic successfully forwarded")
    else:
        result = False
        err = "step 21:Traffic Successfully not forwarded"
        st.error('test_step_failed:' + err)
        err_list.append(err)

    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err_list[0])

@pytest.mark.community
@pytest.mark.community_fail
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_acl_v6_in_drop_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_in_drop_src_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_in_fwd_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_in_fwd_dstip_ip_protocol'])
@pytest.mark.inventory(testcases=['ft_acl_v6_in_fwd_src_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_in_fwd_src_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_in_fwd_srcip_ip_protocol'])
@pytest.mark.inventory(testcases=['ft_acl_v6_ing_drop_ip_proto_src_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_ing_fwd_eth_type'])
@pytest.mark.inventory(testcases=['ft_acl_v6_ing_fwd_ip_proto_src_dst_ip'])
@pytest.mark.inventory(testcases=['ft_acl_v6_ingress_drop_eth_type'])
@pytest.mark.inventory(testcases=['ft_acl_v6_ingress_drop_ip_protocol'])
@pytest.mark.inventory(testcases=['ft_acl_v6_ingress_drop_ip_protocol_dst_port'])
@pytest.mark.inventory(testcases=['ft_acl_v6_ingress_drop_src_ip_ip_protocol'])
@pytest.mark.inventory(testcases=['ft_acl_v6_ingress_drop_tcp_flags'])
@pytest.mark.inventory(testcases=['ft_acl_v6_ingress_fwd_tcp_flags'])
@pytest.mark.inventory(testcases=['ipv6acl_ingress_ip_protocol'])
@pytest.mark.inventory(testcases=['ipv6acl_ingress_srcip_dstip_drop'])
@pytest.mark.inventory(testcases=['ipv6acl_ingress_srcip_dstip_forward'])
@pytest.mark.inventory(testcases=['ipv6acl_ingress_tcpflags_drop'])
@pytest.mark.inventory(testcases=['ipv6acl_ingress_tcpflags_forward'])
def test_ft_acl_ingress_ipv6():
    '''
    IPv6 Ingress ACL is applied on DUT2 port connected to TG Port #2
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    '''
    utils.exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    if not clear_and_verify_acl_counters(vars.D2, "L3_IPV6_INGRESS", acl_type="ipv6"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    print_log('Verifing IPv6 Ingress ACL hit counters')

    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV6_INGRESS', 'rule_no': i} for i in [1, 3, 4]]}
    counters_dict['non_hit_rules'] = [{'access_list_name': 'L3_IPV6_INGRESS', 'rule_no': i} for i in range(5,7)]
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D2, "L3_IPV6_INGRESS", counters_dict, acl_type="ipv6")
    result3 = verify_rule_priority(vars.D2, "L3_IPV6_INGRESS", acl_type="ipv6")
    if not acl_obj.clear_acl_counter(vars.D2, acl_table='L3_IPV6_INGRESS', acl_type='ipv6'):
        st.report_fail("msg", "Failed to clear ACL counters")
    counters_dict = {'non_hit_rules': [{'access_list_name': 'L3_IPV6_INGRESS', 'rule_no': i} for i in [1,3,4,5,6]]}
    result4 = st.poll_wait(verify_acl_hit_counters, 15, vars.D2, "L3_IPV6_INGRESS", counters_dict, acl_type="ipv6")
    acl_utils.report_result(result1 and result2 and result3 and result4)


@pytest.mark.acl_test
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_mac_acl_eg_port_fwd'])
@pytest.mark.inventory(testcases=['ft_mac_acl_in_port_fwd'])
@pytest.mark.inventory(testcases=['ft_mac_acl_rule_ethertype'])
def test_ft_mac_acl_port():
    '''
    MAC Ingress ACL is applied on DUT1 port connected to TG Port#1
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    print_log('Creating MAC ACL table and apply on Port ')
    acl_obj.acl_delete(vars.D1)
    # acl_obj.delete_acl_table(vars.D1, acl_type="ip", acl_table_name=['L3_IPV4_INGRESS', 'L3_IPV4_EGRESS'])
    acl_config = acl_data.acl_json_config_port_d3
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L2_MAC_EGRESS', vars.D1T1P1)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_INGRESS|macrule1", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_INGRESS|macrule2", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_EGRESS|macrule3", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_EGRESS|macrule4", "VLAN", data.vlan)
    acl_obj.apply_acl_config(vars.D1, acl_config)
    utils.exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D1, "L2_MAC_INGRESS", acl_type="mac"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    print_log('Verifying MAC Ingress packet count')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L2_MAC_INGRESS")
    print_log('Verifying MAC Ingress ACL hit counters')
    counters_dict = {'hit_rules': [{'access_list_name': 'L2_MAC_INGRESS', 'rule_no': i} for i in range(1,3)]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L2_MAC_INGRESS', 'rule_no': 3}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_INGRESS", counters_dict, acl_type="mac")
    if not clear_and_verify_acl_counters(vars.D1, "L2_MAC_EGRESS", acl_type="mac"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    print_log('Verifying MAC Ingress packet count')
    result3 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L2_MAC_EGRESS")
    print_log('Verifing MAC Egress ACL hit counters')
    counters_dict = {'hit_rules': [{'access_list_name': 'L2_MAC_EGRESS', 'rule_no': i} for i in range(3, 5)]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L2_MAC_EGRESS', 'rule_no': 1}
    result4 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_EGRESS", counters_dict, acl_type="mac")
    if not acl_obj.clear_acl_counter(vars.D1, acl_table='L2_MAC_INGRESS', acl_type='mac'):
        st.report_fail("msg", "Failed to clear ACL counters")
    counters_dict = {'non_hit_rules': [{'access_list_name': 'L2_MAC_INGRESS', 'rule_no': i} for i in range(1,4)]}
    result5 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_INGRESS", counters_dict, acl_type="mac")
    if not acl_obj.clear_acl_counter(vars.D1, acl_table='L2_MAC_EGRESS', acl_type='mac'):
        st.report_fail("msg", "Failed to clear ACL counters")
    counters_dict = {'non_hit_rules': [{'access_list_name': 'L2_MAC_EGRESS', 'rule_no': i} for i in [1,3,4]]}
    result6 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_EGRESS", counters_dict, acl_type="mac")
    acl_utils.report_result(result1 and result2 and result3 and result4 and result5 and result6)


@pytest.mark.acl_testacl2
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn105'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn106'])
@pytest.mark.inventory(testcases=['ft_acl_ip_in_forward_port_channel'])
@pytest.mark.inventory(testcases=['ft_acl_ipv6_in_forward_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v6_src_dst_ip_fwd_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v6_src_dst_ip_protocol_fwd_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v6_src_dst_port_drop_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v6_src_dst_port_fwd_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v6_src_dst_port_range_fwd_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v6_src_ip_dst_port_drop_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v6_src_port_dst_port_range_drop_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v6_src_tcpflags_drop_port_channel'])
def test_ft_acl_port_channel_ingress():
    '''
    IPv6 Ingress ACL is applied on DUT1 port channel
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    '''
    # deleting same streams are used for both IPv6 and PortChannel test
    # to avoid conflicts, delete IPv6 rules
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules
    print_log('Creating Ingress ACL table and apply on Port channel')
    acl_config = acl_data.acl_json_ingress_configv6
    add_port_to_acl_table(acl_config, 'L3_IPV6_INGRESS', data.portChannelName)
    acl_obj.apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    utils.exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV6_INGRESS", acl_type="ipv6"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV6_INGRESS', 'rule_no': i} for i in [1,3,4]]}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV6_INGRESS", counters_dict, acl_type="ipv6")
    acl_utils.report_result(result1 and result2)

@pytest.mark.acl_test6
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['acl_po_eg1'])
def test_ft_acl_port_channel_egress():
    '''
    IPv6 Egress ACL is applied on DUT1 port channel
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    print_log('Creating Egress ACL table and apply on Port channel')
    # SONiC supports only one egress table for Switch
    # so deleting already created Egress rule. Revisit this test case,
    # when the support is added
    acl_obj.delete_acl_table(vars.D1, acl_table_name='L3_IPV4_EGRESS', acl_type="ipv6")
    acl_config = acl_data.acl_json_egress_configv6
    add_port_to_acl_table(acl_config, 'L3_IPV6_EGRESS', data.portChannelName)
    acl_obj.apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV6_EGRESS", acl_type="ipv6"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV6_EGRESS', 'rule_no': i} for i in range(1, 3)]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L3_IPV6_EGRESS', 'rule_no': 3}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV6_EGRESS", counters_dict, acl_type="ipv6")
    acl_utils.report_result(result1 and result2)

@pytest.mark.acl_test8
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['acl_po_eg2'])
def test_ft_acl_port_channel_V4_egress():
    '''
    IPv6 Ingress ACL is applied on DUT1 port channel
    Traffic is sent on TG Port #2
    Traffic is recived at TG Port #1
    '''
    # deleting same streams are used for both IPv6 and PortChannel test
    # to avoid conflicts, delete IPv6 rules
    acl_obj.delete_acl_table(vars.D2, acl_type="ip", acl_table_name=['L3_IPV4_EGRESS', 'L3_IPV4_INGRESS'])
    # acl_obj.delete_acl_table(vars.D2, acl_table_name='L3_IPV4_EGRESS')
    # acl_obj.delete_acl_table(vars.D2, acl_table_name='L3_IPV4_INGRESS')
    # Creating Ingress ACL table and rules
    print_log('Creating Ingress ACL table and apply on Port channel')
    acl_config = acl_data.acl_json_egress_configv4
    add_port_to_acl_table(acl_config, 'L3_IPV4_EGRESS', data.portChannelName)
    acl_obj.apply_acl_config(vars.D2, acl_config)
    st.wait(2)
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    acl_utils.report_result(result1)



@pytest.mark.acl_test678
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_acl_v6_eg_vlan'])
def test_ft_acl_vlan_v6_egress():
    '''
    IPv6 Egress ACL is applied on DUT2 vlan
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''

    # Creating Ingress ACL table and rules
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    print_log('Creating Egress ACL table and apply on VLAN')
    acl_config = acl_data.acl_json_config_v6_egress_vlan
    add_port_to_acl_table(acl_config, 'L3_IPV6_EGRESS', "Vlan{}".format(data.vlan))
    acl_obj.apply_acl_config(vars.D2, acl_config)
    utils.exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D2, "L3_IPV6_EGRESS", acl_type="ipv6"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV6_EGRESS', 'rule_no': i} for i in [1,4]]}
    counters_dict['non_hit_rules'] = [{'access_list_name': 'L3_IPV6_EGRESS', 'rule_no': i} for i in range(5, 7)]
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D2, "L3_IPV6_EGRESS", counters_dict, acl_type="ipv6")
    acl_utils.report_result(result1 and result2)

@pytest.mark.acl_test
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_acl_v6_in_vlan'])
def test_ft_acl_vlan_v6_ingress():
    '''
    IPv6 Egress ACL is applied on DUT2 vlan
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on VLAN')
    acl_config = acl_data.acl_json_config_v6_ingress_vlan
    add_port_to_acl_table(acl_config, 'L3_IPV6_INGRESS', "Vlan{}".format(data.vlan))
    acl_obj.apply_acl_config(vars.D2, acl_config)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D2, "L3_IPV6_INGRESS", acl_type="ipv6"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1,'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV6_INGRESS', 'rule_no': i} for i in [1,3,4]]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L3_IPV6_INGRESS', 'rule_no': 5}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D2, "L3_IPV6_INGRESS", counters_dict, acl_type="ipv6")
    acl_utils.report_result(result1 and result2)

@pytest.mark.acl_test
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_acl_v4_eg_vlan'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_vlan'])
def test_ft_acl_vlan_V4_ingress():
    '''
    IPv4 Ingress ACL is applied on DUT1 vlan
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on VLAN')
    acl_config = acl_data.acl_json_ingress_vlan_configv4
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', "Vlan{}".format(data.vlan))
    change_acl_rules(acl_data.acl_json_config_d1, "L3_IPV4_INGRESS|rule6", "PACKET_ACTION", "FORWARD")
    acl_obj.apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV4_INGRESS"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': i} for i in [1,2,4,5,7]]}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_INGRESS", counters_dict)
    acl_utils.report_result(result1 and result2)

@pytest.mark.acl_test
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['acl_vlan_eg'])
def test_ft_acl_vlan_V4_egress():
    '''
    IPv4 Ingress ACL is applied on DUT1 vlan
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on VLAN')
    acl_config = acl_data.acl_json_egress_vlan_configv4
    add_port_to_acl_table(acl_config, 'L3_IPV4_EGRESS', "Vlan{}".format(data.vlan))
    acl_obj.apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV4_EGRESS"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1,'tg1', vars.T1D1P1,  "L3_IPV4_EGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV4_EGRESS', 'rule_no': i} for i in range(1,4)]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L3_IPV4_EGRESS', 'rule_no': 4}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_EGRESS", counters_dict)
    acl_utils.report_result(result1 and result2)

@pytest.mark.acl_test
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn102'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn103'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn104'])
@pytest.mark.inventory(testcases=['ft_in_acl_v4_src_dst_ip_drop_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v4_src_dst_ip_fwd_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v4_src_dst_ip_src_port_fwd_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v4_src_dst_port_drop_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v4_src_dst_port_range_drop_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v4_src_dst_port_range_fwd_port_channel'])
@pytest.mark.inventory(testcases=['ft_in_acl_v4_src_tcpflags_drop_port_channel'])
def test_ft_acl_port_channel_V4_ingress():
    '''
    IPv6 Ingress ACL is applied on DUT1 port channel
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    '''
    # deleting same streams are used for both IPv6 and PortChannel test
    # to avoid conflicts, delete IPv6 rules
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules
    print_log('Creating Ingress ACL table and apply on Port channel')
    acl_config = acl_data.acl_json_ingress_configv4
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', data.portChannelName)
    change_acl_rules(acl_data.acl_json_config_d1, "L3_IPV4_INGRESS|rule6", "PACKET_ACTION", "DROP")
    acl_obj.apply_acl_config(vars.D2, acl_config)
    st.wait(2)

    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    acl_utils.report_result(result1)

@pytest.mark.acl_test678
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_acl_v4_eg_switch'])
@pytest.mark.inventory(testcases=['ft_acl_v4_in_switch'])
def test_ft_v4_acl_switch():
    '''
    IPv4 Ingress ACL is applied on DUT1 Switch
    Traffic is sent on TG Port #1 and received at TG Port #2 for ingress
    Traffic is sent on TG Port #2 and received at TG Port #1 for egress
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    print_log('Creating ACL table and apply on switch')
    acl_config = acl_data.acl_json_config_v4_switch
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', "Switch")
    add_port_to_acl_table(acl_config, 'L3_IPV4_EGRESS', "Switch")
    change_acl_rules(acl_data.acl_json_config_d1, "L3_IPV4_INGRESS|rule6", "PACKET_ACTION", "DROP")
    if not acl_obj.apply_acl_config(vars.D1, acl_config):
        st.report_fail("acl_config_status", "using V4 ACL Switch", "FAILED")
    st.wait(2)
    utils.exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV4_INGRESS"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': i} for i in [1,2,4,5,6]]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': 7}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_INGRESS", counters_dict)
    utils.exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV4_EGRESS"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    utils.exec_all(True, [[get_interface_counters, vars.D1, vars.D1T1P1], [get_interface_counters, vars.D2, vars.D2T1P1]])
    result3 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV4_EGRESS', 'rule_no': i} for i in range(1,4)]}
    counters_dict['non_hit_rules'] = [{'access_list_name': 'L3_IPV4_EGRESS', 'rule_no': i} for i in range(4,6)]
    result4 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_EGRESS", counters_dict)

    acl_utils.report_result(result1 and result2 and result3 and result4)


@pytest.mark.acl_test
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_mac_acl_eg_switch'])
@pytest.mark.inventory(testcases=['ft_mac_acl_in_switch'])
def test_ft_mac_acl_switch():
    '''
    IPv4 Ingress ACL is applied on switch
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules

    print_log('Creating ACL table and apply on switch')
    acl_config = acl_data.acl_json_config_switch_d3
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', "Switch")
    if not acl_obj.apply_acl_config(vars.D1, acl_config):
        st.report_fail("acl_config_status", "using MAC ACL Switch", "FAILED")
    acl_obj.show_acl_rule(vars.D1)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D1, "L2_MAC_INGRESS", acl_type='mac'):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L2_MAC_INGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L2_MAC_INGRESS', 'rule_no': i} for i in range(1,3)]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L2_MAC_INGRESS', 'rule_no': 3}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_INGRESS", counters_dict, acl_type='mac')
    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['acl_sw_eg'])
def test_ft_mac_acl_switch_egress():
    '''
    IPv4 Egress ACL is applied on switch
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules

    print_log('Creating ACL table and apply on switch')
    acl_config1 = acl_data.acl_json_config_switch_d3_egress
    add_port_to_acl_table(acl_config1, 'L2_MAC_EGRESS', "Switch")
    if not acl_obj.apply_acl_config(vars.D1, acl_config1):
        st.report_fail("acl_config_status", "using MAC ACL Switch in EGRESS", "FAILED")
    acl_obj.show_acl_rule(vars.D1)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D1, "L2_MAC_EGRESS", acl_type='mac'):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L2_MAC_EGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L2_MAC_EGRESS', 'rule_no': i} for i in range(3,5)]}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_EGRESS", counters_dict, acl_type='mac')
    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_mac_acl_eg_vlan_fwd'])
@pytest.mark.inventory(testcases=['ft_mac_acl_in_vlan_fwd'])
def test_ft_mac_acl_vlan():
    '''
    IPv4 Ingress ACL is applied on DUT1 vlan
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on VLAN')
    acl_config = acl_data.acl_json_config_vlan_d3
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', "Vlan{}".format(data.vlan))
    add_port_to_acl_table(acl_config, 'L2_MAC_EGRESS', "Vlan{}".format(data.vlan))
    acl_obj.apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D1, "L2_MAC_INGRESS", acl_type='mac'):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L2_MAC_INGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L2_MAC_INGRESS', 'rule_no': i} for i in range(1,3)]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L2_MAC_INGRESS', 'rule_no': 3}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_INGRESS", counters_dict, acl_type="mac")
    if not clear_and_verify_acl_counters(vars.D1, "L2_MAC_EGRESS", acl_type='mac'):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    result3 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L2_MAC_EGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L2_MAC_EGRESS', 'rule_no': i} for i in range(3,5)]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L2_MAC_EGRESS', 'rule_no': 1}
    result4 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_EGRESS", counters_dict, acl_type="mac")
    acl_utils.report_result(result1 and result2 and result3 and result4)


@pytest.mark.acl_test
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_mac_acl_in_portchannel_fwd'])
def test_ft_mac_acl_portchannel():
    '''
    IPv4 Ingress ACL is applied on DUT1 vlan
    Traffic is sent on TG Port #1
    Traffic is received at TG Port #2
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules
    print_log('Creating Ingress ACL table and apply on Port channel')
    acl_config = acl_data.acl_json_config_portchannel_d3
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', data.portChannelName)
    change_acl_rules(acl_data.acl_json_config_portchannel_d3, "L2_MAC_INGRESS|macrule1", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_portchannel_d3, "L2_MAC_INGRESS|macrule2", "VLAN", data.vlan)
    acl_obj.apply_acl_config(vars.D2, acl_config)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D2, "L2_MAC_INGRESS", acl_type='mac'):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L2_MAC_INGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L2_MAC_INGRESS', 'rule_no': i} for i in range(1,3)]}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D2, "L2_MAC_INGRESS", counters_dict, acl_type="mac")
    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['mac_acl_eg_po'])
def test_ft_mac_acl_egress_portchannel():
    '''
    IPv4 Ingress ACL is applied on DUT1 vlan
    Traffic is sent on TG Port #1
    Traffic is received at TG Port #2
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules
    print_log('Creating Ingress ACL table and apply on Port channel')
    acl_config = acl_data.acl_json_config_portchannel_egress
    add_port_to_acl_table(acl_config, 'L2_MAC_EGRESS', data.portChannelName)
    change_acl_rules(acl_data.acl_json_config_portchannel_egress, "L2_MAC_EGRESS|macrule3", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_portchannel_egress, "L2_MAC_EGRESS|macrule4", "VLAN", data.vlan)
    acl_obj.apply_acl_config(vars.D2, acl_config)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D2, "L2_MAC_EGRESS", acl_type='mac'):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L2_MAC_EGRESS")
    counters_dict = {'hit_rules': [{'access_list_name': 'L2_MAC_EGRESS', 'rule_no': i} for i in range(3,5)]}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D2, "L2_MAC_EGRESS", counters_dict, acl_type="mac")
    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_testacl1
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_mac_acl_aclshow_advanced_mode'])
def test_ft_mac_acl_port_adv():
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    if not acl_obj.config_hw_acl_mode(vars.D1, counter='per-interface-rule'):
        st.report_fail("hardware_acl_mode_config_failed", "counter per-interface-rule")
    acl_config = acl_data.acl_json_config_d1
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', vars.D1T1P1)
    acl_obj.apply_acl_config(vars.D1, acl_config)
    acl_obj.show_acl_rule(vars.D1)
    if not clear_and_verify_acl_counters(vars.D1, "L2_MAC_INGRESS", acl_type="mac", interface=vars.D1T1P1):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    st.wait(5)
    if not acl_obj.verify_acl_stats(vars.D1, 'L2_MAC_INGRESS', 'macrule1',acl_type="mac"):
        st.report_fail("test_case_failed")
    counters_dict = {'hit_rules': [{'access_list_name': 'L2_MAC_INGRESS', 'rule_no': i} for i in range(1,3)]}
    if not st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_INGRESS", counters_dict, acl_type="mac", interface=vars.D1T1P1, counter_mode = "per-interface-rule"):
        utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
        acl_obj.config_hw_acl_mode(vars.D1, counter='per-rule')
        st.report_fail("msg", "Observing invalid ACL counters")
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    if not acl_obj.config_hw_acl_mode(vars.D1, counter='per-rule'):
        st.report_fail("hardware_acl_mode_config_failed", "counter per-rule")
    st.report_pass("test_case_passed")


@pytest.mark.acl_testacl1
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_v4_acl_aclshow_advanced_mode'])
def test_ft_acl_ingress_ipv4_adv():
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    if not acl_obj.config_hw_acl_mode(vars.D1, counter='per-interface-rule'):
        st.report_fail("hardware_acl_mode_config_failed", "counter per-interface-rule")
    acl_config = acl_data.acl_json_config_d1
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', vars.D1T1P1)
    acl_obj.apply_acl_config(vars.D1, acl_config)
    acl_obj.show_acl_table(vars.D1)
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV4_INGRESS", interface=vars.D1T1P1):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    st.wait(5)
    if not acl_obj.verify_acl_stats(vars.D1, 'L3_IPV4_INGRESS',"rule5",acl_type="ip"):
        st.report_fail("test_case_failed")
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': i} for i in [1,2]+list(range(4,7))]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': 7}
    if not st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_INGRESS", counters_dict, interface=vars.D1T1P1, counter_mode = "per-interface-rule"):
        utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
        acl_obj.config_hw_acl_mode(vars.D1, counter='per-rule')
        st.report_fail("msg", "Observing invalid ACL counters")
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    if not acl_obj.config_hw_acl_mode(vars.D1, counter='per-rule'):
        st.report_fail("hardware_acl_mode_config_failed", "counter per-rule")
    st.report_pass("test_case_passed")


@pytest.mark.acl_test
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn160'])
@pytest.mark.inventory(testcases=['ft_acl_rule_update_with_acl_loader_update_full'])
@pytest.mark.inventory(testcases=['ft_acl_rule_update_with_acl_loader_update_increment'])
@pytest.mark.inventory(testcases=['ft_acl_v4_rule_update_full'])
@pytest.mark.inventory(testcases=['ft_acl_v4_rule_update_incremental'])
@pytest.mark.inventory(testcases=['ft_ipv4_acl_loader_add'])
def test_ft_acl_loader():
    '''
        ACL rule update using config-loader
        ACL rule add
        check for rule upgrade
    '''
    if st.get_ui_type(vars.D1) in ["klish", "rest-put", "rest-patch"]:
        msg = st.log("ACL LOADER NOT SUPPORTED for {}".format(st.get_ui_type(vars.D1)))
        st.report_unsupported("test_case_unsupported", msg)
    data.v4_in_tab = 'L3_IPV4_INGRESS'
    data.v4_eg_tab = 'L3_IPV4_EGRESS'
    data.v6_in_tab = 'L3_IPV6_INGRESS'
    data.v6_eg_tab = 'L3_IPV6_EGRESS'
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    acl_config = acl_data.acl_json_config_table
    add_port_to_acl_table(acl_config, data.v4_in_tab, vars.D1T1P1)
    add_port_to_acl_table(acl_config, data.v4_eg_tab, vars.D1T1P1)
    add_port_to_acl_table(acl_config, data.v6_in_tab, vars.D1T1P1)
    add_port_to_acl_table(acl_config, data.v6_eg_tab, vars.D1T1P2)
    acl_obj.apply_acl_config(vars.D1, acl_config)
    data.json_data = acl_rules_data.multiple_acl_rules
    data.json_data1 = acl_rules_data.add_acl_rules
    acl_obj.show_acl_table(vars.D1)
    st.log('Configure acl rules using "acl-loader update"')
    acl_obj.config_acl_loader_update(vars.D1, 'full', data.json_data, config_type="acl_update")
    rule_update = acl_obj.get_acl_rule_count(vars.D1)
    st.log('Add acl rules using "acl-loader add" to existing rules')
    acl_obj.config_acl_loader_update(vars.D1, 'add', data.json_data1, config_type="acl_add")
    rule_add = acl_obj.get_acl_rule_count(vars.D1)
    if (rule_add[data.v4_in_tab] > rule_update[data.v4_in_tab]
            and rule_add[data.v6_in_tab] > rule_update[data.v6_in_tab]
            and rule_add[data.v4_eg_tab] > rule_update[data.v4_eg_tab]
            and rule_add[data.v6_eg_tab] > rule_update[data.v6_eg_tab]):
        print_log("New rules successfully added using acl-loader")
    else:
        st.report_fail('test_case_failed')
    print_log('Configure acl rules using "config acl update"')
    acl_obj.config_acl_loader_update(vars.D1, 'full', data.json_data)
    config_acl_full = acl_obj.get_acl_rule_count(vars.D1)
    if (config_acl_full[data.v4_in_tab] < rule_add[data.v4_in_tab]
            and config_acl_full[data.v6_in_tab] < rule_add[data.v6_in_tab]
            and config_acl_full[data.v4_eg_tab] < rule_add[data.v4_eg_tab]
            and config_acl_full[data.v6_eg_tab] < rule_add[data.v6_eg_tab]):
        print_log("Successfully added rules using 'config acl update'")
    else:
        st.report_fail('test_case_failed')
    print_log('Add acl rules using "config acl add" to existing rules')
    acl_obj.config_acl_loader_update(vars.D1, 'add', data.json_data1)
    config_acl_add = acl_obj.get_acl_rule_count(vars.D1)
    if not(config_acl_add[data.v4_in_tab] > config_acl_full[data.v4_in_tab]
            and config_acl_add[data.v6_in_tab] > config_acl_full[data.v6_in_tab]
            and config_acl_add[data.v4_eg_tab] > config_acl_full[data.v4_eg_tab]
            and config_acl_add[data.v6_eg_tab] > config_acl_full[data.v6_eg_tab]):
        print_log("Failed to add new rules using config acl")
        st.report_fail('test_case_failed')
    else:
        print_log("New rules successfully added using config acl")
    st.report_pass("test_case_passed")


@pytest.mark.acl_test
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_acl_v6_in_intf'])
def test_ft_acl_icmpv6():
    '''
        TC_id: ft_acl_v6_in_intf
        Description: Verify that ipv6 ingress acl works fine when bound to interface
    '''
    ipv6_src_address = "2001::2"
    ipv6_src_address1 = "2001::3"
    data.af_ipv6 = "ipv6"
    utils.exec_all(True, [
        utils.ExecAllFunc(ipobj.config_ip_addr_interface, vars.D1, "Vlan" + str(data.vlan), ipv6_src_address, 96,
                          family=data.af_ipv6),
        utils.ExecAllFunc(ipobj.config_ip_addr_interface, vars.D2, "Vlan" + str(data.vlan), ipv6_src_address1, 96,
                          family=data.af_ipv6),
    ])
    if not ipobj.ping(vars.D2, ipv6_src_address ,family='ipv6', count=3):
        st.report_fail("ping_fail",ipv6_src_address )
    else:
        st.log("Successfully forwarded icmp packet")
    utils.exec_all(True, [
        utils.ExecAllFunc(ipobj.delete_ip_interface, vars.D1, "Vlan" + str(data.vlan), ipv6_src_address, 96,
                          family=data.af_ipv6),
        utils.ExecAllFunc(ipobj.delete_ip_interface, vars.D2, "Vlan" + str(data.vlan), ipv6_src_address1, 96,
                          family=data.af_ipv6),
    ])
    st.report_pass("ping_success")


@pytest.mark.acl_testacl222
@pytest.mark.inventory(feature='ACL Rate Limiting', release='Buzznik')
@pytest.mark.inventory(testcases=['ft_mac_v4_acl_priority_ingress'])
def test_ft_mac_acl_prioirty_ingress():
    '''
    MAC and IPv4 Ingress ACL is applied on DUT1
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on port')
    acl_config = acl_data.acl_json_config_priority
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', vars.D1T1P1)
    # add_port_to_acl_table(acl_config, 'L3_IPV4_EGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', vars.D1T1P1)
    # add_port_to_acl_table(acl_config, 'L2_MAC_EGRESS', vars.D1T1P1)
    acl_obj.apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    if not clear_and_verify_acl_counters(vars.D1, "L2_MAC_INGRESS", acl_type='mac'):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    if not clear_and_verify_acl_counters(vars.D1, "L3_IPV4_INGRESS"):
        st.report_fail("msg", "Failed to clear/verify the ACL counters")
    transmit('tg1')
    #transmit('tg2')
    print_log('Check acl priority to verify packets are forwarded when MAC and IPv4 ACLs rules are in "forward"')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS|rule1")
    print_log('Check acl priority to verify packets are dropped when MAC acl rule is forward and IPv4 ACL rule is in "drop"')
    result2 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS|rule4")
    counters_dict = {'hit_rules': {'access_list_name': 'L2_MAC_INGRESS', 'rule_no': 1}}
    result3 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L2_MAC_INGRESS", counters_dict, acl_type="mac")
    print_log('Verify ACL hit counters on IPv4)" ')
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': i} for i in [1,4]]}
    result4 = st.poll_wait(verify_acl_hit_counters, 15, vars.D1, "L3_IPV4_INGRESS", counters_dict)
    acl_utils.report_result(result1 and result2 and result3 and result4)

@pytest.mark.acl_test
@pytest.mark.community_unsupported
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_eg_acl_conf_rest'])
@pytest.mark.inventory(testcases=['ft_verify_acl_conf_rest'])
def test_acl_rest():
    acl_aclname = "L3_IPV4_INGRESS"
    acl_aclname1 = "L3_IPV4_EGRESS"
    acl_rulename = "rule2"
    acl_rulename1 = "rule2"
    acl_in_stage = 'INGRESS'
    acl_eg_stage = 'EGRESS'
    acl_src_interface = vars.D1T1P1
    acl_priority = 2000
    acl_priority1 = 4000
    acl_ip_protocol = 17
    acl_src_ip = "5.5.5.5/16"
    acl_dst_ip = "9.9.9.9/16"
    acl_src_ip1 = "88.67.45.9/32"
    acl_dst_ip1 = "12.12.12.12/16"
    acl_l4_src_port_range = "100-500"
    acl_pkt_action = "FORWARD"
    acl_pkt_action_drop = "DROP"
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    rest_url = "/restconf/data/{}".format(YANG_MODEL)
    ACL_TABLE = {"ACL_TABLE_LIST": [
        {"aclname": acl_aclname, "stage": acl_in_stage, "type": "L3", "ports": [acl_src_interface]},
        {"aclname": acl_aclname1, "stage": acl_eg_stage, "type": "L3", "ports": [acl_src_interface]}]
    }
    ACL_RULE = {"ACL_RULE_LIST": [{"aclname": acl_aclname, "rulename": acl_rulename, "PRIORITY": acl_priority,
                                   "PACKET_ACTION": acl_pkt_action,
                                   "IP_PROTOCOL": acl_ip_protocol, "L4_SRC_PORT_RANGE": acl_l4_src_port_range,
                                   "SRC_IP": acl_src_ip, "DST_IP": acl_dst_ip},
                                  {"aclname": acl_aclname1, "rulename": acl_rulename1, "PRIORITY": acl_priority1,
                                   "PACKET_ACTION": acl_pkt_action_drop, "IP_PROTOCOL": acl_ip_protocol,
                                   "SRC_IP": acl_src_ip1, "DST_IP": acl_dst_ip1}
                                  ]}
    Final_dict = {'sonic-acl:sonic-acl': {'ACL_TABLE': ACL_TABLE, 'ACL_RULE': ACL_RULE}}
    st.log("#################")
    st.log(Final_dict)
    if not Final_dict:
        st.report_fail("operation_failed_msg", 'to form acl data')
    op = st.rest_modify(vars.D1, rest_url, Final_dict)
    if not rest_status(op['status']):
        st.report_fail("operation_failed")
    response = st.rest_read(vars.D1, rest_url)
    if response and response["status"] == 200:
        data1 = response["output"][YANG_MODEL]["ACL_TABLE"]["ACL_TABLE_LIST"]
        if not data1:
            st.log("DATA IN RESPONSE IS EMPTY -- {}".format(data1))
        else:
            data2 = response["output"][YANG_MODEL]["ACL_RULE"]["ACL_RULE_LIST"]
            if not data2:
                st.log("DATA IN RESPONSE IS EMPTY -- {}".format(data2))
    else:
        st.log("RESPONSE -- {}".format(response))
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS|rule2")
    transmit('tg2')
    result2 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS|rule2")
    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
@pytest.mark.community_unsupported
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_verify_acl_conf_gNMI'])
def test_ft_acl_gnmi():
    """Verify that ipv4 acls working fine on gNMI"""
    acl_aclname = "L3_IPV4_INGRESS"
    acl_rulename = "rule2"
    acl_in_stage = 'INGRESS'
    acl_priority = 2000
    acl_ip_protocol = 17
    acl_pkt_action = "FORWARD"
    acl_l4_src_port_range = "100-500"
    acl_src_ip = "5.5.5.5/16"
    acl_dst_ip = "9.9.9.9/16"
    acl_src_interface = vars.D1T1P1
    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    xpath = "/sonic-acl:sonic-acl/"
    ACL_TABLE = {"ACL_TABLE_LIST": [
        {"aclname": acl_aclname, "stage": acl_in_stage, "type": "L3", "ports": [acl_src_interface]}]}
    ACL_RULE = {"ACL_RULE_LIST": [{"aclname": acl_aclname, "rulename": acl_rulename, "PRIORITY": acl_priority,
                                   "PACKET_ACTION": acl_pkt_action,
                                   "IP_PROTOCOL": acl_ip_protocol, "L4_SRC_PORT_RANGE": acl_l4_src_port_range,
                                   "SRC_IP": acl_src_ip, "DST_IP": acl_dst_ip},
                                  ]}
    json_content = {'sonic-acl:sonic-acl': {'ACL_TABLE': ACL_TABLE, 'ACL_RULE': ACL_RULE}}
    gnmi_set_out = gnmiapi.gnmi_set(vars.D1, xpath, json_content)
    if not gnmi_set_out:
        st.report_fail("error_string_found", ' ', ' ')
    gnmi_get_out = gnmiapi.gnmi_get(vars.D1, xpath)
    if "rpc error:" in gnmi_get_out:
        st.report_fail("error_string_found", 'rpc error:', ' ')
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS|rule2")
    acl_utils.report_result(result1)


@pytest.fixture(scope="function")
def MacAcl_gnmi_001_fixture(request):
    cli_type = st.get_ui_type(vars.D1)
    yield
    acl_obj.config_access_group(vars.D1, acl_type=data.create_type, table_name=data.create_acl_name,
                               port=vars.D1T1P1, access_group_action='in', cli_type=cli_type, config="no")
    acl_obj.delete_acl_table(vars.D1, acl_type=data.create_type, acl_table_name=[data.create_acl_name])

@pytest.mark.inventory(feature='Replace_BasicL2', release='Cyrus4.1.1')
@pytest.mark.inventory(testcases=['BasicL2_Replace_MacAcl_001'])
def test_BasicL2_Replace_MacAcl_001(MacAcl_gnmi_001_fixture):
    '''
        Verify Mac Acl states and functionality by modifying parameters using GNMI Replace.
        This test function will be executed for Gnmi & Rest UI types and
        report unsupported for Klish and Click.

        Approach:
        1. Using CREATE, configure all possible attributes (non-default values)
        2. Using GET, Validate configure and operational state (bgp, mclag session is up etc)
        3. Using REPLACE, replace 1 or 2 attributes,
        4. Using GET, Validate that specified attribute is modified and
        all other remaining is set to default (if it has a default value) or null
        5. Using REPLACE, replace all attributes,
        6. Using GET, Validate configure and operational state (bgp, mclag session is up etc)
        7. Validate traffic
        8. Using UPDATE, set the values used in base_config.
    '''
    tc_list = ['BasicL2_Replace_MacAcl_001']
    st.banner("Testcase: Verify Basic Replace in Mac Acl functionality.\n TCs:{}.".format(tc_list))
    cli_type = st.get_ui_type(vars.D1)
    if cli_type not in utils_obj.get_supported_ui_type_list():
        st.report_unsupported("test_execution_skipped", "TestCase not valid for this UI-Type")

    ##### Create Mac Acl Rule with new set of non-default attribute values ##########################
    st.banner("1 Using CREATE, configure all possible attributes (non-default values)",delimiter='=')
    #################################################################################################

    data.create_param_map_1 = {vars.D1: {'Name': data.create_acl_name,
                                         'Type': data.create_type}
                                      }
    
    result = acl_lib.create_acl(vars.D1, data.create_param_map_1, Operation.CREATE)
    data.create_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,                                    
                                         'Action': data.create_action,
                                         'SrcMac': data.create_src_mac,
                                         'SrcMacMask': data.create_src_mac_mask,
                                         'DstMac': data.create_dst_mac,
                                         'DstMacMask': data.create_dst_mac_mask,
                                         'Vlanid': data.create_vlan,
                                         'Dei': data.create_dei,
                                         'Pcp': data.create_pcp,
                                         'PcpMask': data.create_pcpmask}
                                      }

    result = acl_lib.acl_rule_change(vars.D1,data.create_param_map_1,data.create_param_map_2,Operation.CREATE)
    if not result:
        fail_msg = 'Mac Acl Rule Create Failed'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Verify Mac Acl Rule Configured and Operational states #####################
    st.banner("2 Using GET, Validate configure and operational state", delimiter='=')
    #################################################################################

    data.get_param_map_1 = data.create_param_map_1.copy()
    data.get_param_map_2 = data.create_param_map_2.copy()
    result = acl_lib.acl_rule_verify(vars.D1,data.get_param_map_1,data.get_param_map_2)
    if not result:
        fail_msg = 'Mac Acl Rule Verification after Create Failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Replace Single Mac Acl Rule attribute ##############################
    st.banner("3 Using REPLACE, replace 1 or 2 attributes", delimiter='=')
    ########################################################################

    data.repl_param_map_1 = {vars.D1: {'Name': data.create_acl_name,
                                       'Type': data.create_type}
                                    }
    data.repl_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,                                    
                                       'Action': data.create_action,
                                       'SrcMac': data.repl_src_mac_1}
                                    }

    result = acl_lib.acl_rule_change(vars.D1,data.repl_param_map_1,data.repl_param_map_2,Operation.REPLACE)

    ##### Verify specified Mac Acl Rule attribute is modified and remaining set to default ##########
    st.banner("4 Using GET, Validate that specified attribute is modified and all other remaining "\
              "is set to default (if it has a default value) or null", delimiter='=')
    #################################################################################################

    data.get_def_param_map_1 = {vars.D1: {'Name': data.create_acl_name,
                                          'Type': data.create_type}
                                       }
    data.get_def_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,                                
                                          'Action': data.create_action,
                                          'SrcMac': data.repl_src_mac_1,
                                          'DstMac': data.def_dst_mac}
                                       }

    result = acl_lib.acl_rule_verify(vars.D1, data.get_def_param_map_1, data.get_def_param_map_2)
    if not result:
        fail_msg = 'Mac Acl Rule Default attributes after Single Replace Failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Replace ALL Mac Acl Rule attribute values ###################
    st.banner("5 Using REPLACE, replace all attributes", delimiter='=')
    ###################################################################

    data.repl_param_map_1 = {vars.D1: {'Name': data.create_acl_name,
                                       'Type': data.create_type}
                                    }

    data.repl_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,
                                       'Action': data.repl_action,
                                       'SrcMac': data.repl_src_mac_2,
                                       'SrcMacMask': data.repl_src_mac_mask,
                                       'DstMac': data.repl_dst_mac,
                                       'DstMacMask': data.repl_dst_mac_mask,
                                       'Vlanid': data.vlan,
                                       'Dei': data.repl_dei,
                                       'Pcp': data.repl_pcp,
                                       'PcpMask': data.repl_pcpmask}
                                    }

    result = acl_lib.acl_rule_change(vars.D1, data.repl_param_map_1, data.repl_param_map_2, Operation.REPLACE)
    if not result:
        fail_msg = 'Mac Acl Rule Config with Replace All Failed'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Verify configure and operational state ######################################
    st.banner("6 Using GET, Validate configure and operational state", delimiter='=')
    ###################################################################################
    
    data.get_param_map_1 = data.repl_param_map_1.copy()
    data.get_param_map_2 = data.repl_param_map_2.copy()
    result = acl_lib.acl_rule_verify(vars.D1,data.get_param_map_1,data.get_param_map_2)
    if not result:
        fail_msg = 'Mac Acl Rule attributes validation afer Replace All Failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    acl_obj.config_access_group(vars.D1, acl_type=data.create_type, table_name=data.create_acl_name,
                               port=vars.D1T1P1, access_group_action='in', cli_type=cli_type)
    
    ######## Validate Traffic #########################################
    st.banner("7 Validate Mac Acl Rule counters update", delimiter='=')
    ###################################################################
    
    ####### Create Stream ##########
    stream = create_streams("tg1", "tg2", acl_rules_data.mac_acl_rule, data.create_acl_name,
                mac_src=data.repl_src_mac_2, mac_dst=data.repl_dst_mac, return_stream=True)
    
    ####### Tramsmit Streams #######
    print_log("Transmitting streams")
    data.tgmap['tg1']['tg'].tg_traffic_control(action='clear_stats', port_handle= tg_port_list)
    data.tgmap['tg1']['tg'].tg_traffic_control(action='run', stream_handle = stream, duration=1)
    data.tgmap['tg1']['tg'].tg_traffic_control(action='stop', stream_handle = stream)

    ####### Verify Counters #########
    counters_dict = {'hit_rules': {'access_list_name': data.create_acl_name, 'rule_no': data.create_seq}}
    result = st.poll_wait(verify_acl_hit_counters, 10, vars.D1, data.create_acl_name, counters_dict, acl_type=data.create_type)
    if not result:
        fail_msg = 'Mac Acl Rule counters update verification failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    st.report_pass("test_case_passed")