# Threshold Feature FT test cases.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import pytest
import re

from spytest import st, tgapi, SpyTestDict

import apis.system.threshold as tfapi
import apis.switching.vlan as vapi
import apis.system.basic as bcapi
import apis.system.box_services as bsapi
import apis.system.switch_configuration as scapi
import apis.system.logging as slog
import apis.system.snapshot as sfapi
from apis.system.basic import get_cfggen_hwsku, get_hwsku, get_machineconf_platform

from utilities.common import random_vlan_list

@pytest.fixture(scope="module", autouse=True)
def threshold_feature_module_hooks(request):
    global_vars_and_constants_init()
    vars = st.ensure_min_topology('D1T1:4')
    if bcapi.is_campus_build(vars.D1):
        st.report_unsupported('telemetry_unsupported','campus')
    tf_module_config(config='yes')
    yield
    tf_module_config(config='no')


@pytest.fixture(scope="function", autouse=True)
def threshold_feature_func_hooks(request):
    verify_system_map_status(tf_data.max_time_to_check_sys_maps[0], tf_data.max_time_to_check_sys_maps[1])
    yield


def global_vars_and_constants_init():
    global vars
    global tf_data
    vars = st.ensure_min_topology('D1T1:4')
    tf_data = SpyTestDict()
    hw_constants = st.get_datastore(vars.D1, "constants")
    scapi.get_running_config(vars.D1)
    # Global Vars
    tf_data.tg_port_list = [vars.T1D1P1, vars.T1D1P2, vars.T1D1P3, vars.T1D1P4]
    tf_data.port_list = [vars.D1T1P1, vars.D1T1P2, vars.D1T1P3, vars.D1T1P4]
    tf_data.platform = bcapi.get_hwsku(vars.D1).lower()
    tf_data.unicast = 'unicast'
    tf_data.multicast = 'multicast'
    tf_data.tg_current_mode = tf_data.unicast
    tf_data.queues_to_check = ['COUNTERS_PG_NAME_MAP', 'COUNTERS_QUEUE_NAME_MAP']
    tf_data.max_time_to_check_sys_maps = [150, 2]  # Seconds
    tf_data.traffic_duration = 3  # Seconds
    tf_data.test_max_retries_count = 3
    tf_data.need_debug_prints = True
    tf_data.platform = get_hwsku(vars.D1).lower()
    tf_data.config_file = "buffers.json"
    tf_data.device_j2_file = "buffers.json.j2"
    # Common Constants
    tf_data.pg_headroom_un_supported_platforms = hw_constants['THRESHOLD_FEATURE_PG_HEADROOM_UN_SUPPORTED_PLATFORMS']
    tf_data.th3_platforms = hw_constants['TH3_PLATFORMS']
    return tf_data


def tf_module_config(config='yes'):
    if config == 'yes':
        tf_data.vlan = str(random_vlan_list()[0])
        vapi.create_vlan(vars.D1, tf_data.vlan)
        vapi.add_vlan_member(vars.D1, tf_data.vlan, port_list=tf_data.port_list, tagging_mode=True)
        tf_data.tg, tf_data.tg_ph_list, tf_data.stream_tf_data = tf_tg_stream_config()
        tfapi.threshold_feature_debug(vars.D1, mode=['port_map','debug_log_enable'])
    else:
        tf_unconfig()
        vapi.delete_vlan_member(vars.D1, tf_data.vlan, port_list=tf_data.port_list, tagging_mode=True)
        vapi.delete_vlan(vars.D1, tf_data.vlan)


def tf_tg_stream_config():
    st.log('TG configuration for tf tests')
    tg_handler = tgapi.get_handles(vars, tf_data.tg_port_list)
    tg = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_ph_3 = tg_handler["tg_ph_3"]
    tg_ph_4 = tg_handler["tg_ph_4"]
    tg_ph_list = [tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4]

    stream_tf_data = {}

    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])

    stream_tf_data['1'] = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_percent=100,
                                               transmit_mode="continuous", mac_src="00:00:00:00:00:02",
                                               mac_dst="00:00:00:00:00:01", vlan_id=tf_data.vlan,
                                               l2_encap='ethernet_ii_vlan', frame_size='1500', high_speed_result_analysis=1)['stream_id']
    stream_tf_data['2'] = tg.tg_traffic_config(port_handle=tg_ph_2, mode='create', rate_percent=100,
                                               transmit_mode="continuous", mac_src="00:00:00:00:00:03",
                                               mac_dst="00:00:00:00:00:01", vlan_id=tf_data.vlan,
                                               l2_encap='ethernet_ii_vlan', frame_size='1500', high_speed_result_analysis=1)['stream_id']
    stream_tf_data['3'] = tg.tg_traffic_config(port_handle=tg_ph_3, mode='create', rate_percent=100,
                                               transmit_mode="continuous", mac_src="00:00:00:00:00:04",
                                               mac_dst="00:00:00:00:00:01", vlan_id=tf_data.vlan,
                                               l2_encap='ethernet_ii_vlan', frame_size='1500', high_speed_result_analysis=1)['stream_id']
    stream_tf_data['4'] = tg.tg_traffic_config(port_handle=tg_ph_4, mode='create', rate_percent=100,
                                               transmit_mode="continuous", mac_src="00:00:00:00:00:01",
                                               mac_dst="00:00:00:00:00:02", vlan_id=tf_data.vlan,
                                               l2_encap='ethernet_ii_vlan', frame_size='1500', high_speed_result_analysis=1)['stream_id']

    return tg, tg_ph_list, stream_tf_data


def verify_system_map_status(itter_count, delay):
    bsapi.get_system_uptime_in_seconds(vars.D1)
    if not tfapi.verify_hardware_map_status(vars.D1, tf_data.queues_to_check, itter_count=itter_count, delay=delay):
        st.error('Required Threshold Feature Queues are not initialized in the DUT')
        report_result(0)


def tf_tg_traffic_start_stop(traffic_mode, duration=3, traffic_action=True):
    st.log(">>> Configuring '{}' traffic streams".format(traffic_mode))
    st.debug("TG Streams : Current Mode = {}, Requested Mode = {}".format(tf_data.tg_current_mode, traffic_mode))
    if not tf_data.tg_current_mode == traffic_mode:
        tf_data.tg_current_mode = traffic_mode
        if traffic_mode == tf_data.multicast:
            for each in tf_data.stream_tf_data:
                tf_data.tg.tg_traffic_config(mode='modify', stream_id=tf_data.stream_tf_data[each],
                                             mac_dst="01:82:33:33:33:33",high_speed_result_analysis=1)
        else:
            tf_data.tg.tg_traffic_config(mode='modify', stream_id=tf_data.stream_tf_data['1'],
                                         mac_dst="00:00:00:00:00:01",high_speed_result_analysis=1)
            tf_data.tg.tg_traffic_config(mode='modify', stream_id=tf_data.stream_tf_data['2'],
                                         mac_dst="00:00:00:00:00:01",high_speed_result_analysis=1)
            tf_data.tg.tg_traffic_config(mode='modify', stream_id=tf_data.stream_tf_data['3'],
                                         mac_dst="00:00:00:00:00:01",high_speed_result_analysis=1)
            tf_data.tg.tg_traffic_config(mode='modify', stream_id=tf_data.stream_tf_data['4'],
                                         mac_dst="00:00:00:00:00:02",high_speed_result_analysis=1)
    tf_data.stream_list = [tf_data.stream_tf_data['1'], tf_data.stream_tf_data['2'],tf_data.stream_tf_data['3'], tf_data.stream_tf_data['4']]
    if traffic_action:
        tf_data.tg.tg_traffic_control(action='run', stream_handle=tf_data.stream_list)
        st.wait(duration)
        tf_data.tg.tg_traffic_control(action='stop', stream_handle=tf_data.stream_list)
        # Allow the breach event to be handled and written to DB.
        st.wait(1)


def tf_unconfig():
    tfapi.clear_threshold(vars.D1, breach='all')
    tfapi.clear_threshold(vars.D1, threshold_type='priority-group', buffer_type='all', port_alias=[vars.D1T1P1, vars.D1T1P4])
    tfapi.clear_threshold(vars.D1, threshold_type='queue', buffer_type='all', port_alias=[vars.D1T1P1, vars.D1T1P4])
    tfapi.config_buffer_pool_threshold_interface(vars.D1, 'no_buffer_pool')
    tfapi.config_buffer_pool_threshold_interface(vars.D1, 'no_buffer-pool', pool_name='egress_lossless_pool',buffer_type='multicast')
    for intf in tf_data.port_list:
        tfapi.config_buffer_pool_threshold_interface(vars.D1, 'no_buffer-pool', port_alias=intf,
                                                     pool_name='egress_lossless_pool', buffer_type='unicast')
        tfapi.config_buffer_pool_threshold_interface(vars.D1, 'no_buffer-pool', port_alias=intf,
                                                     pool_name='ingress_lossless_pool', buffer_type='shared')

def tf_collecting_debug_logs_when_test_fails(test, delay, traffic_mode):
    st.banner("TEST Failed - Collecting the DEBUG log and prints")
    tfapi.threshold_feature_debug(vars.D1, mode=['clear_counters', 'debug_log_enable'])
    tf_tg_traffic_start_stop(traffic_mode, traffic_action=False)

    tf_data.tg.tg_traffic_control(action='run', stream_handle=tf_data.stream_list)
    st.wait(delay)
    tfapi.threshold_feature_debug(vars.D1, mode=['show_counters', 'asic_info', 'show_logging'],
                                  platform=tf_data.platform, test=test)

    tf_data.tg.tg_traffic_control(action='stop', stream_handle=tf_data.stream_list)
    tfapi.threshold_feature_debug(vars.D1, mode='debug_log_disable')


def report_result(status):
    if status:
        st.report_pass('test_case_passed')
    else:
        tfapi.threshold_feature_debug(vars.D1, mode='show_watermark_counters')
        st.report_fail('test_case_failed')

@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_cli
@pytest.mark.inventory(feature='BST', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_tf_clear_config'])
@pytest.mark.inventory(testcases=['ft_tf_pg_shared_thre_breach_event'])
@pytest.mark.inventory(testcases=['ft_tf_pg_shared_thre_breach_event_cleared'])
@pytest.mark.inventory(testcases=['ft_tf_pg_thre_conf_shared'])
@pytest.mark.inventory(testcases=['ft_tf_pg_thre_shared_clear'])
@pytest.mark.inventory(feature='BST Enhancements', release='Cyrus4.0.0', testcases=['ft_tf_tam_Error_logs'])
def test_ft_tf_pg_thre_con_shared():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """

    tf_data.index = 7
    if tf_data.platform in tf_data.th3_platforms:
        tf_data.index = 0
    st.log("Testing with PG{} for PG SHARED test on {}".format(tf_data.index, tf_data.platform))
    tf_data.threshold = 4

    count = 1
    while True:
        result = 1
        result2 = 1

        st.banner("TEST Starts for iteration - {}".format(count))

        config_parameter = {"threshold_type": 'priority-group', "buffer_type": 'shared', "port_alias": vars.D1T1P1,
                            "pg{}".format(tf_data.index): tf_data.threshold}

        st.log("PG shared threshold config")
        tfapi.config_threshold(vars.D1, threshold_type='priority-group', port_alias=vars.D1T1P1, index=tf_data.index,
                               buffer_type='shared', value=tf_data.threshold)
        st.log("PG shared threshold config verify")
        if not tfapi.verify_threshold(vars.D1, **config_parameter):
            st.error("Unable to configure the PG index and corresponding threshold value on PG shared buffer")
            result = 0

        st.log("Traffic start and stop")
        tf_tg_traffic_start_stop(tf_data.unicast, tf_data.traffic_duration)

        st.log("Checking PG shared breach event")
        if not tfapi.verify_threshold_breaches(vars.D1, buffer='priority-group', port=vars.D1T1P1, index=tf_data.index,
                                               threshold_type='shared'):
            st.error("PG shared threshold breach Event is not found")
            if tf_data.need_debug_prints:
                tf_collecting_debug_logs_when_test_fails('shared', tf_data.traffic_duration, tf_data.unicast)
            result = 0
            result2 = 0

        output = tfapi.show_threshold_breaches(vars.D1)
        st.log("Clear PG shared threshold breach")
        tfapi.clear_threshold(vars.D1, breach='all')

        st.log("Checking PG shared breach event")
        if tfapi.verify_threshold_breaches(vars.D1, buffer='priority-group', port=vars.D1T1P1, index=tf_data.index,
                                           threshold_type='shared'):
            output1 = tfapi.show_threshold_breaches(vars.D1)
            if output1:
                for evnt in output1:
                    key = evnt['timestamp']
                    for i in output:
                        if re.search(key, i['timestamp']):
                            st.error("Post clear - PG shared threshold breach Event is found")
                            result = 0
                        else:
                            st.log("already a event was present in buffer which got popped up")

        st.log("PG shared threshold config clear")
        tfapi.clear_threshold(vars.D1, threshold_type='priority-group', port_alias=vars.D1T1P1, index=tf_data.index,
                              buffer_type='shared')
        st.log("PG shared threshold config verify")
        if tfapi.verify_threshold(vars.D1, **config_parameter):
            st.error("Unable to configure the PG index and corresponding shared threshold value")
            result = 0

        if not result2 and tf_data.need_debug_prints:
            st.log("As Breach events are not observed collecting logs by disabling the Thresholds")
            tf_collecting_debug_logs_when_test_fails('shared', tf_data.traffic_duration, tf_data.unicast)

        tfapi.clear_threshold(vars.D1, breach='all')

        st.banner('verifying the tam Error logs on the device')
        if slog.get_logging_count(vars.D1, severity="ERR", filter_list='brcm_sai_tam'):
            st.report_tc_fail("ft_tf_tam_Error_logs", "logs_are_getting_generated", "failed")
        else:
            st.report_tc_pass("ft_tf_tam_Error_logs", "logs_are_getting_generated", "successful")

        if result:
            st.log("Test PASSED in Iteration {}.".format(count))
            report_result(result)
            break

        if count == tf_data.test_max_retries_count:
            st.log("Test Failed in all {} Iterations. Hence Declaring as FAIL".format(count))
            report_result(result)

        st.log("Test Failed in the Iteration-{}. Hence re-testing".format(count))
        count += 1


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_cli
@pytest.mark.inventory(feature='BST', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_tf_queue_thre_conf_unicast'])
@pytest.mark.inventory(testcases=['ft_tf_queue_unicast_thre_breach_event_cleared'])
@pytest.mark.inventory(testcases=['ft_tf_ucast_queue_thre_breach_event'])
@pytest.mark.inventory(testcases=['ft_tf_ucast_queue_thre_clear'])
def test_ft_tf_queue_thre_con_unicast():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """

    tf_data.index = 0
    tf_data.threshold = 20
    count = 1
    while True:
        result = 1
        result2 = 1

        st.banner("TEST Starts for iteration - {}".format(count))

        st.log("Unicast queue threshold config")
        tfapi.config_threshold(vars.D1, threshold_type='queue', port_alias=vars.D1T1P4, index=tf_data.index,
                               buffer_type='unicast', value=tf_data.threshold)
        st.log("Unicast queue threshold config verify")
        if not tfapi.verify_threshold(vars.D1, threshold_type='queue', buffer_type='unicast',
                                      port_alias=vars.D1T1P4, uc0=tf_data.threshold):
            st.error("Unable to configure unicast queue threshold value on unicast-queue buffer")
            result = 0

        st.log("Traffic start and stop")
        tf_tg_traffic_start_stop(tf_data.unicast, tf_data.traffic_duration)

        st.log("Checking unicast queue breach event")
        if not tfapi.verify_threshold_breaches(vars.D1, buffer='queue', port=vars.D1T1P4, index=tf_data.index,
                                               threshold_type='unicast'):
            st.error("Unicast queue threshold breach Event is not found")
            if tf_data.need_debug_prints:
                tf_collecting_debug_logs_when_test_fails('unicast', tf_data.traffic_duration, tf_data.unicast)
            result = 0
            result2 = 0

        st.log("Clear Unicast queue threshold breach")
        tfapi.clear_threshold(vars.D1, breach='all')

        st.log("Checking unicast queue breach event")
        if tfapi.verify_threshold_breaches(vars.D1, buffer='queue', port=vars.D1T1P4, index=tf_data.index,
                                           threshold_type='unicast'):
            st.error("Post clear - Unicast queue threshold breach Event is found")
            result = 0

        st.log("Unicast queue threshold config clear")
        tfapi.clear_threshold(vars.D1, threshold_type='queue', port_alias=vars.D1T1P4, index=tf_data.index,
                              buffer_type='unicast')
        st.log("Unicast queue threshold config verify")
        if tfapi.verify_threshold(vars.D1, threshold_type='queue', buffer_type='unicast',
                                  port_alias=vars.D1T1P4, uc0=tf_data.threshold):
            st.error("Unable to configure unicast queue threshold value")
            result = 0

        if not result2 and tf_data.need_debug_prints:
            st.log("As Breach events are not observed collecting logs by disabling the Thresholds")
            tf_collecting_debug_logs_when_test_fails('unicast', tf_data.traffic_duration, tf_data.unicast)

        tfapi.clear_threshold(vars.D1, breach='all')
        if result:
            st.log("Test PASSED in Iteration {}.".format(count))
            report_result(result)
            break

        if count == tf_data.test_max_retries_count:
            st.log("Test Failed in all {} Iterations. Hence Declaring as FAIL".format(count))
            report_result(result)

        st.log("Test Failed in the Iteration-{}. Hence re-testing".format(count))
        count += 1


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_cli
@pytest.mark.inventory(feature='BST', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_tf_mcast_queue_thre_breach_event'])
@pytest.mark.inventory(testcases=['ft_tf_mcast_queue_thre_clear'])
@pytest.mark.inventory(testcases=['ft_tf_queue_multicast_thre_breach_event_cleared'])
@pytest.mark.inventory(testcases=['ft_tf_queue_thre_conf_multicast'])
def test_ft_tf_queue_thre_con_multicast():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """

    tf_data.index = 0
    tf_data.threshold = 2
    count = 1
    while True:
        result = 1
        result2 = 1

        st.banner("TEST Starts for iteration - {}".format(count))

        st.log("Multicast queue threshold config")
        tfapi.config_threshold(vars.D1, threshold_type='queue', port_alias=vars.D1T1P4, index=tf_data.index,
                               buffer_type='multicast', value=tf_data.threshold)
        st.log("Multicast queue threshold config verify")
        if not tfapi.verify_threshold(vars.D1, threshold_type='queue', buffer_type='multicast',
                                      port_alias=vars.D1T1P4, mc0=tf_data.threshold):
            st.error("Unable to configure multicast queue threshold value on multicast-queue buffer")
            result = 0

        st.log("Traffic start and stop")
        tf_tg_traffic_start_stop(tf_data.multicast, tf_data.traffic_duration+7)

        st.log("Checking multicast queue breach event")
        if not tfapi.verify_threshold_breaches(vars.D1, buffer='queue', port=vars.D1T1P4, index=tf_data.index,
                                               threshold_type='multicast'):
            st.error("Multicast queue threshold breach Event is not found")
            if tf_data.need_debug_prints:
                tf_collecting_debug_logs_when_test_fails('multicast', tf_data.traffic_duration+7, tf_data.multicast)
            result = 0
            result2 = 0

        st.log("Clear Multicast queue threshold breach")
        tfapi.clear_threshold(vars.D1, breach='all')

        st.log("Checking multicast queue breach event")
        if tfapi.verify_threshold_breaches(vars.D1, buffer='multicast', port=vars.D1T1P4, index=tf_data.index,
                                           threshold_type='queue'):
            st.error("Post clear - Multicast queue threshold breach Event is found")
            result = 0

        st.log("Multicast queue threshold config clear")
        tfapi.clear_threshold(vars.D1, threshold_type='queue', port_alias=vars.D1T1P4, index=tf_data.index,
                              buffer_type='multicast')
        st.log("Multicast queue threshold config verify")
        if tfapi.verify_threshold(vars.D1, threshold_type='queue', buffer_type='multicast',
                                  port_alias=vars.D1T1P4, mc0=tf_data.threshold):
            st.error("Unable to configure multicast queue threshold value")
            result = 0

        if not result2 and tf_data.need_debug_prints :
            st.log("As Breach events are not observed collecting logs by disabling the Thresholds")
            tf_collecting_debug_logs_when_test_fails('multicast', tf_data.traffic_duration, tf_data.multicast)

        tfapi.clear_threshold(vars.D1, breach='all')
        if result:
            st.log("Test PASSED in Iteration {}.".format(count))
            report_result(result)
            break

        if count == tf_data.test_max_retries_count:
            st.log("Test Failed in all {} Iterations. Hence Declaring as FAIL".format(count))
            report_result(result)

        st.log("Test Failed in the Iteration-{}. Hence re-testing".format(count))
        count += 1

@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_cli
@pytest.mark.inventory(feature='BST Enhancements', release='Cyrus4.0.0')
@pytest.mark.inventory(testcases=['ft_device_negative'])
@pytest.mark.inventory(testcases=['ft_tf_device_buffer_pool'])
def test_ft_tf_device_threshold():
    """
    :param dut:
    :return:
    """
    result = 1
    tf_data.threshold = '20'

    tf_data.platform_name = get_machineconf_platform(vars.D1)
    tf_data.platform_hwsku = get_cfggen_hwsku(vars.D1)

    path = "/usr/share/sonic/device/{}/{}/{}".format(tf_data.platform_name, tf_data.platform_hwsku,tf_data.device_j2_file)
    convert_json = "sonic-cfggen -d -t " "{} > {}".format(path, tf_data.config_file)
    sfapi.load_json_config(vars.D1, convert_json, tf_data.config_file)

    st.log("################  Device threshold config tescase ####################")

    tfapi.config_buffer_pool_threshold_interface(vars.D1, 'device',threshold_value=tf_data.threshold)
    st.log("threshold configuration verify")
    out=tfapi.show_device(vars.D1, 'device')
    if not out[0]['threshold_val']==tf_data.threshold:
        st.error("Unable to configure threshold device ")
        result = 0

    st.log("################  Device buffer counters tescase ####################")
    st.log("Traffic start and stop")
    tf_tg_traffic_start_stop(tf_data.unicast, tf_data.traffic_duration)

    st.log("Checking unicast breach events")
    if not tfapi.verify_device_threshold_pool(vars.D1, buffer='device',threshold_type='device', non_zero_value=True):
        st.error(" Device buffer counters are not observed")
        result = 0


    st.log("threshold config clear")
    tfapi.clear_threshold(vars.D1, breach='all')
    if tfapi.verify_threshold_breaches(vars.D1, buffer='device', threshold_type='device',value = tf_data.threshold):
        st.error("after clear threshold entries are not flused")
        result = 0

    tfapi.config_buffer_pool_threshold_interface(vars.D1, 'no_device')

    if not result:
        st.report_fail("threshold_config_fail")
    else:
        st.report_pass("threshold_config_success")


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_cli
@pytest.mark.inventory(feature='BST Enhancements', release='Cyrus4.0.0')
@pytest.mark.inventory(testcases=['ft_tf_egress_port_pool_shared'])
@pytest.mark.inventory(testcases=['ft_tf_egress_port_pool_unicast'])
@pytest.mark.inventory(testcases=['ft_tf_global_egress_buffer_pool_multicast'])
@pytest.mark.inventory(testcases=['ft_tf_ingress_port_pool_shared'])
def test_ft_tf_buffer_counter_threshold():
    """
    :param dut:
    :param :pool:ingress_lossless_pool|egress_lossy_pool|egress_lossless_pool
    :param :threshold_value:
    :param :cli_type:klish
    :return:
    """

    result = 1

    st.log("################  global Egress service pool multicast buffer pool counters tescase ####################")
    st.log(":: global threshold buffer_pool config ::")
    tfapi.config_buffer_pool_threshold_interface(vars.D1,'buffer-pool',pool_name='egress_lossless_pool',buffer_type='multicast',value=2)
    st.log("Traffic start and stop")
    tf_tg_traffic_start_stop(tf_data.multicast, tf_data.traffic_duration)

    tfapi.show_device(vars.D1, 'buffer_pool')
    if not tfapi.verify_device_threshold_pool(vars.D1, buffer='egress_lossless_pool', threshold_type='egress-multicast',non_zero_value=True):
        st.error(" Egress pool multicast buffer pool counters are not observed")
        result = 0

    st.log("################  Egress port buffer pool unicast buffer poolcounters tescase ####################")
    tfapi.clear_threshold(vars.D1, breach='all')
    for intf in tf_data.port_list:
        tfapi.config_buffer_pool_threshold_interface(vars.D1, 'buffer-pool',port_alias=intf,pool_name='egress_lossless_pool',buffer_type='unicast', value=1)

    st.log("Traffic start and stop")
    tf_tg_traffic_start_stop(tf_data.unicast, tf_data.traffic_duration)

    if not tfapi.verify_device_threshold_pool(vars.D1, buffer='egress_lossless_pool', threshold_type='egress-unicast',non_zero_value=True):
        st.error(" Egress port buffer pool unicast counters are not observed")
        result = 0

    for intf in tf_data.port_list:
        tfapi.show_device(vars.D1, 'buffer_pool_intf', intf_name=intf)

    st.log("################  Egress port buffer pool shared buffer poolcounters tescase ####################")
    tfapi.clear_threshold(vars.D1, breach='all')
    for intf in tf_data.port_list:
        tfapi.config_buffer_pool_threshold_interface(vars.D1, 'buffer-pool',port_alias=intf,pool_name='egress_lossless_pool',buffer_type='shared', value=1)

    st.log("Traffic start and stop")
    tf_tg_traffic_start_stop(tf_data.unicast, tf_data.traffic_duration)


    if not tfapi.verify_device_threshold_pool(vars.D1, buffer='egress_lossless_pool', threshold_type='egress-unicast',non_zero_value=True):
        st.error(" Egress port buffer pool shared counters are not observed")

    for intf in tf_data.port_list:
        tfapi.show_device(vars.D1, 'buffer_pool_intf',intf_name=intf)

    st.log("################  ingress port buffer pool shared buffer poolcounters tescase ####################")
    tfapi.clear_threshold(vars.D1, breach='all')
    for intf in tf_data.port_list:
        tfapi.config_buffer_pool_threshold_interface(vars.D1, 'buffer-pool',port_alias=intf,pool_name='ingress_lossless_pool',buffer_type='shared', value=4)

    st.log("Traffic start and stop")
    tf_tg_traffic_start_stop(tf_data.unicast, tf_data.traffic_duration)

    if not tfapi.verify_device_threshold_pool(vars.D1, buffer='ingress_lossless_pool', threshold_type='ingress',non_zero_value=True):
        st.error(" ingress port buffer pool shared counters are not observed ")
        result = 0

    for intf in tf_data.port_list:
        tfapi.show_device(vars.D1, 'buffer_pool_intf',intf_name=intf)


    if not result:
        st.report_fail("threshold_config_fail")
    else:
        st.report_pass("threshold_config_success")
