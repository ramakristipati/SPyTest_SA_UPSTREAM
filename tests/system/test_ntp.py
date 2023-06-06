import pytest
import time

from spytest import st, SpyTestDict

import apis.system.reboot as reboot_obj
import apis.system.ntp as ntp_obj
import apis.system.logging as syslog_obj
import apis.system.basic as basic_obj
import apis.routing.ip as ping_obj
import apis.system.config_session as ses_api
import apis.system.config_replace as rep_api

import utilities.utils as utils_obj

@pytest.fixture(scope="module", autouse=True)
def ntp_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    global_vars()
    yield
    #ntp_obj.delete_ntp_servers(vars.D1)

@pytest.fixture(scope="function", autouse=True)
def ntp_func_hooks(request):
    yield

def global_vars():
    global data
    data = SpyTestDict()
    data.servers = utils_obj.ensure_service_params(vars.D1, "ntp", "host")
    data.verify_no_server = 'None'
    data.ntp_service = 'ntp'


def config_ntp_server_on_config_db_file(dut, iplist,config_save = False):
    """
    Author: Anil Kumar Kacharla <anilkumar.kacharla@broadcom.com>
    """
    st.log("Configuring NTP servers in Config_db file")
    ntp_obj.add_ntp_servers(dut, iplist=iplist)
    data.time_date = time.strftime('%a %B %d %H:%M:%S %Z %Y')
    ntp_obj.config_date(vars.D1, data.time_date)
    reboot_obj.config_save(vars.D1)
    if not config_save:
        st.log("verifying ntp service status")
        if ntp_obj.verify_ntp_service_status(vars.D1, 'active'):
            st.log("ntpd is running")
        else:
            st.warn("ntpd is exited and restarting ntp service")
            basic_obj.service_operations(vars.D1, data.ntp_service, action="restart")
        if not st.poll_wait(ntp_obj.verify_ntp_server_details, 10, dut, iplist, remote=iplist):
            st.report_result(st.error("ip not matching"))
        if not ntp_obj.verify_ntp_service_status(dut, 'active', iteration=65, delay=2):
            st.report_result(st.error("ntp is exited"))
        st.log("Verify that NTP server connectivity from DUT")
        result = 0
        for server_ip in data.servers:
            if not ping_obj.ping(vars.D1, server_ip):
                st.error("ping to ntp server is not successfull:{}".format(server_ip))
                result += 1
        if len(data.servers) == result:
            st.report_fail("None_of_the_configured_ntp_server_reachable")
        if not ntp_obj.verify_ntp_status(vars.D1, iteration=65, delay=2, server=data.servers):
            st.report_result(st.error("ntp syncronization failed"))


@pytest.mark.ntp_disable_enable_message_log
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_ntp_disable_ntp_enable_ntp'])
@pytest.mark.inventory(testcases=['ft_ntp_message_log_display_with_correct_time'])
def test_ft_ntp_disable_enable_with_message_log():
    """
    Author: Anil Kumar Kacharla <anilkumar.kacharla@broadcom.com>
    Referrence Topology : 	Test bed ID:4 D1--Mgmt network
    Verify that Ntp synchronization is successful after doing NTP server on and off  and the message log display the correct time based upon the system up time.
    """
    data.string_generate = 'Iam Testing NTP'
    data.lines = 1
    data.time_date = time.strftime('%a %B %d %H:%M:%S %Z %Y')

    ntp_obj.config_date(vars.D1, data.time_date)
    st.log("checking time in message log without ntp ")
    log_message_1=syslog_obj.show_logging(vars.D1, severity=None, filter_list=[], lines=data.lines)
    if not log_message_1:
        st.report_result(st.error("log message_1 not created"))

    clock= utils_obj.log_parser(log_message_1[0])
    st.debug(clock)

    config_ntp_server_on_config_db_file(vars.D1, data.servers)
    st.log("Generating log messages")
    syslog_obj.clear_logging(vars.D1)
    syslog_obj.write_logging(vars.D1, data.string_generate)
    log_message = syslog_obj.show_logging(vars.D1, severity=None, filter_list=[data.string_generate])
    if not log_message:
        st.report_result(st.error("log message not created"))

    st.log("printing system clock")
    ntp_obj.show_clock(vars.D1)
    out = utils_obj.log_parser(log_message[0])
    if not (clock[0]['month'] == out[0]['month'] and clock[0]['hours'] == out[0]['hours'] and
            clock[0]['date'] == out[0]['date'] and clock[0]['minutes'] <= out[0]['minutes'] or clock[0]['seconds'] >= out[0]['seconds']):
        st.report_result(st.error("time not updated"))

    st.log("message log displaying correct timed based on system up time")
    st.log("disabling ntp")
    basic_obj.service_operations(vars.D1, data.ntp_service, action="stop")
    if not ntp_obj.verify_ntp_service_status(vars.D1, 'inactive (dead)'):
        st.report_result(st.error("ntp disabled failed"))

    st.log("Enabling NTP")
    basic_obj.service_operations(vars.D1, data.ntp_service, action="restart")
    if not ntp_obj.verify_ntp_service_status(vars.D1, 'active', iteration=65, delay=2):
        st.report_result(st.error("ntp is exited after enable and disable ntp"))

    if not ntp_obj.verify_ntp_status(vars.D1, iteration=65, delay=2, server=data.servers):
        st.report_result(st.error("ntp syncronization failed after enable and disable ntp"))

    st.report_pass("test_case_passed")

@pytest.mark.ntpdef
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['ft_ntp_existsconfig'])
def test_ntp_exists_config():
    if ntp_obj.ensure_ntp_config(vars.D1):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.inventory(feature='Config Replace', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['CONF_ROLLBACK_NTP_USECASE_007'])
def test_rollback_ntp_usecase_007():
    """
    Author: Chandra Sekhar Reddy <chandra.vedanaparthi@broadcom.com>
    Referrence Topology : 	Test bed ID:4 D1--Mgmt network
    To verify NTP config after config rollback.
    """
    err_list = []
    data.string_generate = 'Iam Testing NTP'
    ntp_obj.delete_ntp_servers(vars.D1)
    data.lines = 1
    data.time_date = time.strftime('%a %B %d %H:%M:%S %Z %Y')

    st.log("Time Date ======>{}".format(data.time_date))
    ntp_obj.config_date(vars.D1, data.time_date)

    st.log("checking time in message log without ntp ")
    log_message_1=syslog_obj.show_logging(vars.D1, severity=None, filter_list=[], lines=data.lines)
    if not log_message_1:
        st.report_result(st.error("log message_1 not created"))
    clock= utils_obj.log_parser(log_message_1[0])
    st.debug(clock)

    #enter config session
    st.log("##################################################")
    st.log("### Step 1: Create a config session")
    st.set_module_params(conf_session=1)
    #config ntp
    config_ntp_server_on_config_db_file(vars.D1, data.servers,config_save = True)
    st.log("#############################################################")
    st.log("### Step 2: save the running config at the specified path")
    rep_api.copy_running_config_to_config_db_json(vars.D1, "home://dut1_ntp_db.json")
    st.set_module_params(conf_session=0)

    st.log("##################################################")
    st.log("### Step 3: Create a config session and replace config")
    st.set_module_params(conf_session=1)
    rep_api.config_replace_in_config_session(vars.D1, "home://dut1_ntp_db.json")

    st.log("##################################################")
    st.log("### Step 4: Commit config in  config session with timer 100 Sec")
    ses_api.config_commit(vars.D1, timeout=100, expect_mode='mgmt-config')
    st.wait(5)

    st.log("Generating log messages")
    syslog_obj.clear_logging(vars.D1)
    syslog_obj.write_logging(vars.D1, data.string_generate)
    log_message = syslog_obj.show_logging(vars.D1, severity=None, filter_list=[data.string_generate])
    st.log("Log Message========>{}".format(log_message))
    if not log_message:
        err_list.append(st.error("log message not created"))
    st.log("printing system clock")
    ntp_obj.show_clock(vars.D1)
    out = utils_obj.log_parser(log_message[0])
    st.log("Log Message  ======>{}".format(out))
    if not (clock[0]['month'] == out[0]['month'] and clock[0]['hours'] == out[0]['hours'] and
            clock[0]['date'] == out[0]['date'] and clock[0]['minutes'] <= out[0]['minutes']):
        err_list.append(st.error("time not updated"))
    st.log("message log displaying correct timed based on system up time")
    st.wait(160,"waiting for 100 Sec to expire the commit timer + Config Reload time 60Sec")
    if not utils_obj.retry_api(basic_obj.get_system_status_all_brief, vars.D1, retry_count=12, delay=20):
        err_list.append(st.error("System is not Ready"))
    elif  st.poll_wait(ntp_obj.verify_ntp_server_details, 10, vars.D1, data.servers, remote=data.servers):
        err_list.append(st.error("NTP Config exists even after commit timer expire"))

    st.report_result(err_list)


