import pytest

from spytest import st, SpyTestDict

import apis.security.tacacs as tacacs_obj
import apis.security.user as user
import apis.system.connection as ssh_obj
from apis.system.connection import connect_to_device
import apis.routing.ip as ping_obj
import apis.system.basic as basic_obj
from apis.security.rbac import ssh_call
from apis.switching.vlan import clear_vlan_configuration
import apis.system.reboot as reboot_api

from utilities.utils import ensure_service_params

vars = dict()
data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def tacacs_module_hooks(request):
    # add things at the start of this module
    global vars
    vars = st.ensure_min_topology("D1")
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    st.log("Getting IP address of the device")
    data.clear()
    data.hosts = ensure_service_params(vars.D1, "tacacs", "hosts")
    data.tacacs_ser_ip_1 = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "ip")
    data.tcp_port = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "tcp_port")
    data.passkey = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "passkey")
    data.priority = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "priority")
    data.timeout = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "timeout")
    data.auth_type = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "auth_type")
    data.tacacs_ser_ip_2 = ensure_service_params(vars.D1, "tacacs", "hosts", 2, "ip")
    data.priority_server2 = ensure_service_params(vars.D1, "tacacs", "hosts", 2, "priority")
    data.time_out = '10'
    data.username = 'testrw'
    data.password = 'testrw'
    data.protocol = 'ssh'
    data.ssh_port = '22'
    data.login_type = "tacacs+"
    data.failthrough_mode = 'enable'
    data.local_username = 'admin'
    data.local_password = 'YourPaSsWoRd'
    data.local_password2 = 'broadcom'
    data.username1 = 'test'
    data.password1 = 'test'
    data.ro_username = ensure_service_params(vars.D1, "radius", "ro_user", "username")
    data.ro_password = ensure_service_params(vars.D1, "radius", "ro_user", "password1")
    data.rw_user = {'username': data.username1, 'password': data.password1, 'mode': 'rw','role': 'admin'}
    data.ro_user = {'username': data.ro_username, 'password': data.ro_password, 'mode': 'ro','role': 'operator'}
    data.rw_secadmin_user = {'username': 'secadmin1', 'password': 'secadmin123', 'mode': 'rw','role': 'secadmin'}
    data.rw_netadmin_user = {'username': 'netadmin1', 'password': 'netadmin123', 'mode': 'rw','role': 'netadmin'}
    if st.is_feature_supported("host-account-manager"):
        data.user_list = [data.rw_secadmin_user,data.rw_netadmin_user,data.ro_user,data.rw_user]
    else:
        data.user_list = []
    data.reboot = 0
    ensure_device_ipaddress()
    tacacs_obj.set_aaa_authentication_properties(vars.D1,"failthrough",'enable')
    tacacs_obj.set_tacacs_server(vars.D1, 'add', data.tacacs_ser_ip_1, data.tcp_port, data.timeout, data.passkey,
                                 data.auth_type, data.priority)
    st.log("Configuring authentication login parameter as tacacs+ and local")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'tacacs+ local')
    tacacs_config_user()
    yield
    config_default_tacacs_properties(vars.D1)
    st.log("Deleting all TACACS+ servers from the device")
    for i in range(0, 8):
        tacacs_obj.set_tacacs_server(vars.D1, 'delete', tacacs_params.hosts[i].ip)
    st.log("Making AAA parameters to default")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'default')
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'failthrough', 'default')
    clear_vlan_configuration([vars.D1])


# add things at the end of this module"

@pytest.fixture(scope="function", autouse=True)
def tacacs_func_hooks(request):
    if st.get_func_name(request) == 'test_ft_tacacs_enable_disable_failthrough':
        tacacs_obj.set_aaa_authentication_properties(vars.D1, 'failthrough', 'default')
    yield
    # add things at the end every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case


def ensure_device_ipaddress():
    data.ip_address_list = basic_obj.get_ifconfig_inet(vars.D1, 'eth0')
    if not data.ip_address_list:
        st.report_fail("DUT_does_not_have_IP_address")
    data.ip_address = data.ip_address_list[0]


def config_default_tacacs_properties(dut):
    st.log("Making TACACS+ parameters to default")
    tacacs_obj.set_tacacs_properties(dut, 'default', 'authtype')
    tacacs_obj.set_tacacs_properties(dut, 'default', 'passkey')
    tacacs_obj.set_tacacs_properties(dut, 'default', 'timeout')


def verify_tacacs_server_reachability(dut, tacacs_ser_ip):
    st.log("Verify that tacacs server connectivity from DUT")
    if not ping_obj.ping(dut, tacacs_ser_ip):
        st.report_fail("Ping_to_tacacs_server_is_not_successful", tacacs_ser_ip)


def verifying_tacacs_config(dut, tacacs_ser_ip):
    if not tacacs_obj.verify_tacacs_server(dut, tacacs_ser_ip):
        st.report_fail("Tacacs_server_configs_are_not_successful", tacacs_ser_ip)


def debug_info(test_case, server_ip):
    if test_case == "test_ft_tacacs_enable_disable_failthrough":
        st.log("Checking TACACS+ server is reachable or not from the device")
        verify_tacacs_server_reachability(vars.D1, server_ip)
        st.log("Checking TACACS+ config in the device")
        verifying_tacacs_config(vars.D1, server_ip)

def config_save_reboot():
    if not data.reboot:
        reboot_api.config_save(vars.D1)
        st.reboot(vars.D1)
        st.wait(5,'wait is added for reboot the device')
        data.reboot = 1

def tacacs_config_user():
    st.banner("Configuring User(s) to the DUT.")
    for each in data.user_list:
         st.banner("Configuring - {}".format(each), delimiter='*')
         user.config(vars.D1, **each)

@pytest.mark.ssh_login
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['auth_shared_keys '])
@pytest.mark.inventory(testcases=['executing_server_key_in_appropriate_mode'])
@pytest.mark.inventory(testcases=['ft_tacacs_default_login'])
@pytest.mark.inventory(testcases=['ft_tacacs_single_server_for_auth'])
@pytest.mark.inventory(testcases=['ft_tacacs_ssh_login'])
@pytest.mark.inventory(testcases=['ft_tacacsauth_enable_pamfile_created'])
def test_ft_tacacs_ssh_login_with_tacacs_operations():
    """
    Author: Karthik Kumar Goud Battula(karthikkumargoud,battula@broadcom.com)
    This testcase covers the below scenarios
    scenario-1: Verify default login via tacacs is successful.
    scenario-2: Verify that by default, no TACACS servers exist and that a single TACACS server can be added and used for authentication
    scenario-3: Verify that SSH login using Cisco ACS TACACS+ Server is successful.
    Scenario-4: Verify If TACACS+ Authentication is enabled, a new PAM configuration file ?common-auth-sonic? is created.
	Scenario-5: Verify that user is able to execute the ?TACACS-server key command successfully in appropriate mode.
	Scenario-6: Verify that authentication to a TACACS server will only take place if the NAS and the server are configured with the same shared key
    """
    if not basic_obj.verify_file_on_device(vars.D1, "/etc/pam.d", "common-auth"):
        st.report_fail("PAM_file_is_not_created")
    if not basic_obj.verify_file_on_device(vars.D1, "/etc/pam.d", "common-auth-sonic"):
        st.report_fail("PAM_file_is_not_created")
    st.report_pass("test_case_passed")


@pytest.mark.functionality_failthrough
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_tacacs_enable_disable_failthrough'])
@pytest.mark.inventory(testcases=['ft_tacacs_failthrough_with_multiple_servers'])
def test_ft_tacacs_enable_disable_failthrough():
    """
    Author: Karthik Kumar Goud Battula(karthikkumargoud,battula@broadcom.com)
    This test case covers the below Scenarios
    Scenario-1: Verify the functionality of failthrough mechanism by changing the login authentication order
    Scenario-2: Verify the functionality of failthrough mechanism when DUT have multiple server with default priority.
    """
    verify_tacacs_server_reachability(vars.D1, data.tacacs_ser_ip_2)
    tacacs_obj.set_tacacs_server(vars.D1, 'add', data.tacacs_ser_ip_2, data.tcp_port, data.timeout, data.passkey,
                                 data.auth_type, data.priority_server2, username=data.username, password=data.password)
    st.wait(5, "to sync the tacacs server config")
    st.log(
        "Trying to SSH to the device using local credetails when login method set to TACACS+ and local and fail through mode is not enabled")
    if ssh_obj.connect_to_device(data.ip_address, data.local_username, data.local_password, data.protocol,
                                 data.ssh_port, alt_password=data.local_password2):
        tacacs_obj.set_aaa_authentication_properties(vars.D1, 'failthrough', 'enable', username=data.username,
                                                     password=data.password)
        st.wait(5, "to sync the faithrough changes")
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log(
        "Trying to SSH to the device using TACACS+ credetails when login method set to TACACS+ and local and fail through mode is not enabled")
    if not ssh_obj.connect_to_device(data.ip_address, data.username, data.password, data.protocol):
        debug_info("test_ft_tacacs_enable_disable_failthrough", data.tacacs_ser_ip_2)
        tacacs_obj.set_aaa_authentication_properties(vars.D1, 'failthrough', 'enable', username=data.username,
                                                     password=data.password)
        st.wait(5, "to sync the faithrough changes")
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log("Setting login authentication to local and tacacs+")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'local tacacs+', username=data.username, password=data.password)
    st.log(
        "Trying to SSH to the device using local credetails when login method set to local and TACACS+ and fail through mode is not enabled")
    st.wait(5, "to sync the Setting login authentication to local and tacacs+ changes")
    if not ssh_obj.connect_to_device(data.ip_address, data.local_username, data.local_password,
                                     alt_password=data.local_password2):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log(
        "Trying to SSH to the device using TACACS+ credetails when login method set to local and TACACS+ and fail through mode is not enabled")
    if ssh_obj.connect_to_device(data.ip_address, data.username, data.password, data.protocol, data.ssh_port):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log("Configuring AAA login to tacacs+ and local and enabling failthrough mode")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'tacacs+ local')
    st.wait(5, "sync the tacacs server after config changes")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'failthrough', 'enable', username=data.username, password=data.password)
    st.wait(5, "sync the tacacs server after config changes")
    st.log(
        "Trying to SSH to the device using local credetails when login method set to TACACS+ and local and fail through mode is enabled")
    if not ssh_obj.connect_to_device(data.ip_address, data.local_username, data.local_password,
                                     alt_password=data.local_password2):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log(
        "Trying to SSH to the device using TACACS+ credetails when login method set to TACACS+ and local and fail through mode is enabled")
    if not ssh_obj.connect_to_device(data.ip_address, data.username, data.password, data.protocol, data.ssh_port):
        debug_info("test_ft_tacacs_enable_disable_failthrough", data.tacacs_ser_ip_2)
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.report_pass("test_case_passed")


@pytest.mark.ssh_login_highest_priorityserver
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_tacacs_remove_highpriority_server'])
@pytest.mark.inventory(testcases=['ft_tacacs_ssh_login_highest_priorityserver'])
@pytest.mark.inventory(testcases=['ft_tacacs_ssh_login_with_nondefaultpriority_servers'])
def test_ft_tacacs_ssh_login_highest_priorityserver():
    """
    Author:Karthik Kumar Goud Battula(karthikkumargoud.battula@broadcom.com
    This test case covers the below Scenarios
    Scenario-1: verify if DUT is configured with more than one tacacs server with  priority configured  client can login do dut via heightest priority tacacs server
    Scenario-2: Verify user login with multiple TACACS server when nondefault priority is configured for all server.
    Scenario-3: Verify that if the current TACACS server is unresponsive  the NAS will failover  to the next configured TACACS server  according to configured server priorities  and so on.
    """
    st.log("Login to the device via SSH using the credentials of highest priority server")
    if not ssh_obj.connect_to_device(data.ip_address, data.username1, data.password1, data.protocol):
        debug_info("test_ft_tacacs_ssh_login_highest_priorityserver", data.tacacs_ser_ip_2)
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    tacacs_obj.set_tacacs_server(vars.D1, 'delete', data.tacacs_ser_ip_1)
    st.report_pass("test_case_passed")


@pytest.mark.rbac
@pytest.mark.inventory(feature='RBAC', release='Buzznik')
@pytest.mark.inventory(testcases=['FtOpSoScRBACFn009'])
def test_ft_rbac_rw_tacacs_cred_ssh():
    '''
    FtOpSoScRBACFn009:	Verify that admin tacacs user will have all permissions when SSH to the system with username/password.
    '''
    ssh_call(vars.D1, login_type='cred', **data.rw_user)


@pytest.mark.rbac
@pytest.mark.inventory(feature='RBAC', release='Buzznik')
@pytest.mark.inventory(testcases=['FtOpSoScRBACFn008'])
def test_ft_rbac_ro_tacacs_cred_ssh():
    '''
    Author: Sai Durga (pchvsai.durga@broadcom,com)
    FtOpSoScRBACFn008	Verify that non-admin tacacs user doesn?t have all permissions except show (get) commands when SSH to the system with username/password.
    '''
    if not st.exec_ssh(vars.D1, data.ro_username, data.ro_password, ['show vlan config']):
        st.report_fail("cmd_not_executed")
    if not st.exec_ssh(vars.D1, data.ro_username, data.ro_password, ['sudo config vlan add 1000']):
        st.report_fail("admin_user_root_privilege", "non", "got")
    st.report_pass("admin_user_root_privilege", "non", "doesnot got")

@pytest.mark.rbac
@pytest.mark.inventory(feature='RBAC and HAMD Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoScRBACTacacsSecAdminFn009'])
def test_ft_rbac_secadmin_rw_tacacs_cred_ssh():
    '''
    FtOpSoScRBACTacacsSecAdminFn009:	Verify that secadmin tacacs user will have all security related  permissions when SSH to the system with username/password.
    '''
    if not st.is_feature_supported("host-account-manager"):
        st.report_unsupported('test_case_unsupported', "host-account-manager")
    ssh_call(vars.D1, login_type='cred', **data.rw_secadmin_user)

@pytest.mark.rbac
@pytest.mark.inventory(feature='RBAC and HAMD Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoScRBACTacacsNetAdminFn009'])
def test_ft_rbac_netadmin_rw_tacacs_cred_ssh():
    '''
    FtOpSoScRBACTacacsNetAdminFn009:	Verify that netadmin tacacs user will have all netadmin related  permissions when SSH to the system with username/password.
    '''
    if not st.is_feature_supported("host-account-manager"):
        st.report_unsupported('test_case_unsupported', "host-account-manager")
    ssh_call(vars.D1, login_type='cred', **data.rw_netadmin_user)

@pytest.mark.rbac
@pytest.mark.inventory(feature='RBAC and HAMD Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoScRBACAdminRebootFn009'])
def test_ft_rbac_rw_tacacs_cred_ssh_reboot():
    '''
    FtOpSoScRBACAdminRebootFn009:	Verify that admin tacacs user will have all permissions when SSH to the system with username/password after reboot.
    '''
    config_save_reboot()
    ssh_call(vars.D1, login_type='cred', **data.rw_user)

@pytest.mark.rbac
@pytest.mark.inventory(feature='RBAC and HAMD Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoScRBACOperatorRebootFn008'])
def test_ft_rbac_ro_tacacs_cred_ssh_reboot():
    '''
    Author: Sai Durga (pchvsai.durga@broadcom,com)
    FtOpSoScRBACOperatorRebootFn008	Verify that non-admin tacacs user doesn?t have all permissions except show (get) commands when SSH to the system with username/password.
    '''
    if not st.exec_ssh(vars.D1, data.ro_username, data.ro_password, ['show vlan config']):
        st.report_fail("cmd_not_executed")
    if not st.exec_ssh(vars.D1, data.ro_username, data.ro_password, ['sudo config vlan add 1000']):
        st.report_fail("admin_user_root_privilege", "non", "got")
    st.report_pass("admin_user_root_privilege", "non", "doesnot got")

@pytest.mark.rbac
@pytest.mark.inventory(feature='RBAC and HAMD Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoScRBACTacacsSecAdminRebootFn009'])
def test_ft_rbac_secadmin_rw_tacacs_cred_ssh_reboot():
    '''
    FtOpSoScRBACTacacsSecAdminRebootFn009:	Verify that secadmin tacacs user will have all security related  permissions when SSH to the system with username/password after reboot.
    '''
    if not st.is_feature_supported("host-account-manager"):
        st.report_unsupported('test_case_unsupported', "host-account-manager")
    config_save_reboot()
    ssh_call(vars.D1, login_type='cred', **data.rw_secadmin_user)

@pytest.mark.rbac
@pytest.mark.inventory(feature='RBAC and HAMD Enhancements', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoScRBACTacacsNetAdminRebootFn009'])
def test_ft_rbac_netadmin_rw_tacacs_cred_ssh_reboot():
    '''
    FtOpSoScRBACTacacsNetAdminRebootFn009:	Verify that netadmin tacacs user will have all netadmin related  permissions when SSH to the system with username/password after reboot.
    '''
    if not st.is_feature_supported("host-account-manager"):
        st.report_unsupported('test_case_unsupported', "host-account-manager")
    config_save_reboot()
    ssh_call(vars.D1, login_type='cred', **data.rw_netadmin_user)

@pytest.mark.modify_tacacsserver_parameters
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_tacacs_modify_server_parameters'])
@pytest.mark.inventory(testcases=['ft_tacacs_nondefault_global_key_timeout'])
@pytest.mark.inventory(testcases=['ft_tacacs_nondefault_timeout'])
def test_ft_tacacs_modify_server_parameters():
    """

    Author: Karthik Kumar Goud Battula(karthikkuamrgoud.battula@broadcom.com)
    This Testcase covers the below scenarios
    Scenario-1: Verify device behavior when TACACS+ application parameters (valid and invalid) are modified while traffic is running.
    Scenario-2: Verify that the key and timeout options default to global but may be specified to unique values on a per Server basis.
    Scenario-3: Verify that the NAS will stop communicating with the current server is the server is down  after the duration of the configured server timeout  or the default timeout value
    Scenario-4: Verify that Taccacs server key can be configured with more that 4 special characters
    """
    invalid_l4_port = '59'
    invalid_pass_key = "key123"
    invalid_timeout = '10'
    invalid_ip_addr = '10.10.10.1'
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    tacacs_obj.set_tacacs_server(vars.D1, 'delete', tacacs_params.hosts[2].ip)
    tacacs_obj.set_tacacs_properties(vars.D1, 'passkey', 'secretstring')
    st.log("Configuring global tacacs server key with special characters")
    tacacs_obj.set_tacacs_properties(vars.D1, 'passkey', data.passkey)
    st.log("Check client authentication by modifing ip address,timeout,passkey")
    tacacs_obj.set_tacacs_server(vars.D1, 'add', invalid_ip_addr, invalid_l4_port, invalid_timeout, invalid_pass_key,
                                 data.auth_type, data.priority_server2)
    st.wait(5, "sync the tacacs server after config changes")
    st.log("Trying to SSH to the device when TACACS+ server is configured with invalid parameters")
    if ssh_obj.connect_to_device(data.ip_address, data.username, data.password, data.protocol, data.ssh_port):
        st.log("Deleting the TACACS+ server which is invalid for failed scenario")
        tacacs_obj.set_tacacs_server(vars.D1, 'delete', invalid_ip_addr)
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log("Deleting the TACACS+ server which is invalid")
    tacacs_obj.set_tacacs_server(vars.D1, 'delete', invalid_ip_addr)
    st.log("Creating valid TACACS+ server")
    tacacs_obj.set_tacacs_server(vars.D1, 'add', data.tacacs_ser_ip_1, data.tcp_port, data.timeout, data.passkey,
                                 data.auth_type, data.priority)
    st.wait(5, "sync the tacacs server after config changes")
    st.log("Trying to SSH to the device with TACACS+ server which is configured with the valid parameters")
    if not st.poll_wait(connect_to_device, 10, data.ip_address, data.username,
                     data.password, data.protocol, data.ssh_port):
        debug_info("test_ft_tacacs_modify_server_parameters", data.tacacs_ser_ip_1)
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.report_pass("test_case_passed")


@pytest.mark.maximum_servers
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_tacacs_add_multiple_servers'])
@pytest.mark.inventory(testcases=['ft_tacacs_maximum_ipv4_servers '])
@pytest.mark.inventory(testcases=['tacacs_key_config_with_special_characters'])
def test_ft_tacacs_maximum_servers():
    """
     Author: Karthik Kumar Goud Battula(karthikkumargoud.battula@broadcom.com)
    This testcase covers the below scenarios
    Scenario-1: Verify that more than one TACACS server can be configured on the NAS, upto the maximum number of servers that are allowed.
    Scenario-2: Verify that TACACS+ servers with IPv4 and IPv6 address can be added at the same time.
    Scenario-3: Verify that Maximum number of TACACS IPv4 servers can be configured on DUT.
    Scenario-4: Verify that Maximum number of TACACS IPv6 servers can be configured on DUT.
    Scenario-5: Verify the Save and Reload Functionality for TACACS IPv6 feature.
    """
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'default')
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    for i in range(1, 8):
        ip_addr = ensure_service_params(vars.D1, "tacacs", "hosts", i, "ip")
        priority = ensure_service_params(vars.D1, "tacacs", "hosts", i, "priority")
        tacacs_obj.set_tacacs_server(vars.D1, 'add', ip_addr, data.tcp_port,
                                     data.timeout, data.passkey,
                                     data.auth_type, priority)
    st.wait(5, "sync the tacacs server after config changes")
    if not tacacs_obj.verify_tacacs_details(vars.D1, tacacs_params.hosts):
        st.report_fail("Tacacs_server_configs_are_not_successful", tacacs_params.hosts)
    st.report_pass("test_case_passed")
