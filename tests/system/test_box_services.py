import pytest
from spytest.dicts import SpyTestDict
from spytest import st
import apis.system.box_services as boxserv_obj
import apis.system.basic as basic_obj
import apis.system.i2c as i2c_api

data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    hw_constants = st.get_datastore(vars.D1, "constants")
    data.temp_sensors = [{'accton-as7326-56x': hw_constants["AS7326_TEMP_SENSORS"]},
                         {'accton-as7816-64x': hw_constants["AS7816_TEMP_SENSORS"]},
                         {'accton-as7726-32x': hw_constants["AS7726_TEMP_SENSORS"]}]
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    global vars
    vars = st.get_testbed_vars()
    yield

@pytest.fixture(scope="function")
def hostname_config_fixture():
    yield
    st.log('Function unconfig')
    boxserv_obj.config_hostname(vars.D1, 'sonic')

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_system_uptime'])
def test_ft_system_uptime():
    """
    Author: Sreenivasula Reddy V <sreenivasula.reddy@broadcom.com>
    Validate 'show uptime' command
    """
    st.log("About to get system uptime in seconds")
    intial_uptime=int(boxserv_obj.get_system_uptime_in_seconds(vars.D1))
    st.log("initial_uptime: {}".format(intial_uptime))
    st.log("About to wait for 1 min")
    st.wait(60)
    uptime_after_1min=intial_uptime+int(60)
    st.log("uptime_after_1min: {}".format(uptime_after_1min))
    st.log("About to check system uptime after 60 sec")
    sys_uptime=int(boxserv_obj.get_system_uptime_in_seconds(vars.D1))
    st.log("sys_uptime: {}".format(sys_uptime))
    st.log("About to validate system uptime which should be greater than or equal to system uptime after 1 min")
    st.log("uptime_after_1min+60: {}".format(uptime_after_1min+60))
    st.log("Verifying {}<={}<={}".format(uptime_after_1min, sys_uptime, uptime_after_1min + 60))
    if uptime_after_1min<=sys_uptime<=uptime_after_1min+60:
        st.log("System Uptime is getting updated with correct value")
    else:
        st.report_fail("sytem_uptime_fail",vars.D1)
    st.report_pass("test_case_passed")

# This testcases will get the host name and try configuring hostname with special charecter and validates the hostname
@pytest.mark.inventory(feature='Regression', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_hostname_config'])
def test_hostname_config(hostname_config_fixture):
    report_flag=0
    st.log("Get the host name and try configuring hostname with special charecter and re verify the hostname")
    hostname = basic_obj.get_hostname(vars.D1)
    hostname_new=hostname+'_123'
    if boxserv_obj.config_hostname(vars.D1,hostname_new, skip_error_check=True):
        report_flag+=1
    if basic_obj.get_hostname(vars.D1)==hostname_new:
        st.log("Hostname updated which is not expected")
        report_flag+=1
    if report_flag==0:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


@pytest.mark.inventory(feature='I2C Error Statistics', release='Cyrus4.1.0')
@pytest.mark.inventory(testcases=['FtOpSoSysI2cFn006'])
def test_ft_verify_i2c_errors_for_supported_and_unsupported_devices():
    hw_constants = st.get_datastore(vars.D1, "constants")
    supported_devices = hw_constants["I2C_ERRORS_SUPPORTED_PLATFORMS"]
    st.banner('checking that error message is shown, if feature not supported')
    output1 = basic_obj.get_hwsku(vars.D1).lower()
    output = i2c_api.show_i2c(vars.D1)
    if output[0]['message_string'] != '' and output1 not in supported_devices:
        st.report_pass("msg","feature is not supported on this platform: {}".format(output1))
    elif output[0]['message_string'] == '' and output1 in supported_devices:
        st.report_pass("msg", "feature is supported on this platform: {}".format(output1))
    else:
        st.report_fail("msg","verification of i2c errors failed.")


@pytest.mark.inventory(feature='CPU TEMP AND LABELLING', release='Buzznik3.7.0')
@pytest.mark.inventory(testcases=['CPU_TEMP_LABELLING'])
def test_ft_verify_system_temperature_sensors():
    """
    Author: nagarjuna suravarapu<nagarjuna.suravarapu@broadcom.com>
    Validate 'show system temperature' command
    """
    if basic_obj.get_hwsku(vars.D1).lower() in ["accton-as7326-56x","accton-as7816-64x", "accton-as7726-32x"]:
        output= boxserv_obj.get_platform_temperature(vars.D1)
        if boxserv_obj.get_device_name_by_sensor_data(output,data.temp_sensors) == basic_obj.get_hwsku(vars.D1).lower():
            st.report_pass("test_case_passed")
        else:
            st.report_fail("msg","TEMP SENSORS of device are not matched")
    else:
        st.report_unsupported("msg","device not supported")
