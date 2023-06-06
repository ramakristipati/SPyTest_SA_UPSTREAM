from spytest import st
import datetime
import re
from utilities.utils import get_supported_ui_type_list
import apis.system.system_server as sys_server_api

def config_timezone(dut, time_zone, **kwargs):
    """
    API to configure Timezone on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type= st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    if cli_type in get_supported_ui_type_list():
        kwargs['config'] = 'yes'
        kwargs['time_zone'] = time_zone
        return sys_server_api.config_system_properites(dut, **kwargs)
    if cli_type in ["klish", "rest-patch", "rest-put"]:
        cmd = 'clock timezone {}'.format(time_zone)
        output = st.config(dut, cmd, skip_error_check=skip_error, type="klish")
        if "% Error" in output:
            return False
    elif cli_type == "click":
        cmd = 'timedatectl set-timezone {}'.format(time_zone)
        st.config(dut, cmd, skip_error_check=skip_error, type=cli_type)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return True


def delete_timezone(dut, **kwargs):
    """
    API to configure Timezone on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type= st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    if cli_type in get_supported_ui_type_list():
        kwargs['config'] = 'no'
        kwargs['time_zone'] = 'anything'
        return sys_server_api.config_system_properites(dut, **kwargs)
    
    if cli_type in ["klish", "rest-patch", "rest-put", "click"]:
        cmd = 'no clock timezone'
        st.config(dut, cmd, skip_error_check=skip_error, type="klish")
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return True


def show_running_config(dut, **kwargs):
    """
    API to configure Timezone on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type= st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type 
    if cli_type in ["klish", "rest-patch", "rest-put", "click"]:
        cmd = 'show running-config | grep timezone'
        output = st.show(dut, cmd, skip_tmpl=True, type="klish")
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return output


def verify_time(time1, time2, diff):
    month_dict = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
    try:
        time1 = datetime.datetime(int(time1['year']), month_dict[time1['month']], int(time1['monthday']), int(time1['hours']), int(time1['minutes']), int(time1['seconds']))
        time2 = datetime.datetime(int(time2['year']), month_dict[time2['month']], int(time2['monthday']), int(time2['hours']), int(time2['minutes']), int(time2['seconds']))
        difference = (time2 - time1).total_seconds()
    except Exception as e:
        st.error("'{}' exception occurred".format(e))
        return False
    return True if int(difference) < diff else False


def validate_time(time1, time2, timeref, add_flag=True):
    ret_val = True
    time_ref_list = timeref.split(':')
    if len(time_ref_list) == 1:
        time_ref = (int(time_ref_list[0]) * 3600)
    elif len(time_ref_list) == 2:
        time_ref = (int(time_ref_list[0]) * 3600) + (int(time_ref_list[1]) * 60)
    else:
        time_ref = (int(time_ref_list[0]) * 3600) + (int(time_ref_list[1]) * 60) + (int(time_ref_list[2]))

    if add_flag:
        variance_val = time_ref
    else:
        variance_val = time_ref * (-1)

    if ((time1 + variance_val) >= 86400):
          time2 += 86400
    elif ((time1 + variance_val) <= 0):
          time1 += 86400

    time_diff = time2 - time1
    time_diff = abs(time_diff)

    if (time_diff*0.995) < time_ref < (time_diff*1.005):
        print("Time modified based on time reference")
    else:
        print("Time has not been modified based on time reference")
        ret_val = False
    return ret_val


def get_show_clock(dut):
    time = st.cli_show(dut, "show clock", skip_tmpl=False, mode = 'mgmt-user')
    if not time:
        st.log("show clock output is empty {}".format(time))
        return False
    for output in time:
        time1_hr = output['hours']
        time1_min = output['minutes']
        time1_sec = output['seconds']
        time1_meridiem = output['meridiem']
    time1 = time1_hr + ":" + time1_min + ":" + time1_sec + ' ' + time1_meridiem
    st.log("Clock time shown on device is {}".format(time1))
    # Validating 24 hrs conversion
    x = re.search(r'(\d+):(\d+):(\d+)\s+([A|P]M)',time1)
    amorpm = x.group(4)
    th1 = int(x.group(1))
    tm1 = int(x.group(2))
    ts1 = int(x.group(3))
    if amorpm == 'PM':
        if th1 == 12:
            ret_time = ((th1 * 3600) + (tm1 * 60) + ts1)
        else:
            ret_time = (((th1 + 12) * 3600) + (tm1 * 60) + ts1)
    else:
        if th1 == 12:
            ret_time = ((tm1 * 60) + ts1)
        else:
            ret_time = ((th1 * 3600) + (tm1 * 60) + ts1)
    return ret_time
