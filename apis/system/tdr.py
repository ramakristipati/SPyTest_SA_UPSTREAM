from spytest import st
import datetime
import re
from apis.system.rest import config_rest, get_rest
from utilities.utils import get_interface_number_from_name, get_supported_ui_type_list
from struct import unpack
from base64 import b64decode

try:
    import apis.yang.codegen.messages.platform_diagnostics as umf_plat_diag 
except ImportError:
    pass


def config(dut, intf=None, **kwargs):
    """
    API to configure cable-diagnostics on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :param intf:
    :param action:
        value: <enable|disable>, default is enable
    :return:
    """
    
    cli_type= st.get_ui_type(dut, **kwargs)
    #Force cli_type to klish as this cant be enabled globally in new API infra
    if cli_type in get_supported_ui_type_list() and intf is None: cli_type = 'klish'
    if cli_type in get_supported_ui_type_list():
        plat_diag_obj = umf_plat_diag.CableDiagnosticsInfo(Ifname=intf, Status='SUBMITTED')
        result = plat_diag_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config TDR {}'.format(result.message))
            return False
        return True
        
    if cli_type == "klish":
        confirm = 'y'
        skip_error = kwargs.get('skip_error', False)
        intf_info = get_interface_number_from_name(intf)
        if intf:
            cmd = 'test cable-diagnostics {} {}'.format(intf_info['type'], intf_info['number'])
        else:
            cmd = 'test cable-diagnostics'
        st.config(dut, cmd, confirm=confirm, skip_error_check=skip_error, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if intf:
            data={
                  "openconfig-platform-diagnostics:cable-diagnostics-info": [
                    {
                      "ifname": str(intf),
                      "config": {
                        "ifname": str(intf),
                        "status": "SUBMITTED"
                      }
                    }
                  ]
                }
            url1 = rest_urls['config_cable_diagnostics_int'].format(intf)
            if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=data):
                st.error("Failed to enable cable-diagnostics on interface {}".format(intf))
        else:
            url1 = rest_urls['config_cable_diagnostics']
            if not config_rest(dut, http_method=cli_type, rest_url=url1):
                st.error("Failed to enable cable-diagnostics on all interfaces")
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return True


def show(dut, intf=None, **kwargs):
    """
    API to show cable-diagnostics on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :param intf:
    :return:
    """
    cli_type= st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type == "klish":
        intf_info = get_interface_number_from_name(intf)
        if intf:
            cmd = 'show cable-diagnostics report {} {}'.format(intf_info['type'], intf_info['number'])
        else:
            cmd = 'show cable-diagnostics report'
        output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if intf:
            url1 = rest_urls['config_cable_diagnostics_int'].format(intf)
            data = get_rest(dut, http_method=cli_type, rest_url=url1)
        else:
            url1 = rest_urls['config_cable_diagnostics']
            data = get_rest(dut, http_method=cli_type, rest_url=url1)
        output =  process_tdr_output(data['output'])
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return output


def show_dom(dut, intf=None, **kwargs):
    """
    API to show dom parameters on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :param intf:
    :return:
    """
    cli_type= st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type == "klish":
        intf_info = get_interface_number_from_name(intf)
        if intf:
            cmd = 'show interface transceiver dom {} {}'.format(intf_info['type'], intf_info['number'])
        else:
            cmd = 'show interface transceiver dom'
        output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if intf:
            url1 = rest_urls['show_dom_int'].format(intf)
            data = get_rest(dut, http_method=cli_type, rest_url=url1)
        else:
            url1 = rest_urls['show_dom']
            data = get_rest(dut, http_method=cli_type, rest_url=url1)
        output = get_dom_info(data['output'])
        # output = convertbase64(output)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return output


def show_dom_summary(dut, intf=None, **kwargs):
    """
    API to show dom summary on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :param intf:
    :return:
    """
    cli_type= st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type == "klish":
        intf_info = get_interface_number_from_name(intf)
        if intf:
            cmd = 'show interface transceiver dom {} {} summary'.format(intf_info['type'], intf_info['number'])
        else:
            cmd = 'show interface transceiver dom summary'
        output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if intf:
            url1 = rest_urls['show_dom_int'].format(intf)
            data = get_rest(dut, http_method=cli_type, rest_url=url1)
        else:
            url1 = rest_urls['show_dom']
            data = get_rest(dut, http_method=cli_type, rest_url=url1)
        output = get_dom_info(data['output'])
        # output = convertbase64(output)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return output


def show_cable_length(dut, intf=None, **kwargs):
    """
    API to show cable length on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :param intf:
    :return:
    """
    cli_type= st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type == "klish":
        intf_info = get_interface_number_from_name(intf)
        if intf:
            cmd = 'show cable-diagnostics cable-length {} {}'.format(intf_info['type'], intf_info['number'])
        else:
            cmd = 'show cable-diagnostics cable-length'
        output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if intf:
            url1 = rest_urls['config_cable_diagnostics_int'].format(intf)
            data = get_rest(dut, http_method=cli_type, rest_url=url1)
        else:
            url1 = rest_urls['config_cable_diagnostics']
            data = get_rest(dut, http_method=cli_type, rest_url=url1)
        output = process_tdr_output(data['output'])
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return output


def get_time_stamp(data):
    elements =  re.findall(r"(\d+)\-(\S+)\-(\d+) (\d+)\:(\d+)\:(\d+)", data)
    if len(elements[0])==6:
        data = elements[0]
        ret_val = list()
        out = dict()
        out['monthday'] = data[0]
        out['month'] = data[1]
        out['year'] = data[2]
        out['hours'] = data[3]
        out['minutes'] = data[4]
        out['seconds'] = data[5]
        ret_val.append(out)
        return ret_val
    else:
        st.error("invalid data")
        return False

def verify_time_stamp(dut_time, stamp_time):
    diff=10
    month_dict = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
    try:
        time1 = datetime.datetime(int(dut_time['year']), month_dict[dut_time['month']], int(dut_time['monthday']), int(dut_time['hours']), int(dut_time['minutes']), int(dut_time['seconds']))
        time2 = datetime.datetime(int(stamp_time['year']), month_dict[stamp_time['month']], int(stamp_time['monthday']), int(stamp_time['hours']), int(stamp_time['minutes']), int(stamp_time['seconds']))
        difference = (time1 - time2).total_seconds()
    except Exception as e:
        st.error("'{}' exception occurred".format(e))
        return False
    return True if int(difference) < diff else False


def process_tdr_output(data):
    retval = []
    if data.get("openconfig-platform-diagnostics:cable-diagnostics-info") and isinstance(data["openconfig-platform-diagnostics:cable-diagnostics-info"], list):
        cable_diagnostics_info = data["openconfig-platform-diagnostics:cable-diagnostics-info"]
    elif data.get("openconfig-platform-diagnostics:cable-diagnostics") and data["openconfig-platform-diagnostics:cable-diagnostics"].get("cable-diagnostics-info") and isinstance(data["openconfig-platform-diagnostics:cable-diagnostics"]["cable-diagnostics-info"], list):
        cable_diagnostics_info = data["openconfig-platform-diagnostics:cable-diagnostics"]["cable-diagnostics-info"]
    else:
        return retval
    for output in cable_diagnostics_info:
       temp = dict()
       if isinstance(output, dict) and output.get("state") and isinstance(output["state"], dict):
         temp["interface"] = output["state"]["ifname"] if output["state"].get("ifname") else ""
         temp["status"] = output["state"]["status"] if output["state"].get("status") else ""
         temp["timestamp"] = output["state"]["timestamp"] if output["state"].get("timestamp") else ""
         temp["length"] = output["state"]["length"] if output["state"].get("length") else ""
         temp["result"] = output["state"]["result"] if output["state"].get("result") else ""
         temp["type"] = output["state"]["type"] if output["state"].get("type") else ""
         retval.append(temp)
    st.debug(retval)
    return retval


def get_dom_info(data):
    retval = list()
    if data.get("openconfig-platform-diagnostics:transceiver-dom") and data["openconfig-platform-diagnostics:transceiver-dom"].get("transceiver-dom-info") and isinstance(data["openconfig-platform-diagnostics:transceiver-dom"]["transceiver-dom-info"], list):
        req_data = data["openconfig-platform-diagnostics:transceiver-dom"]["transceiver-dom-info"]
    elif data.get("openconfig-platform-diagnostics:transceiver-dom-info") and isinstance(
            data["openconfig-platform-diagnostics:transceiver-dom-info"], list):
        req_data = data["openconfig-platform-diagnostics:transceiver-dom-info"]
    else:
        return retval
    for entry in req_data:
        temp = dict()
        if isinstance(entry, dict) and entry.get("state") and isinstance(entry["state"], dict):
            temp["port"] = entry["state"]["ifname"] if entry["state"].get("ifname") else ""
            temp["type"] = entry["state"]["type"] if entry["state"].get("type") else ""
            temp["warn_volt_hi"] = entry["state"]["warning-volt-hi"] if entry["state"].get("warning-volt-hi") else ""
            temp["warn_tx_power_lo"] = entry["state"]["warning-tx-power-lo"] if entry["state"].get("warning-tx-power-lo") else ""
            temp["warn_volt_lo"] = entry["state"]["warning-volt-lo"] if entry["state"].get("warning-volt-lo") else ""
            temp["warn_tx_power_hi"] = entry["state"]["warning-tx-power-hi"] if entry["state"].get("warning-tx-power-hi") else ""
            temp["voltage"] = entry["state"]["voltage"] if entry["state"].get("voltage") else ""
            temp["warn_rx_power_lo"] = entry["state"]["warning-rx-power-lo"] if entry["state"].get("warning-rx-power-lo") else ""
            temp["temperature"] = entry["state"]["temperature"] if entry["state"].get("temperature") else ""
            temp["al_tx_power_lo"] = entry["state"]["alarm-tx-power-lo"] if entry["state"].get("alarm-tx-power-lo") else ""
            temp["warn_tx_bias_lo"] = entry["state"]["warning-tx-bias-lo"] if entry["state"].get("warning-tx-bias-lo") else ""
            temp["al_tx_bais_hi"] = entry["state"]["alarm-tx-bias-hi"] if entry["state"].get("alarm-tx-bias-hi") else ""
            temp["al_rx_power_hi"] = entry["state"]["alarm-rx-power-hi"] if entry["state"].get("alarm-rx-power-hi") else ""
            temp["al_tx_bais_lo"] = entry["state"]["alarm-tx-bias-lo"] if entry["state"].get("alarm-tx-bias-lo") else ""
            temp["al_rx_power_lo"] = entry["state"]["alarm-rx-power-lo"] if entry["state"].get("alarm-rx-power-lo") else ""
            temp["al_temp_lo"] = entry["state"]["alarm-temp-lo"] if entry["state"].get("alarm-temp-lo") else ""
            temp["vendor"] = entry["state"]["vendor"] if entry["state"].get("vendor") else ""
            temp["warn_temp_lo"] = entry["state"]["warning-temp-lo"] if entry["state"].get("warning-temp-lo") else ""
            temp["tx1_bias"] = entry["state"]["tx1-bias"] if entry["state"].get("tx1-bias") else ""
            temp["tx2_bias"] = entry["state"]["tx2-bias"] if entry["state"].get("tx2-bias") else ""
            temp["tx3_bias"] = entry["state"]["tx3-bias"] if entry["state"].get("tx3-bias") else ""
            temp["tx4_bias"] = entry["state"]["tx4-bias"] if entry["state"].get("tx4-bias") else ""
            temp["tx5_bias"] = entry["state"]["tx5-bias"] if entry["state"].get("tx5-bias") else ""
            temp["tx6_bias"] = entry["state"]["tx6-bias"] if entry["state"].get("tx6-bias") else ""
            temp["tx7_bias"] = entry["state"]["tx7-bias"] if entry["state"].get("tx7-bias") else ""
            temp["tx8_bias"] = entry["state"]["tx8-bias"] if entry["state"].get("tx8-bias") else ""
            temp["warn_tx_bias_hi"] = entry["state"]["warning-tx-bias-hi"] if entry["state"].get("warning-tx-bias-hi") else ""
            temp["rx1_power"] = entry["state"]["rx1-power"] if entry["state"].get("rx1-power") else ""
            temp["rx2_power"] = entry["state"]["rx2-power"] if entry["state"].get("rx2-power") else ""
            temp["rx3_power"] = entry["state"]["rx3-power"] if entry["state"].get("rx3-power") else ""
            temp["rx4_power"] = entry["state"]["rx4-power"] if entry["state"].get("rx4-power") else ""
            temp["rx5_power"] = entry["state"]["rx5-power"] if entry["state"].get("rx5-power") else ""
            temp["rx6_power"] = entry["state"]["rx6-power"] if entry["state"].get("rx6-power") else ""
            temp["rx7_power"] = entry["state"]["rx7-power"] if entry["state"].get("rx7-power") else ""
            temp["rx8_power"] = entry["state"]["rx8-power"] if entry["state"].get("rx8-power") else ""
            temp["presence"]= ""
            temp["al_tx_power_hi"] = entry["state"]["alarm-tx-power-hi"] if entry["state"].get("alarm-tx-power-hi") else ""
            temp["al_volt_lo"]  = entry["state"]["alarm-volt-lo"] if entry["state"].get("alarm-volt-lo") else ""
            temp["al_volt_hi"] = entry["state"]["alarm-volt-hi"] if entry["state"].get("alarm-volt-hi") else ""
            temp["tx1_power"] = entry["state"]["tx1-power"] if entry["state"].get("tx1-power") else ""
            temp["tx2_power"] = entry["state"]["tx2-power"] if entry["state"].get("tx2-power") else ""
            temp["tx3_power"] = entry["state"]["tx3-power"] if entry["state"].get("tx3-power") else ""
            temp["tx4_power"] = entry["state"]["tx4-power"] if entry["state"].get("tx4-power") else ""
            temp["tx5_power"] = entry["state"]["tx5-power"] if entry["state"].get("tx5-power") else ""
            temp["tx6_power"] = entry["state"]["tx6-power"] if entry["state"].get("tx6-power") else ""
            temp["tx7_power"] = entry["state"]["tx7-power"] if entry["state"].get("tx7-power") else ""
            temp["tx8_power"] = entry["state"]["tx8-power"] if entry["state"].get("tx8-power") else ""
            temp["al_temp_hi"] = entry["state"]["alarm-temp-hi"] if entry["state"].get("alarm-temp-hi") else ""
            temp["vendor_part"] = entry["state"]["vendor-part"] if entry["state"].get("vendor-part") else ""
            temp["warn_temp_hi"] = entry["state"]["warning-temp-hi"] if entry["state"].get("warning-temp-hi") else ""
            temp["warn_rx_power_hi"] = entry["state"]["warning-rx-power-hi"] if entry["state"].get("warning-rx-power-hi") else ""
            retval.append(temp)
    st.debug(retval)
    return retval

def convert4BytesToStr(b):
    f = unpack('>f', b64decode(b))[0]
    return "{:.2f}".format(f)


def convertbase64(output):
    for entry in output:
        st.debug("entry: {}".format(entry))
        for key, value in entry.items():
            if key in ['rx7_power', 'tx2_power', 'warn_temp_lo', 'tx8_bias', 'rx5_power', 'tx5_bias', 'voltage',
                       'tx3_power', 'warn_tx_bias_lo', 'al_rx_power_hi', 'temperature', 'tx8_power', 'rx4_power',
                       'warn_tx_bias_hi', 'al_tx_bais_hi', 'tx7_power', 'tx3_bias', 'al_tx_power_lo', 'al_tx_bais_lo',
                       'al_tx_power_hi', 'tx2_bias', 'al_temp_lo', 'warn_rx_power_hi', 'tx6_power', 'warn_temp_hi',
                       'tx4_power', 'rx8_power', 'tx5_power', 'rx1_power', 'al_volt_lo', 'al_rx_power_lo',
                       'warn_rx_power_lo', 'tx1_power', 'warn_tx_power_lo', 'tx4_bias', 'tx1_bias', 'warn_tx_power_hi',
                       'rx2_power', 'tx7_bias', 'rx3_power', 'al_volt_hi', 'warn_volt_hi', 'tx6_bias', 'al_temp_hi',
                       'warn_volt_lo', 'rx6_power'] and  value:
                st.banner("Before conversion of entries")
                st.banner("key: {}, value: {}".format(key, value))
                entry[key] = convert4BytesToStr(value)
                st.banner("after conversion of entries")
                st.banner("key: {}, value: {}".format(key, value))
    st.banner("output after conversion is {}".format(output))
    return output
