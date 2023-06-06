import time
from tabulate import tabulate

from spytest import st
from utilities.common import filter_and_select
import apis.system.basic as basic_obj
from apis.system.rest import config_rest, delete_rest, get_rest
from utilities.utils import get_interface_number_from_name, segregate_intf_list_type, is_a_single_intf, get_supported_ui_type_list, convert_intf_name_to_component
import utilities.common as utils

try:
    import apis.yang.codegen.messages.udld_ext as umf_udld
    import apis.yang.codegen.messages.errdisable_ext as umf_errdisable
    from apis.yang.utils.common import Operation
except ImportError:
    pass

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type

def print_log(message,alert_type="LOW"):
    utils.print_log_alert(message, alert_type)

def config_udld_global(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_global(dut=data.dut1,udld_enable='yes',config='yes')
    config_udld_global(dut=data.dut1,udld_enable='yes')
    config_udld_global(dut=data.dut1,udld_enable='',config='no')
    udld.config_udld_global(dut=dut1,udld_enable='yes',config='yes',cli_type='rest-put')
    Configure udld global
    :param dut:
    :param udld_enable:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    st.log("Starting UDLD Module Configurations1...")
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    udld_enable =  kwargs.get('udld_enable',None)
    my_cmd = ''

    if cli_type in get_supported_ui_type_list():
        if config_cmd == '' and udld_enable is not None:
            udld_obj = umf_udld.Udld(AdminEnable=True)
            result = udld_obj.configure(dut, cli_type=cli_type)
        else:
            udld_obj = umf_udld.Udld(AdminEnable=False)
            result = udld_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Udld global Config {}'.format(result.data))
            return False
        return True

    if cli_type == 'klish' or cli_type == 'click':
        if 'udld_enable' in kwargs:
            my_cmd = '{} udld enable \n'.format(config_cmd)
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['udld_admin_config']
        if config_cmd == '' and udld_enable is not None:
            ocdata = {"openconfig-udld-ext:admin-enable":bool(1)}
        else:
            ocdata = {"openconfig-udld-ext:admin-enable":bool(0)}
        response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
        if not response:
            st.log('UDLD global config/unconfig failed')
            st.log(response)
            return False
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False
    return True

def config_udld_mode(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_mode(dut=data.dut1,udld_mode='yes',config='yes')
    config_udld_mode(dut=data.dut1,udld_mode='yes')
    config_udld_mode(dut=data.dut1,udld_mode='',config='yes')
    udld.config_udld_mode(dut=dut1,udld_mode='yes',config='yes',cli_type='rest-put')
    Configure udld mode to Agressive
    :param dut:
    :param udld_mode:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    udld_mode =  kwargs.get('udld_mode',None)
    if cli_type in get_supported_ui_type_list():
        if config_cmd == '' and udld_mode is not None:
            udld_obj = umf_udld.Udld(Aggressive=True)
            result = udld_obj.configure(dut, cli_type=cli_type)
        else:
            udld_obj = umf_udld.Udld(Aggressive=False)
            result = udld_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Udld mode Config {}'.format(result.data))
            return False
        return True

    if cli_type == 'klish' or cli_type == 'click':
        if 'udld_mode' in kwargs:
            my_cmd = '{} udld aggressive \n'.format(config_cmd)
        else:
            st.error("unknown request - {}".format(kwargs))
            return False
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['udld_aggressive_config']
        if config_cmd == '' and udld_mode is not None:
            ocdata = {"openconfig-udld-ext:aggressive":bool(1)}
        else:
            ocdata = {"openconfig-udld-ext:aggressive":bool(0)}
        response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
        if not response:
            st.log('UDLD global mode config/unconfig failed')
            st.log(response)
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_udld_message_time(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_message_time(dut=data.dut1,udld_message_time='3',config='yes')
    config_udld_message_time(dut=data.dut1,udld_message_time='3')
    config_udld_message_time(dut=data.dut1,udld_message_time='3',config='no')
    udld.config_udld_message_time(dut=dut1,udld_message_time='3',config='yes',cli_type='rest-put')
    Configure udld message time globally
    :param dut:
    :param udld_message_time:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    udld_message_time =  kwargs.get('udld_message_time',None)
    if cli_type in get_supported_ui_type_list():
        udld_obj = umf_udld.Udld(MsgTime=int(udld_message_time))
        #Workaround for default values. Setting of defult values are not working in FT runs
        if int(udld_message_time) == 1: config_cmd = 'no'
        if config_cmd == '' and udld_message_time is not None:
            result = udld_obj.configure(dut, cli_type=cli_type)
        else:
            result = udld_obj.unConfigure(dut, target_attr=udld_obj.MsgTime, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Udld message time Config {}'.format(result.data))
            return False
        return True

    if cli_type == 'klish' or cli_type == 'click':
        if 'udld_message_time' in kwargs:
            kwargs['udld_message_time'] = '' if config_cmd == 'no' else kwargs['udld_message_time']
            my_cmd = '{} udld message-time {} \n'.format(config_cmd, kwargs['udld_message_time'])
        else:
            st.error("unknown request - {}".format(kwargs))
            return False
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['udld_msgtime_config']
        ocdata = {"openconfig-udld-ext:msg-time":int(kwargs['udld_message_time'])}
        if config_cmd == '' and udld_message_time is not None:
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
        else:
            response = delete_rest(dut, http_method='delete', rest_url=rest_url, json_data=ocdata)
        if not response:
            st.log('UDLD global message time config/unconfig failed')
            st.log(response)
            return False
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False
    return True

def config_udld_multiplier(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_multiplier(dut=data.dut1,udld_multiplier='4',config='yes')
    config_udld_multipier(dut=data.dut1,udld_multiplier='4')
    config_udld_multipier(dut=data.dut1,udld_multiplier='4',config='no')
    udld.config_udld_multiplier(dut=dut1,udld_multiplier='3',config='yes',cli_type='rest-put')
    Configure udld multipllier globally
    :param dut:
    :param udld_multipier:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    udld_multiplier =  kwargs.get('udld_multiplier',None)
    if cli_type in get_supported_ui_type_list():
        udld_obj = umf_udld.Udld(Multiplier=int(udld_multiplier))
        #Workaround for default values. Setting of defult values are not working in FT runs
        if int(udld_multiplier) == 3: config_cmd = 'no'
        if config_cmd == '' and udld_multiplier is not None:
            result = udld_obj.configure(dut, cli_type=cli_type)
        else:
            result = udld_obj.unConfigure(dut, target_attr=udld_obj.Multiplier, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Udld message time Config {}'.format(result.data))
            return False
        return True
    if cli_type == 'klish' or cli_type == 'click':
        if 'udld_multiplier' in kwargs:
            kwargs['udld_multiplier'] = '' if config_cmd == 'no' else kwargs['udld_multiplier']
            my_cmd = '{} udld multiplier {} \n'.format(config_cmd, kwargs['udld_multiplier'])
        else:
            st.error("unknown request - {}".format(kwargs))
            return False
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['udld_multiplier_config']
        ocdata = {"openconfig-udld-ext:multiplier":int(kwargs['udld_multiplier'])}
        if config_cmd == '' and udld_multiplier is not None:
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
        else:
            response = delete_rest(dut, http_method='delete', rest_url=rest_url, json_data=ocdata)
        if not response:
            st.log('UDLD global message time config/unconfig failed')
            st.log(response)
            return False
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False
    return True

def config_intf_udld(dut, **kwargs):
    """
    config_intf_udld(dut=data.dut1,intf ='Ethernet10',udld_enable='yes',config='yes')
    config_intf_udld(dut=data.dut1,intf ='Ethernet10',udld_enable='yes')
    config_intf_udld(dut=data.dut1,intf ='Ethernet10',udld_enable='',config='no')
    udld.config_intf_udld(dut=dut2,intf ='Ethernet37',udld_enable='yes',config='yes',cli_type='rest-put')
    Author: Chandra.vedanaparthi@broadcom.com
    Enable UDLD at interface level
    :param dut:
    :param intf:
    :param udld_enable:
    :return:
    Added intf range support(pavan.kasula@broadcom.com)
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    if 'intf' not in kwargs:
        st.error("Please provide mandatory parameter Interface")
        return False
    if cli_type in get_supported_ui_type_list():
        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        interface_list = port_hash_list['intf_list_all']
        operation = Operation.CREATE
        for intf in interface_list:
            if config_cmd == '' and kwargs['udld_enable'] is not None:
                udld_obj = umf_udld.Interface(Name = intf, AdminEnable=True)
                result = udld_obj.configure(dut, operation=operation, cli_type=cli_type)
            else:
                udld_obj = umf_udld.Interface(Name = intf, AdminEnable=False)
                result = udld_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Udld intf Config {}'.format(result.data))
                return False
        return True
    if cli_type == 'klish' or cli_type == 'click':
        my_cmd = ''
        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        interface_list = port_hash_list['intf_list_all']

        for intf in interface_list:
            if not is_a_single_intf(intf):
                my_cmd +="interface range {}\n".format(intf)
            else:
                intf_details = get_interface_number_from_name(intf)
                if not intf_details:
                    st.log("Interface data not found for {} ".format(intf))
                my_cmd +="interface {} {}\n".format(intf_details["type"], intf_details["number"])
            if 'udld_enable' in kwargs:
                my_cmd += '{} udld enable\n'.format(config_cmd)
                my_cmd += 'exit\n'
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        interface_list = port_hash_list['intf_list_all']

        for intf1 in interface_list:
            rest_url = rest_urls['udld_interface_admin_config'].format(intf1)
            url2 = rest_urls['udld_interface']
            udld_int_data = {"openconfig-udld-ext:interfaces": {"interface": [{"name": intf1,"config": \
                {"name": intf1,"admin-enable": False,"aggressive": False}}]}}
            if not config_rest(dut, http_method=cli_type, rest_url=url2, json_data=udld_int_data):
                st.error("Failed to create udld interface container {}".format(intf1))
                return False
            if config_cmd == '':
                ocdata = {"openconfig-udld-ext:admin-enable":bool(1)}
            else:
                ocdata = {"openconfig-udld-ext:admin-enable":bool(0)}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            if not response:
                st.log('UDLD interface config/unconfig failed')
                st.log(response)
                return False
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False
    return True

def config_intf_udld_mode(dut, **kwargs):
    """
    config_intf_udld_mode(dut=data.dut1,intf ='Ethernet10',udld_mode='yes',config='yes')
    config_intf_udld_mode(dut=data.dut1,intf ='Ethernet10',udld_mode='yes')
    config_intf_udld_mode(dut=data.dut1,intf ='Ethernet10',udld_mode='',config='no')
    udld.config_intf_udld_mode(dut=dut2,intf ='Ethernet37',udld_mode='yes',config='yes',cli_type='rest-put')
    Author: Chandra.vedanaparthi@broadcom.com
    Enable UDLD mode Aggressive at interface level
    :param dut:
    :param intf:
    :param udld_mode:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    if 'intf' not in kwargs:
        st.error("Please provide mandatory parameter Interface")
        return False

    my_cmd= ''

    if cli_type in get_supported_ui_type_list():
        if config_cmd == '' and kwargs['udld_mode'] is not None:
            udld_obj = umf_udld.Interface(Name = kwargs['intf'], Aggressive=True)
            result = udld_obj.configure(dut, cli_type=cli_type)
        else:
            udld_obj = umf_udld.Interface(Name = kwargs['intf'], Aggressive=False)
            result = udld_obj.unConfigure(dut, target_attr= udld_obj.Aggressive, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Udld intf mode Config {}'.format(result.data))
            return False
        return True

    if cli_type == 'klish' or cli_type == 'click':

        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for intf in interface_list:
            if not is_a_single_intf(intf):
                my_cmd += "interface range {}\n".format(intf)
            else:
                intf_details = get_interface_number_from_name(intf)
                if not intf_details:
                    st.log("Interface data not found for {} ".format(intf))
                my_cmd += "interface {} {}\n".format(intf_details["type"], intf_details["number"])
            if 'udld_mode' in kwargs:
                my_cmd += '{} udld aggressive\n'.format(config_cmd)
                my_cmd += 'exit\n'
        st.config(dut, my_cmd,type='klish')

    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for intf in interface_list:
            rest_url = rest_urls['udld_interface_aggressive_config'].format(intf)
            if config_cmd == '':
                ocdata = {"openconfig-udld-ext:aggressive":bool(1)}
            else:
                ocdata = {"openconfig-udld-ext:aggressive":bool(0)}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            if not response:
                st.log('UDLD mode for interface config/unconfig failed')
                st.log(response)
                return False
            return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_udld_recover(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_recover(dut=data.dut1,udld_recover='enable',module="udld")
    config_udld_recover(dut=data.dut1,udld_recover='disable',module="udld")
    udld.config_udld_recover(dut=dut1,udld_recover='enable',module="udld",cli_type = 'klish')
    udld.config_udld_recover(dut=dut1,udld_recover='enable',module="udld",cli_type = 'rest-put')
    Configure udld recover global
    :param dut:
    :param udld_recover:
    :module:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    module = kwargs.get('module',None)
    udld_recover = kwargs.get('udld_recover',None)
    st.log("Starting UDLD recover Configurations1...")
    my_cmd= ''

    if cli_type in get_supported_ui_type_list():
        if udld_recover is not None and module is not None:
            errdisable_obj = umf_errdisable.Errdisable(Cause=kwargs['module'].upper())
            if udld_recover == 'enable':
                result = errdisable_obj.configure(dut, cli_type=cli_type)
            elif udld_recover == 'disable':
                result = errdisable_obj.unConfigure(dut, target_attr=errdisable_obj.Cause, cli_type=cli_type)
        else:
            st.error("Mandatory arguments udld recover and module name should be given")
            return False
        if not result.ok():
            st.log('test_step_failed: Udld recover Config {}'.format(result.data))
            return False
        return True

    if cli_type == 'click':
        if 'udld_recover' in kwargs and 'module' in kwargs:
            my_cmd = 'config errdisable recovery cause {} {}'.format(kwargs['udld_recover'],kwargs['module'])
        else:
            st.error("Mandatory arguments udld enable or disable and module name should be given")
            return False
        st.config(dut,my_cmd,type=cli_type)
    elif cli_type == 'klish':
        if udld_recover is not None and module is not None:
            if udld_recover == 'enable':
                my_cmd = 'errdisable recovery cause {}'.format(kwargs['module'])
            elif udld_recover == 'disable':
                my_cmd = 'no errdisable recovery cause {}'.format(kwargs['module'])
        else:
            st.error("Mandatory arguments udld recover and module name should be given")
            return False
        st.config(dut,my_cmd,type=cli_type)
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['errdisable_recover_cause_config']
        if module is not None and udld_recover is not None:
            ocdata = {"openconfig-errdisable-ext:cause":[module.upper()]}
            if udld_recover.lower() == 'enable':
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            elif udld_recover.lower() == 'disable':
                response = delete_rest(dut, http_method='delete', rest_url=rest_url, json_data=ocdata)
        else:
            st.error("Mandatory arguments udld recover and module name should be given")
            return False
        if not response:
            st.log('Errdisable recovery cause config/unconfig failed')
            st.log(response)
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_udld_recover_timer(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_recover_timer(dut=data.dut1,udld_recover_timer='30')
    config_udld_recover_timer(dut=data.dut1,udld_recover_timer='300')
    udld.config_udld_recover_timer(dut=dut1,udld_recover_timer='30',cli_type = 'klish')

    Configure udld recover timer
    :param dut:
    :param udld_recover_timer: 300 default in sec
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    udld_recover_timer = kwargs.get('udld_recover_timer',None)
    config = kwargs.get('config','')
    st.log("Starting UDLD recover timer Configurations1...")
    my_cmd= ''
    if cli_type in get_supported_ui_type_list():
        if udld_recover_timer is not None:
            errtimer_obj = umf_errdisable.Errdisable(Interval=kwargs['udld_recover_timer'])
            if config == '':
                result = errtimer_obj.configure(dut, cli_type=cli_type)
            else:
                result = errtimer_obj.unConfigure(dut, target_attr=errtimer_obj.Interval, cli_type=cli_type)
        else:
            st.error("Mandatory arguments udld recover and module name should be given")
            return False
        if not result.ok():
            st.log('test_step_failed: Udld recover Config {}'.format(result.data))
            return False
        return True
    if cli_type == 'click':
        if 'udld_recover_timer' in kwargs:
            my_cmd = 'config errdisable recovery interval {}'.format(kwargs['udld_recover_timer'])
        else:
            st.error("Mandatory argument udld recover timer should be given")
            return False
        st.config(dut,my_cmd,type=cli_type)
    elif cli_type == 'klish':
        if udld_recover_timer is not None:
            if config == '':
                my_cmd = 'errdisable recovery interval {}'.format(kwargs['udld_recover_timer'])
            else:
                my_cmd = 'no errdisable recovery interval'
        else:
            st.error("Mandatory argument udld recover timer should be given")
            return False
        st.config(dut,my_cmd,type=cli_type)
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['errdisable_recover_interval_config']
        if udld_recover_timer is not None:
            ocdata = {"openconfig-errdisable-ext:interval":int(udld_recover_timer)}
            if config == '':
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            else:
                response = delete_rest(dut, http_method='delete', rest_url=rest_url, json_data=ocdata)
        else:
            st.error("Mandatory arguments udld recover interval should be given")
            return False
        if not response:
            st.log('Errdisable recovery interval config/unconfig failed')
            st.log(response)
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def udld_reset(dut):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    udld_reset(dut=data.dut1)

    Reset the UDLD at exec level
    :param dut:
    :return:
    """
    my_cmd = 'udld reset'
    st.config(dut,my_cmd,type="click")

def udld_clear_stats(dut):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    udld_clear_stats(dut=data.dut1)

    Reset the UDLD stats at global level
    :param dut:
    :return:
    """
    my_cmd = 'clear udld statistics'
    st.config(dut,my_cmd,type="click")

def udld_clear_stats_intf(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    udld_clear_stats_intf(dut=data.dut1,intf =['Ethernet10','Ethernet11'])

    Reset the UDLD stats at interface level
    :param dut:
    :param intf:
    :return:
    """
    if 'intf' not in kwargs:
        st.error("Please provide mandatory parameter Interface")
        return False

    port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
    interface_list = port_hash_list['intf_list_all']
    my_cmd= ''
    for intf in interface_list:
        intf = convert_intf_name_to_component(dut, intf_list=intf)
        '''
        if '/' in intf:
            intf = st.get_other_names(dut,[intf])[0]
        '''
        my_cmd += 'clear udld statistics {}\n'.format(intf)
    st.config(dut,my_cmd,type="click")

def udld_block(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    udld_blockf(dut=data.dut1,intf ='Ethernet10')

    Block the UDLD packtets at interface level
    :param dut:
    :param intf:
    :return:
    """
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = 'enable'
    else:
        config_cmd = 'disable'

    if 'intf' in kwargs:
        my_cmd= ''
        port_hash_list = segregate_intf_list_type(intf=kwargs['intf'], range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for intf in interface_list:
            intf = convert_intf_name_to_component(dut, intf_list=intf, component='applications')
            '''
            if '/' in intf:
                intf = st.get_other_names(dut,[intf])[0]
            '''
            my_cmd += 'udldctl rx_drop {} {}\n'.format(config_cmd,intf)
    else:
        st.error("Mandatory argument interface name Not Found")
        return False
    st.config(dut,my_cmd,type="click")
    return True

def udld_cfg_ebtables_rule(dut, **kwargs):
    if 'add' in kwargs:
        if kwargs['add']:
            cmd = "sudo ebtables -A FORWARD "
        else:
            cmd = "sudo ebtables -D FORWARD "
    else:
        print_log('Missing keyword')
        return
    cmd = cmd + "-d 1:0:c:cc:cc:cc -j DROP"
    st.show(dut, cmd, skip_tmpl=True)

def verify_udld_global(dut,**kwargs):
    """
    Author: Chandra Sekhar Reddy
    email : chandra.vedanaparthi@broadcom.com
    Verify show udld global output
    :param dut:
    :param kwargs: Parameters can be <udld_admin_state|udld_mode|udld_message_time|udld_multiplier|All>
    :return:
    Usage:
    udld.verify_udld_global(data.dut1,udld_admin_state="enabled", udld_mode='Normal', udld_message_time="1", udld_multiplier="3",cli_type = 'rest-put')
    verify_udld_global(dut1,udld_message_time="1", udld_multiplier="3")
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    ret_val = True
    udld_admin_state = kwargs.get('udld_admin_state',None)
    udld_mode = kwargs.get('udld_mode',None)
    udld_message_time = kwargs.get('udld_message_time',None)
    udld_multiplier = kwargs.get('udld_multiplier',None)

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        udld_obj = umf_udld.Udld()
        if udld_admin_state:
            udld_obj.AdminEnable = True if udld_admin_state.lower() == 'enabled' else False
        if udld_mode:
            udld_obj.Aggressive = True if udld_mode.lower() == 'aggressive' else False
        if udld_message_time: udld_obj.MsgTime = int(udld_message_time)
        if udld_multiplier: udld_obj.Multiplier = int(udld_multiplier)
        result = udld_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Match NOT Found: UDLD global parameters')
            return False
        return True

    if cli_type == 'klish' or cli_type == 'click':
        cmd = 'show udld global'
        output = st.show(dut,cmd,type="klish",config="false",skip_error_check="True")
        st.log("Before output......................")
        st.log("{}".format(tabulate(output, headers="keys", tablefmt='psql')))
        st.log("After output......................")
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        for key in kwargs:
            if str(kwargs[key]) != str(output[0][key]):
                st.error("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
                ret_val = False
            else:
                st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
        return ret_val
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['show_udld_global_get']
        output = get_rest(dut, rest_url=rest_url)['output']
        if output:
            payload = output['openconfig-udld-ext:udld']['state']
            if udld_mode is not None and udld_mode != 'Normal':
                if (payload[udld_mode.lower()]) is not True and 'aggressive' in payload:
                    ret_val = False
            if udld_admin_state is not None  and 'admin-enable' in payload:
                if udld_admin_state.lower() == 'enabled':
                    if (payload['admin-enable']) is not True:
                        ret_val = False
            if udld_message_time is not None and 'msg-time' in payload:
                if payload['msg-time'] != int(udld_message_time):
                    ret_val = False
            if udld_multiplier is not None and 'multiplier' in payload:
                if payload['multiplier'] != int(udld_multiplier):
                    ret_val = False
        else:
            st.log("Rest output empty")
            ret_val = False
        return ret_val

def verify_udld_neighbors(dut,**kwargs):
    """
    Author: Chandra Sekhar Reddy
    email : chandra.vedanaparthi@broadcom.com
    :param dut:
    :param local_port:
    :type string or list
    :param device_name:
    :type string or list
    :param remote_device_id:
    :type mac in string or list
    :param remote_port:
    :type string or list
    :param neighbor_state:
    :type string or list
    :return:

    Usage
    verify_udld_neighbors(dut1,local_port=['Ethernet1','Ethernet3'],device_name=['Sonic','Sonic'],
                             remote_device_id=['3c2c.992d.8201','3c2c.992d.8202'],remote_port=['Ethernet0','Ethernet3'],\
                             neighbor_state=['Bidirectional','Bidirectional'])
    verify_udld_neighbors(dut1,local_port='Ethernet3',neighbor_state='Bidirectional')
    udld.verify_udld_neighbors(dut1,local_port='Ethernet32',neighbor_state='Bidirectional', device_name='Sonic' ,remote_device_id ='3C2C.99A6.FBA0' ,remote_port ='Ethernet24',cli_type = 'rest-put')
    """
    ret_val = True
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    #Forcing to klish due to JIRA:60045
    #cli_type = force_cli_type_to_klish(cli_type=cli_type)

    remote_port = kwargs.get('remote_port',None)
    device_name = kwargs.get('device_name',None)
    neighbor_state = kwargs.get('neighbor_state',None)
    local_port = kwargs.get('local_port',None)
    if cli_type in get_supported_ui_type_list() and 'return_output' in kwargs:
        cli_type ='klish'
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        udld_obj = umf_udld.Udld()
        remote_port = utils.make_list(remote_port)
        device_name = utils.make_list(device_name)
        neighbor_state = utils.make_list(neighbor_state)
        local_port = utils.make_list(local_port)
        for port, rport, dname, nstate in zip(local_port, remote_port, device_name, neighbor_state):
            udld_intf_obj = umf_udld.Interface(Name=port,Udld=udld_obj)
            #nbr_state = 'oc-udld-types:' + nstate.upper()
            nbr_state = nstate.upper()
            #print("############ {} ##########".format(nbr_state))
            udld_nbr_obj = umf_udld.Neighbor(Index=1,DeviceName=dname, Status=nbr_state, PortId=rport,Interface=udld_intf_obj)
            result = udld_nbr_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Match NOT Found: UDLD neighbor')
                return False
        return True

    if cli_type == 'klish' or cli_type == 'click':
        output = st.show(dut,'show udld neighbors',type="klish",config="false",skip_error_check="True")
        st.log("Before output......................")
        st.log("{}".format(tabulate(output, headers="keys", tablefmt='psql')))
        st.log("After output......................")
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        if 'return_output' in kwargs:
            return output
        #Converting all kwargs to list type to handle single or list of udld neighbors
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]
        #convert kwargs into list of dictionary
        input_dict_list =[]
        for i in range(len(kwargs[list(kwargs.keys())[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)
        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if not entries:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False
        return ret_val
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        if type(local_port) is list:
            local_port = list(local_port)
        else:
            local_port = [local_port]
        try:
            for port,rport,dname,nstate in zip (local_port,remote_port,device_name,neighbor_state):
                rest_url = rest_urls['show_udld_interface_state_get'].format(port)
                payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-udld-ext:neighbors-info']['neighbor']
                for neighbor in payload:
                    if remote_port is not None:
                        if neighbor['state']['port-id'] != str(rport):
                            ret_val = False
                    if device_name is not None:
                        if neighbor['state']['device-name'] != str(dname).lower():
                            ret_val = False
                    if neighbor_state is not None:
                        if neighbor['state']['status'].split(':')[1] != str(nstate).upper():
                            ret_val = False
        except Exception as e:
            st.error("Exception is {}".format(e))
            ret_val = False
        return ret_val

def get_udld_intf_state(dut, **kwargs):
    cmd = 'show udld interface '
    if 'udld_intf' in kwargs:
        udld_intf = kwargs['udld_intf']
        del kwargs['udld_intf']
        cmd += '{}'.format(udld_intf)
    else:
        st.error("Mandatory argument interface name Not Found")
        return None

    output = st.show(dut, cmd,type="klish",config="false")
    if output and  len(output) > 0:
        if 'udld_status' in output[0].keys():
            return output[0]['udld_status']
        else:
            return None

def verify_udld_interface(dut,**kwargs):
    """
    Author: Chandra Sekhar Reddy
    email: chandra.vedanaparthi@broadcom.com
    Verify show udld interface ouput
    :param dut:
    :param kwargs: Parameters can be <udld_intf|udld_admin_state|udld_mode|udld_status|local_device_id|local_port
    :                                |local_device_name|local_udld_message_time|local_udld_multiplier
    :                                |neighbor_device_id|neighbor_port|neighbor_device_name|neighbor_udld_message_time
    :                                |neighbor_udld_multiplier|neighbor_udld_multiplier>
    :return:
    Usage:
    verify_udld_interface(dut1,udld_intf='Ethernet1", udld_admin_state='Enabled', udld_mode='Aggressive', udld_status='Bidirectional', \
                            local_device_id="3c2c.992d.8201",local_port='Ethernet1', local_device_name='Sonic' \
                            local_udld_message_time=1, local_udld_multiplier=3, neighbor_device_id="3c2c.992d.8235" \
                            neighbor_port='Ethernet2', neighbor_device_name='Sonic', neighbor_udld_message_time=1, neighbor_udld_multiplier=3)
    udld.verify_udld_interface(data.dut1,udld_intf='Ethernet32", udld_admin_state='Enabled', udld_mode='Normal', udld_status='Bidirectional', neighbor_port='Ethernet24', neighbor_device_name='Sonic', neighbor_udld_message_time=1, neighbor_udld_multiplier=3, cli_type = 'rest-put')
    """
    ret_val = True
    cmd = 'show udld interface '
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    # Forcing to klish due to JIRA:60047
    #cli_type = force_cli_type_to_klish(cli_type=cli_type)

    udld_admin_state = kwargs.get('udld_admin_state',None)
    udld_mode = kwargs.get('udld_mode',None)
    udld_status = kwargs.get('udld_status',None)
    neighbor_device_id = kwargs.get('neighbor_device_id',None)
    neighbor_port = kwargs.get('neighbor_port',None)
    neighbor_device_name = kwargs.get('neighbor_device_name',None)
    neighbor_udld_message_time = kwargs.get('neighbor_udld_message_time',None)
    neighbor_udld_multiplier = kwargs.get('neighbor_udld_multiplier',None)
    if 'udld_intf' in kwargs:
        udld_intf = kwargs['udld_intf']
        del kwargs['udld_intf']
        cmd += '{}'.format(udld_intf)
    else:
        st.error("Mandatory argument interface name Not Found")
        return False

    if cli_type in get_supported_ui_type_list() and 'return_output' in kwargs:
        cli_type ='klish'
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        udld_obj = umf_udld.Udld()
        udld_intf_obj = umf_udld.Interface(Name=udld_intf, Udld=udld_obj)
        if udld_admin_state:
            udld_intf_obj.AdminEnable = True if udld_admin_state.lower() == 'enabled' else False
        if udld_mode:
            udld_intf_obj.Aggressive = True if udld_mode.lower() == 'aggressive' else False
        if udld_status:
            udld_status = udld_status.upper()
            if udld_status == 'BIDIRECTIONAL':
                #udld_intf_obj.Status = 'oc-udld-types:BIDIRECTIONAL'
                udld_intf_obj.Status = 'BIDIRECTIONAL'
            elif udld_status == 'UNDETERMINED':
                udld_intf_obj.Status = 'UNDETERMINED'
        result = udld_intf_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Match NOT Found: UDLD Local Interface Parameters')
            return False
        if udld_status.upper() == 'BIDIRECTIONAL':
            udld_nbr_obj = umf_udld.Neighbor(Index=1,Interface=udld_intf_obj)
            if neighbor_device_id:
                udld_nbr_obj.DeviceId = neighbor_device_id
            if neighbor_port:
                udld_nbr_obj.PortId = neighbor_port
            if neighbor_device_name:
                udld_nbr_obj.DeviceName = neighbor_device_name
            if neighbor_udld_message_time: udld_nbr_obj.MsgTime = int(neighbor_udld_message_time)
            if neighbor_udld_multiplier: udld_nbr_obj.TimeoutInterval = int(neighbor_udld_multiplier)
            result = udld_nbr_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Match NOT Found: UDLD Remote Interface Parameters')
                return False
        return True
    if cli_type == 'klish' or cli_type == 'click':
        output = st.show(dut, cmd,type="klish",config="false",skip_error_check="True")
        st.log("Before output......................")
        st.log("{}".format(cmd))
        st.log("{}".format(tabulate(output, headers="keys", tablefmt='psql')))
        st.log("After output......................")
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        for key in kwargs:
            if str(kwargs[key]) != str(output[0][key]):
                st.error("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
                ret_val = False
            else:
                st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
        return ret_val
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['show_udld_interface_local_and_remote_state_get'].format(udld_intf)
        try:
            payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-udld-ext:interface']
            if udld_mode is not None and udld_mode != 'Normal':
                if (payload[0]['state']['aggressive']) is not True:
                    ret_val = False
            if udld_admin_state is not None:
                if udld_admin_state.lower() == 'enabled':
                    if (payload[0]['state']['admin-enable']) is not True:
                        ret_val = False
            if udld_status is not None:
                if payload[0]['local-info']['state']['status'].split(':')[1] != str(udld_status).upper():
                    ret_val = False
            if udld_status == 'Bidirectional':
                neigh = payload[0]['neighbors-info']
                if neighbor_device_id is not None:
                    if neigh['neighbor'][0]['state']['device-id'] != str(neighbor_device_id):
                        ret_val = False
                if neighbor_port is not None:
                    if neigh['neighbor'][0]['state']['port-id'] != str(neighbor_port):
                        ret_val = False
                if neighbor_device_name is not None:
                    if neigh['neighbor'][0]['state']['device-name'] != str(neighbor_device_name).lower():
                        ret_val = False
                if neighbor_udld_message_time is not None:
                    if neigh['neighbor'][0]['state']['msg-time'] != int(neighbor_udld_message_time):
                        ret_val = False
                if neighbor_udld_multiplier is not None:
                    if neigh['neighbor'][0]['state']['timeout-interval'] != int(neighbor_udld_multiplier):
                        ret_val = False
        except Exception as e:
            st.error("The Exception is {} on DUT: {}".format(e, dut))
            ret_val = False
        return ret_val

def verify_udld_statistics(dut,**kwargs):
    """
    Author: Chandra Sekhar Reddy
    email : chandra.vedanaparthi@broadcom.com
    :param dut:
    :param udld_interface:
    :type  String or list
    :param udld_tx
    :type integer or list of integers
    :param udld_rx
    :type integer or list of integers
    :param udld_errors
    :type integer or list of integers
    :return:

    Usage
    verify_udld_statistics(dut1,udld_interface=['Ethernet24','Ethernet32'],udld_tx=[10,10],udld_rx=[10,10],udld_errors=[10,10])

    verify_udld_statistics(dut1,udld_interface='Ethernet24','Ethernet32',udld_tx=10,udld_rx=10,udld_errors=10)
    udld.verify_udld_statistics(dut1,udld_interface='Ethernet41',udld_tx=5708,udld_rx=5708,udld_errors=0,cli_type='rest-put')

    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    udld_interface = kwargs.get('udld_interface',None)
    udld_tx = kwargs.get('udld_tx',None)
    udld_rx = kwargs.get('udld_rx',None)
    #udld_errors = kwargs.get('udld_errors',None)
    #Converting all kwargs to list type to handle single or list of udld stats
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    if cli_type == 'klish' or cli_type == 'click':
        if len(kwargs['udld_interface']) > 1:
            cmd = "show udld statistics"
        else:
            cmd = "show udld statistics interface {}".format(kwargs['udld_interface'])
        output = st.show(dut, cmd,type="klish",config="false")
        if 'return_output' in kwargs:
            return output
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        #convert kwargs into list of dictionary
        input_dict_list =[]
        for i in range(len(kwargs[list(kwargs.keys())[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)
        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if not entries:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False
        return ret_val
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        if type(udld_interface) is list:
            udld_interface = list(udld_interface)
        else:
            udld_interface = [udld_interface]
        for intf in udld_interface:
            rest_url = rest_urls['show_udld_interface_counters_get'].format(intf)
            payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-udld-ext:counters']
            if udld_tx is not None:
                if payload['pdu-sent'] != int(udld_tx):
                    ret_val = False
            if udld_rx is not None:
                if payload['pdu-received'] != int(udld_rx):
                    ret_val = False
        return ret_val

def check_udld_status_after_restart(dut):
    ret = False
    max_wait_time = 300 # 5 mins, reason, cold reboot might take upto 5mins
    wait_start_time = time.time()
    total_wait_time = 0
    while not ret:
        st.wait(2)
        total_wait_time = int(time.time() - wait_start_time)
        st.log("Verify UDLD service status after {} sec".format(total_wait_time))
        if total_wait_time > max_wait_time:
            st.error('UDLD is NOT READY even after {} seconds'.format(total_wait_time))
            return False
        ret = basic_obj.verify_service_status(dut, "udld")

    st.log('UDLD is READY after {} seconds'.format(total_wait_time))
    return True
