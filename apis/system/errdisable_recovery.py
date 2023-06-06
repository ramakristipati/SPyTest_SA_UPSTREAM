from spytest import st
from utilities.common import filter_and_select, make_list, get_query_params
from apis.system.rest import config_rest, delete_rest, get_rest
from utilities.utils import get_supported_ui_type_list

try:
    import apis.yang.codegen.messages.errdisable_ext.ErrdisableExt as umf_errdis_ext
except ImportError:
    pass


def config_errdisable_recovery(dut,**kwargs):
    """

    :param dut:
    :param cause:
    :param interval:
    :param kwargs:
    :return:
    """
    result = True
    skip_error_check = kwargs.get("skip_error_check", False)
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    cause = make_list(kwargs.get('cause')) if kwargs.get('cause') else None
    interval = kwargs.get('interval', None)
    if cli_type in get_supported_ui_type_list():
        if cause:
            for ea in cause:
                ea = ea.replace('-', '_')
                err_cause_obj = umf_errdis_ext.Errdisable(Cause=ea.upper())
                if config == 'yes':
                    result = err_cause_obj.configure(dut, cli_type=cli_type)
                else:
                    result = err_cause_obj.unConfigure(dut, target_attr=err_cause_obj.Cause, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Config Error Recovery {}'.format(result.data))
                    return False
        if interval:
            err_int_obj = umf_errdis_ext.Errdisable(Interval=interval)
            if config == 'yes':
                result = err_int_obj.configure(dut, cli_type=cli_type)
            else:
                result = err_int_obj.unConfigure(dut, target_attr=err_int_obj.Interval, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config Error Recovery {}'.format(result.data))
                return False
        return True
    if cli_type == 'klish':
        config = 'no' if config == 'no' else ''
        cmd = list()
        if cause:
            for ea in cause:
                cmd.append("{} errdisable recovery cause {}".format(config, ea))
        if interval:
            interval = "" if config == "no" else interval
            cmd.append("{} errdisable recovery interval {}".format(config, interval))
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type == 'click':
        config = 'disable' if config == 'no' else 'enable'
        cmd = list()
        if cause:
            for ea in cause:
                if ea == 'udld':
                    cmd.append('sudo config errdisable recovery  cause {} udld'.format(config))
                else:
                    st.log("Unsupported cli type {} for cause type {}".format(cli_type, ea))
        if interval:
            cmd.append('sudo config errdisable recovery interval {}'.format(interval))
        st.config(dut, '; '.join(cmd), type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if cause:
            for ea in cause:
                ea = ea.replace('-', '_')
                if config == 'yes':
                    rest_url = rest_urls['errdisable_recover_cause_config']
                    data1 = {"openconfig-errdisable-ext:cause": [ea.upper()]}
                    if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data1):
                        st.error("Failed to enable errdisable recovery cause for {} through REST").format(ea)
                        result = False
                elif config == 'no':
                    del_url = rest_urls['errdisable_recover_specific_cause_unconfig'].format(ea.upper())
                    if not delete_rest(dut, http_method=cli_type, rest_url=del_url):
                        st.error("Failed to disable errdisable recovery cause for {} through REST").format(ea)
                        result = False
        if interval:
            rest_url = rest_urls['errdisable_recover_interval_config']
            data2 = {"openconfig-errdisable-ext:interval": int(interval)}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data2):
                    st.error("Failed to configure errdisable recovery interval through REST")
                    result = False
            elif config == 'no':
                if not delete_rest(dut, http_method=cli_type, rest_url=rest_url):
                    st.error("Failed to unconfigure errdisable recovery interval through REST")
                    result = False
    return result


def show_errdisable_recovery(dut, **kwargs):
    """
    show_errdisable_recovery(dut=vars.D1,**kwargs)
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    show_command = "show errdisable recovery"
    if cli_type in ['klish', 'click']:
        output = st.show(dut, show_command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['get_errdisable_recovery']
        result = get_rest(dut, http_method=cli_type, rest_url=url)
        try:
            response = result['output']['openconfig-errdisable-ext:errdisable']
            temp = {}
            output = []
            temp.update({'interval': result['output']['openconfig-errdisable-ext:errdisable']['config'].get('interval')})
            if 'cause' in response['config']:
                for info in response['config']['cause']:
                    info = info.split(":")[1]
                    if 'LINK' in info:
                        temp.update({'link_flap': info})
                    elif 'BPDUGUARD' in info:
                        temp.update({'bpduguard': info})
                    elif 'UDLD' in info:
                        temp.update({'udld': info})
            output.append(temp)
        except Exception as e:
            st.error("Exception is{}".format(e))
            return False
    return output


def verify_errdisable_recovery(dut, **kwargs):
    """
    verify_errdisable_recovery(dut=vars.D1, verify_list= [{'link_flap':'enabled','interface': 'Ethernet10', 'errdisable_reason': 'link-flap', 'timeleft'=10}])
    verify_errdisable_recovery(dut=vars.D1, verify_list= [{'udld':'enabled','interval': '40'}])
    verify_errdisable_recovery(dut=vars.D1, verify_list= [{'bpduguard':'enabled','interval': '60'}])
    verify_errdisable_recovery(dut=vars.D1, verify_list= [{'udld':'disabled'}])
    :param dut:
    :param kwargs:
    :return:
    """
    st.log('API_NAME: verify_errdisable_recovery, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    if not kwargs.get('verify_list'):
        st.error("verify_list is not provided")

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        for each in make_list(kwargs['verify_list']):
            err_disable_obj = umf_errdis_ext.Errdisable()
            if each.get('link_flap') == 'enabled': err_disable_obj.Cause = 'LINK_FLAP'
            if each.get('bpduguard') == 'enabled': err_disable_obj.Cause = 'BPDUGUARD'
            if each.get('udld')  == 'enabled': err_disable_obj.Cause = 'UDLD'
            if each.get('interval'): err_disable_obj.Interval = each['interval']
            result = err_disable_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Match Not Found for Cause')
                return False
        return True

    output = show_errdisable_recovery(dut, **kwargs)
    for each in make_list(kwargs['verify_list']):
        if cli_type in ["rest-put", "rest-patch"]:
            if each['link_flap']:
                if each['link_flap'] == 'enabled':
                    each['link_flap'] = 'LINK_FLAP'
                else:
                    each.pop('link_flap')
            elif each['bpduguard']:
                if each['bpduguard'] == 'enabled':
                    each['bpduguard'] = 'BPDUGUARD'
                else:
                    each.pop('bpduguard')
            elif each['udld']:
                if each['udld'] == 'enabled':
                    each['udld'] = 'UDLD'
                else:
                    each.pop('pop')
        entries=filter_and_select(output, None, each)
        st.debug(entries)
        if not entries:
            st.error("match {} is not in output {}".format(each, output))
            return False
    return True


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type
