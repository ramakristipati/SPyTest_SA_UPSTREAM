##########################################
#RCC APIs (Route Consistency Checker)
##########################################
from spytest import st
import spytest.utils as utils
from apis.common import redis
from utilities.utils import get_supported_ui_type_list
#from utilities.utils import segregate_intf_list_type, is_a_single_intf
#from apis.system.rest import get_rest, config_rest, delete_rest
#from utilities.common import filter_and_select

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type

def force_cli_type_to_click(cli_type):
    cli_type = "click" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type

def config_consistency_check(dut, **kwargs):
    '''
    This is operational command to trigger Route Consistency Check.
    Author: sunil.rajendra@broadcom.com
    :param dut:
    :param config: yes/no.
    :param vrf: VRF name.
    :param family: address family - ipv4/ipv6.
    :param threshold: threshold value.
    :param feature: default:route. <route/acl>.
    :param cli_type: CLI type - click/klish/rest-patch (As of now only klish is supported).
    :param skip_error: True/False.
    :param skip_template: True/False.
    :return:

    Usage:
    consistency-check route start [vrf Vrf1] [ ipv4|ipv6 ] [threshold 30] [auto-rectify]
    config_consistency_check(dut, config='yes', family='ipv6')
    config_consistency_check(dut, config='yes', vrf='Vrf1', threshold='50')
    config_consistency_check(dut, config='no')
    '''
    ### Optional parameters processing
    config = kwargs.get('config', 'yes')
    vrf = kwargs.get('vrf', "")
    family = kwargs.get('family', "")
    threshold = kwargs.get('threshold', "")
    rectify = kwargs.get('rectify', "")
    feature = kwargs.get('feature', "route")
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', True)
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    # CLI not supported in click and Rest.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "click"] else "klish"
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    vrf = 'vrf '+vrf if vrf != "" else ""
    rectify = 'auto-rectify' if rectify != "" else ""
    threshold = 'threshold '+threshold if threshold != "" else ""
    output = False
    if cli_type == 'klish':
        config = 'start' if config == "yes" else "stop"
        cmd = "consistency-check {} {} {} {} {}".format(config, feature, vrf, family, rectify)
        output = st.show(dut, cmd, type=cli_type, skip_error_check=skip_error, skip_tmpl=skip_template)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        if "Error" in output:
            st.error("Error seen while configuring.")
            return False
    return output

def create_inconsistency_appdb(dut, prefix_list, **kwargs):
    '''
    This is redis command to create route inconsistency in appDB.
    Author: sunil.rajendra@broadcom.com
    :param dut:
    :param config: yes/no. This corresponds to add/del. 'Modify' comes in 'add'.
    :param prefix_list: List of prefixes. Can be IPv4 or IPv6.
    :param mask_list: List of mask values. Default: 24.
    :param vrf_list: List of VRF names.
    :param nexthop_list: List of nexthop prefixes.
    :param ifname_list: List of egress interfaces.
    :param cli_type: CLI type - click/klish/rest-patch (As of now only click is supported).
    :param skip_error: True/False.
    :param skip_template: True/False.
    :return:

    Usage:
    consistency-check route start [vrf Vrf1] [ ipv4|ipv6 ] [threshold 30] [auto-rectify]
    create_inconsistency_appdb(dut, config='yes', prefix_list='2001::1', mask_list='64', nexthop_list='22')
    create_inconsistency_appdb(dut, config='no', prefix_list=['1.1.1.1','1.1.1.2'], mask_list='32', vrf_list='Vrf1')

    Add route to APP_DB create extra routes in H/W:

    redis-cli -n 0 -p 63792
    "SADD" "ROUTE_TABLE_KEY_SET" "88.0.0.2/32"
    "HSET" "_ROUTE_TABLE:88.0.0.2/32" "nexthop_group" "2"
    "HSET" "_ROUTE_TABLE:88.0.0.2/32" "vni_label" ""
    "HSET" "_ROUTE_TABLE:88.0.0.2/32" "route_mac" ""
    "HSET" "_ROUTE_TABLE:88.0.0.2/32" "group" ""
    "PUBLISH" "ROUTE_TABLE_CHANNEL" "G"

    Modify out-interface and nexthop-ip in APP_DB to change nexthop in H/W:
    redis-cli -n 0 -p 63792
    "SADD" "ROUTE_TABLE_KEY_SET" "1113::/64 "
    "HSET" "_ROUTE_TABLE:1113::/64 " "nexthop" "11::1"
    "HSET" "_ROUTE_TABLE:1113::/64 " "ifname" "Ethernet65"
    "PUBLISH" "ROUTE_TABLE_CHANNEL" "G"

    Remove route from APP_DB to delete routes in H/W:
    redis-cli -n 0 -p 63792
    "SADD" "ROUTE_TABLE_KEY_SET" "81.0.0.1/32"
    "SADD" "ROUTE_TABLE_DEL_SET" "81.0.0.1/32"
    "DEL" "_ROUTE_TABLE:81.0.0.1/32"
    "PUBLISH" "ROUTE_TABLE_CHANNEL" "G"
    '''
    ### Optional parameters processing
    config = kwargs.get('config', 'yes')
    mask_list = kwargs.get('mask_list', "24")
    vrf_list = kwargs.get('vrf_list', "")
    nexthop_list = kwargs.get('nexthop_list', "")
    ifname_list = kwargs.get('ifname_list', "")
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', True)
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    # CLI supported only from click.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "klish"] else "click"
    cli_type = force_cli_type_to_click(cli_type=cli_type)

    # Making all variables to list if they are not.
    prefix_list = prefix_list if type(prefix_list) is list else [prefix_list]
    mask_list = mask_list if type(mask_list) is list else [mask_list]
    vrf_list = vrf_list if type(vrf_list) is list else [vrf_list]
    nexthop_list = nexthop_list if type(nexthop_list) is list else [nexthop_list]
    ifname_list = ifname_list if type(ifname_list) is list else [ifname_list]

    # Making all variables length to be equal to prefix_list.
    len_pl = len(prefix_list)
    mask_list = mask_list if len(mask_list) == len_pl else mask_list*len_pl
    vrf_list = vrf_list if len(vrf_list) == len_pl else vrf_list*len_pl
    nexthop_list = nexthop_list if len(nexthop_list) == len_pl else nexthop_list*len_pl
    ifname_list = ifname_list if len(ifname_list) == len_pl else ifname_list*len_pl

    output = False
    if cli_type == 'click':
        cmd_last = '"PUBLISH" "ROUTE_TABLE_CHANNEL" "G"'
        cmd_list = []
        if config == 'yes':
            for prefix, mask, vrf, nexthop in zip(prefix_list, mask_list, vrf_list, nexthop_list):
                vrf1 = vrf if vrf == "" else vrf+":"
                cmd1 = '"SADD" "ROUTE_TABLE_KEY_SET" "{}{}/{}"'.format(vrf1, prefix, mask)
                cmd2 = '"HSET" "_ROUTE_TABLE:{}{}/{}" "nexthop_group" "{}"'.format(vrf1, prefix, mask, nexthop)
                cmd3 = '"HSET" "_ROUTE_TABLE:{}{}/{}" "vni_label" ""'.format(vrf1, prefix, mask)
                cmd4 = '"HSET" "_ROUTE_TABLE:{}{}/{}" "route_mac" ""'.format(vrf1, prefix, mask)
                cmd5 = '"HSET" "_ROUTE_TABLE:{}{}/{}" "group" ""'.format(vrf1, prefix, mask)
                cmd_list.append(cmd1)
                cmd_list.append(cmd2)
                cmd_list.append(cmd3)
                cmd_list.append(cmd4)
                cmd_list.append(cmd5)
                cmd_list.append(cmd_last)
        elif config == 'no':
            for prefix, mask, vrf in zip(prefix_list, mask_list, vrf_list):
                vrf1 = vrf if vrf == "" else vrf+":"
                cmd1 = '"SADD" "ROUTE_TABLE_KEY_SET" "{}{}/{}"'.format(vrf1, prefix, mask)
                cmd2 = '"SADD" "ROUTE_TABLE_DEL_SET" "{}{}/{}"'.format(vrf1, prefix, mask)
                cmd3 = '"DEL" "_ROUTE_TABLE:{}{}/{}"'.format(vrf1, prefix, mask)
                cmd_list.append(cmd1)
                cmd_list.append(cmd2)
                cmd_list.append(cmd3)
                cmd_list.append(cmd_last)
        for cmd in cmd_list:
            output = st.show(dut, redis.build(dut, redis.APPL_DB, cmd), skip_error_check=skip_error, skip_tmpl=skip_template)
            if "Could not connect to Management REST Server" in output:
                st.error("click mode not working.")
                return False
            if "Error" in output:
                st.error("Error seen while configuring.")
                return False
    return True

def create_inconsistency_asicdb(dut, prefix_list, **kwargs):
    '''
    This is redis command to create route inconsistency in asicDB.
    Author: sunil.rajendra@broadcom.com
    :param dut:
    :param config: yes/no. This corresponds to add/del. 'Modify' comes in 'add'.
    :param prefix_list: List of prefixes in full key format. Can be IPv4 or IPv6. Refer to show_asicdb_route_key API.
    :param nexthop_list: List of nexthop values in case of add/modify. Not needed in 'delete'.
    :param cli_type: CLI type - click/klish/rest-patch (As of now only click is supported).
    :param skip_error: True/False.
    :param skip_template: True/False.
    :return:

    Usage:
    create_inconsistency_asicdb(dut, config='yes', prefix_list="SAI_OBJECT_TYPE_ROUTE_ENTRY:{\"dest\":\"1121:1:0:4d::/64\",\"switch_id\":\"oid:0x21000000000000\",\"vr\":\"oid:0x3000000000022\"}", nexthop_list="oid:0x40000000008e9")

    Add/Modify route to ASIC_DB:
    redis-cli -n 1 -p 63793
    "SADD" "ASIC_STATE_KEY_SET" "SAI_OBJECT_TYPE_ROUTE_ENTRY:{\"dest\":\"8.1.1.3/32\",\"switch_id\":\"oid:0x21000000000000\",\"vr\":\"oid:0x300000000003c\"}"
    "HSET" "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:{\"dest\":\"8.1.1.3/32\",\"switch_id\":\"oid:0x21000000000000\",\"vr\":\"oid:0x300000000003c\"}" "SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID" "oid:0x4000000000b3a"
    "PUBLISH" "ASIC_STATE_CHANNEL" "G"

    Remove route from ASIC_DB (to delete):
    redis-cli -n 1 -p 63793
    "SADD" "ASIC_STATE_KEY_SET" "SAI_OBJECT_TYPE_ROUTE_ENTRY:{\"dest\":\"8.0.0.1/32\",\"switch_id\":\"oid:0x21000000000000\",\"vr\":\"oid:0x300000000003c\"}"
    "SADD" "ASIC_STATE_DEL_SET" "SAI_OBJECT_TYPE_ROUTE_ENTRY:{\"dest\":\"8.0.0.1/32\",\"switch_id\":\"oid:0x21000000000000\",\"vr\":\"oid:0x300000000003c\"}"
    "DEL" "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:{\"dest\":\"8.0.0.1/32\",\"switch_id\":\"oid:0x21000000000000\",\"vr\":\"oid:0x300000000003c\"}"
    "PUBLISH" "ASIC_STATE_CHANNEL" "G"
    '''
    ### Optional parameters processing
    config = kwargs.get('config', 'yes')
    nexthop_list = kwargs.get('nexthop_list', "")
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', True)
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    # CLI supported only from click.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "klish"] else "click"
    cli_type = force_cli_type_to_click(cli_type=cli_type)

    # Making all variables to list if they are not.
    prefix_list = prefix_list if type(prefix_list) is list else [prefix_list]
    nexthop_list = nexthop_list if type(nexthop_list) is list else [nexthop_list]

    # Making all variables length to be equal to prefix_list.
    len_pl = len(prefix_list)
    nexthop_list = nexthop_list if len(nexthop_list) == len_pl else nexthop_list*len_pl

    output = False
    if cli_type == 'click':
        cmd_last = '"PUBLISH" "ASIC_STATE_CHANNEL" "G"'
        cmd_list = []
        if config == 'yes':
            for prefix, nexthop in zip(prefix_list, nexthop_list):
                cmd1 = '"SADD" "ASIC_STATE_KEY_SET" "{}"'.format(prefix)
                cmd2 = '"HSET" "ASIC_STATE:{}" "SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID" "{}"'.format(prefix, nexthop)
                cmd_list = [cmd1, cmd2, cmd_last]
        elif config == 'no':
            for prefix in prefix_list:
                cmd1 = '"SADD" "ASIC_STATE_KEY_SET" "{}"'.format(prefix)
                cmd2 = '"SADD" "ASIC_STATE_DEL_SET" "{}"'.format(prefix)
                cmd3 = '"DEL" "ASIC_STATE:{}"'.format(prefix)
                cmd_list = [cmd1, cmd2, cmd3, cmd_last]
        # Infra bug in this. So hardcoding the value of 'p'.
        cmd_redis = "redis-cli -p 63793 -n 1"
        for cmd in cmd_list:
            output = st.show(dut, '{} {}'.format(cmd_redis, cmd), skip_error_check=skip_error, skip_tmpl=skip_template)
            if "Could not connect to Management REST Server" in output:
                st.error("click mode not working.")
                return False
            if "Error" in output:
                st.error("Error seen while configuring.")
                return False
    return True

def show_hget_key_field(dut, **kwargs):
    """
    show consistency-check status
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :param :skip_template:
    :param :prefix - default 'ROUTE_TABLE'. Give "" for other prefixes.
    :param :key - value of the key.
    :param :field - field value.
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    # CLI not supported in click and Rest. Supported only in klish.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "click"] else "klish"
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', False)
    prefix = kwargs.get('prefix', "ROUTE_TABLE")
    key = kwargs.get('key', "")
    field = kwargs.get('field', "nexthop_group")

    output = False
    if prefix == "ROUTE_TABLE":
        key = "\"{}:{}\"".format(prefix, key)
    field = "\"{}\"".format(field)
    cmd = "hget {} {}".format(key, field)
    output = st.show(dut, redis.build(dut, redis.APPL_DB, cmd), skip_error_check=skip_error, skip_tmpl=skip_template)
    if "Could not connect to Management REST Server" in output:
        st.error("click mode not working.")
        return False
    if "Error" in output:
        st.error("Error seen while configuring.")
        return False
    if kwargs.get('field') == "nexthop_group":
        return output[0]['result']
    return output

def show_asicdb_route_key(dut, **kwargs):
    """
    show consistency-check status
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :param :skip_template:
    :param :prefix - default '0.0.0.0'. or can give in 1.1.1.1/32 format too.
    :param :mask - Mask of prefix. Default: "24".
    :return:

    rcc_api.show_asicdb_route_key(dut1, prefix='131.11.255.0', mask='24')
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    # CLI not supported in click and Rest. Supported only in klish.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "click"] else "klish"
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', False)
    prefix = kwargs.get('prefix', "0.0.0.0")
    mask = kwargs.get('mask', "24")
    if '/' in prefix:
        prefix, mask = prefix.split('/')

    output = False
    key = "*ROUTE*{}/{}*".format(prefix, mask)
    # Infra bug in this. So hardcoding the value of 'p'.
    # cmd_redis = redis.build(dut, redis.APPL_DB, cmd)
    cmd_redis = "redis-cli -p 63793 -n 1"
    cmd = "{} keys {}".format(cmd_redis, key)
    output = st.show(dut, cmd, skip_error_check=skip_error, skip_tmpl=skip_template)
    if "Could not connect to Management REST Server" in output:
        st.error("click mode not working.")
        return False
    if "Error" in output:
        st.error("Error seen while configuring.")
        return False
    route_key = output[0]['name'][11:]
    return route_key

def show_asicdb_nexthop(dut, prefix, **kwargs):
    """
    show consistency-check status
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :param :skip_template:
    :param :prefix - In full key format. Refer to show_asicdb_route_key() API.
    :return:

    rcc_api.show_asicdb_nexthop(dut1, prefix='SAI_OBJECT_TYPE_ROUTE_ENTRY:{\"dest\":\"131.11.255.0/24\",\"switch_id\":\"oid:0x21000000000000\",\"vr\":\"oid:0x30000000008a8\"}')
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    # CLI not supported in click and Rest. Supported only in klish.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "click"] else "klish"
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', False)

    output = False
    key = 'hget "ASIC_STATE:{}" "SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID"'.format(prefix)
    cmd_redis = "redis-cli -p 63793 -n 1"
    cmd = "{} {}".format(cmd_redis, key)
    output = st.show(dut, cmd, skip_error_check=skip_error, skip_tmpl=skip_template)
    if "Could not connect to Management REST Server" in output:
        st.error("click mode not working.")
        return False
    if "Error" in output:
        st.error("Error seen while configuring.")
        return False
    return output[0]['result']

def show_consistency_check_status(dut, **kwargs):
    """
    show consistency-check status
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :param :skip_template:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    # CLI not supported in click and Rest. Supported only in klish.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "click"] else "klish"
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', False)

    if cli_type == 'click':
        st.error("CLI not supported in CLICK. Supported only in KLISH.")
        return False
    elif cli_type == 'klish':
        command = "show consistency-check status"
    elif cli_type in ['rest-put','rest-patch']:
        st.error("CLI not supported in rest-put/rest-patch. Supported only in KLISH.")
        return False
    else:
        st.error("Supported modes are only KLISH.")
        return False
    return st.show(dut, command, type=cli_type, skip_error_check=skip_error, skip_tmpl=skip_template)

def verify_consistency_check_status(dut, **kwargs):
    """
    Verify the output of 'show consistency-check status'.
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :feature_list: List of features.
    :param :status_list: List of statuses of each feature.
    :param :cli_type:
    :param :skip_error:
    :param :skip_template:
    :return:
    """
    feat_list = kwargs.get('feature_list', None)
    st_list = kwargs.get('status_list', None)
    feat_list = feat_list if type(feat_list) is list else [feat_list]
    st_list = st_list if type(st_list) is list else [st_list]
    output = show_consistency_check_status(dut, **kwargs)
    st.log("output={}, kwargs={}".format(output,kwargs))
    if "Could not connect to Management REST Server" in output:
        st.error("klish mode not working.")
        return False
    if "Error" in output:
        st.error("Error seen in the output.")
        return False
    for feat, status in zip(feat_list, st_list):
        entries = utils.filter_and_select(output, None, {'feature':feat, 'status':status})
        if not entries:
            st.error("{} and {} did not match.".format(feat, status))
            return False
        else:
            st.log("{} and {} Found.".format(feat, status))
    return True

def show_consistency_check_status_route(dut, **kwargs):
    """
    show consistency-check status
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :param :skip_template:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    # CLI not supported in click and Rest.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "click"] else "klish"
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', False)
    vrf = kwargs.get('vrf', "")

    if cli_type == 'click':
        st.error("CLI not supported in CLICK. Supported only in KLISH.")
        return False
    elif cli_type == 'klish':
        vrf = 'vrf '+vrf if vrf != "" else ""
        command = "show consistency-check status route {}".format(vrf)
    elif cli_type in ['rest-put','rest-patch']:
        st.error("CLI not supported in rest-put/rest-patch. Supported only in KLISH.")
        return False
    else:
        st.error("Supported modes are only KLISH.")
        return False
    return st.show(dut, command, type=cli_type, skip_error_check=skip_error, skip_tmpl=skip_template)

def verify_consistency_check_status_route(dut, **kwargs):
    """
    Verify the output of 'show consistency-check status route'.
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :return_output = True/False (default: False): returns the output.
    :param :verify_list: List of dictionaries to be verified with the output.
    :param :cli_type:
    :param :skip_error:
    :param :skip_template:
    :return:

    : layer = (appdb|asicdb|fib|sai)
    : layer_type = (rib | <layer> | Unequal)
    Example:
    line1 = {'result': 'Inconsistent'}
    line2 = {'vrf': 'default', 'addr_family': 'ipv4', 'result_appdb': 'Inconsistent', 'layer': 'appdb', 'layer_type': 'appdb', 'prefix': '8.0.0.1', 'mask': '32'}
    line3 = {'vrf': 'default', 'addr_family': 'ipv4', 'result_asicdb': 'Inconsistent', 'layer': 'asicdb', 'layer_type': 'Unequal', 'prefix': '8.1.1.2', 'mask': '32', 'prefix_text': 'NHop(s) do not match', 'uneq_ribnum': '1', 'uneq_ip': '65.0.0.2', 'uneq_intf': 'Ethernet65', 'uneq_mac': '80:a2:35:26:45:61'}
    line4 = {'vrf': 'default', 'addr_family': 'ipv6', 'result_appdb': 'Consistent', 'result_asicdb': 'Consistent', 'result_fib': 'Consistent', 'result_sai': 'Consistent'}
    result = rcc_api.verify_consistency_check_status_route(dut, verify_list=[line1, line2, line3, line4])
    """
    ret_flag = True
    return_output = kwargs.pop('return_output', False)
    verify_list = kwargs.pop('verify_list', [])
    output = show_consistency_check_status_route(dut, **kwargs)
    st.log("output={}, kwargs={}".format(output,kwargs))
    if return_output:
        return output
    for in_dict in verify_list:
        entries = utils.filter_and_select(output, None, in_dict)
        if not entries:
            st.error("{} did not match.".format(in_dict))
            ret_flag = False
        else:
            st.log("{} is Found.".format(in_dict))
    return ret_flag
