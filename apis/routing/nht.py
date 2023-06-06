#   Nexthop Tracking APIs
#   Author: Naveena Suvarna (naveen.suvarna@broadcom.com)

from spytest import st
from utilities.common import filter_and_select
from apis.system.rest import config_rest, delete_rest
from apis.routing.ospf import validate_config_result
from utilities.utils import get_supported_ui_type_list

try:
    import apis.yang.codegen.messages.network_instance as umf_ni
    from apis.yang.utils.common import Operation
except ImportError:
    pass

def get_nht_cli_type(dut, **kwargs):
    st_cli_type = st.get_ui_type(dut, **kwargs)
    if st_cli_type == 'klish' or st_cli_type == '':
       return 'klish'
    elif st_cli_type == 'click' or st_cli_type == 'vtysh' :
       return 'vtysh'
    elif st_cli_type in ["rest-patch", "rest-put"]+get_supported_ui_type_list():
        return st_cli_type
    else:
        st.error("Invalid UI type {}".format(st_cli_type))
        return 'Invalid'

def show_nht_running_config(dut_list, cli_type=''):
    if not isinstance(dut_list, list):
        dut_list = [dut_list]

    for dut in dut_list :
        cli_type = get_nht_cli_type(dut, cli_type=cli_type)
        cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
        if cli_type == 'klish' :
            st.show(dut,"show running-configuration | grep nht ", type='klish')
            config_entries = st.show(dut,"show running-config zebra", type='vtysh')
            st.log("NHT - {} {} => Running config is {}".format(dut, cli_type, config_entries))
            st.log("")
        else :
            config_entries = st.show(dut,"show running-config zebra", type='vtysh')
            st.log("NHT - {} {} => Running config is {}".format(dut, cli_type, config_entries))
            st.log("")
    return True, 'Success'

def config_nht_resolve_via_default(dut, addr_families=['ipv4'], vrf='default', use_vrfname='no', config='yes', cli_type='', **kwargs):

    cli_type = get_nht_cli_type(dut, cli_type=cli_type)
    skip_error = kwargs.get('skip_error', False)

    if not isinstance(addr_families, list):
        addr_families = [addr_families]

    cli_type = get_nht_cli_type(dut, cli_type=cli_type)
    cmd_pfx = '' if config == 'yes' else 'no '
    vrf = 'default' if vrf == '' else vrf

    command = []
    rest_ret_flag=[]
    for afamily in addr_families :
        family_str = ''
        if afamily == 'ipv4' :
            family_str = 'ip'
        elif afamily == 'ipv6' :
            family_str = 'ipv6'
        else :
            st.error("Invalid Address family: {} provided".format(afamily))
            return False

        if cli_type in get_supported_ui_type_list():
            ret_flag = True
            family_str = afamily.upper()
            ni_obj = umf_ni.NetworkInstance(Name=vrf)
            af_obj = umf_ni.AddressFamily(Family=family_str, ResolveViaDefault=True, NetworkInstance=ni_obj)
            if config == 'yes':
                operation = Operation.CREATE
                result = af_obj.configure(dut, operation=operation, cli_type=cli_type)
            else:
                result = af_obj.unConfigure(dut, cli_type=cli_type)

            if not result.ok():
                st.log('test_step_failed: Config NHT {}'.format(result.data))
                ret_flag = False
            
            rest_ret_flag.append(ret_flag)
    
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = "{}{}".format(cmd_pfx, family_str)

            if vrf != 'default' or use_vrfname == 'yes' :
                cmd_str += " vrf {}".format(vrf)

            cmd_str += " nht resolve-via-default"
            command.append(cmd_str)

        elif cli_type in ["rest-patch", "rest-put"]:
            rest_urls = st.get_datastore(dut, 'rest_urls')
            ret_flag = True
            family_str = afamily.upper()
            if config == 'yes':
                rest_url = rest_urls['nht_config_base'].format(vrf)
                payload = {"openconfig-nexthop-tracking-ext:address-family":[{"family":family_str, "config":{"family":family_str,"resolve-via-default":True}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload):
                    ret_flag = False
            else:
                rest_url = rest_urls['nht_delete_base'].format(vrf,family_str)
                if not delete_rest(dut, rest_url=rest_url):
                    ret_flag = False
            rest_ret_flag.append(ret_flag)
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in get_supported_ui_type_list():
        return all(rest_ret_flag)
    elif cli_type in ['vtysh', 'klish']:
        if len(command) == 0 :
            st.error("No commands executed for dut: {} vrf: {} afmly: {}".format(dut, vrf, addr_families))
            return False

        result = st.config(dut, command, type=cli_type, conf=True, skip_error_check=skip_error)
        if skip_error is False:
            return validate_config_result(command, result, "")
        else:
            if "Could not connect to Management REST Server" in result:
                st.error("klish mode not working.")
                return False
            if "Error" in result:
                st.error("Error seen while configuring.")
                return False
    elif cli_type in ["rest-patch", "rest-put"]:
        return all(rest_ret_flag)
    else:
        return False

def verify_nht_config(dut, vrf='', match=None, cli_type=''):

    result = False
    st.log("NHT - Verify nht config on {} {} matching {}.".format(dut, vrf, match))

    input_cli_type = cli_type
    cli_type = get_nht_cli_type(dut, cli_type=cli_type)
    if cli_type in ["rest-patch", "rest-put"]: cli_type = 'klish'

    match_list = [ {} ] if match is None else match
    if not isinstance(match_list, list):
        match_list = [match]

    #force vtysh for now
    input_cli_type = 'vtysh'

    cli_type_map = {}
    if input_cli_type == 'klish' :
        cli_type_map.update( {'klish' : False} )
    elif input_cli_type == 'vtysh' :
        cli_type_map.update( { 'vtysh': False} )
    else :
        cli_type_map = { 'vtysh': False}
        if cli_type == 'klish' :
            cli_type_map.update( {'klish' : False} )

    for ctype in cli_type_map.keys() :
        if ctype == 'klish' :
            cmd_str = "show running-configuration ospf"
        else :
            cmd_str = "show running-config zebra"

        config_entries = st.show(dut, cmd_str, type=ctype)
        st.log("NHT - {} => {} Running config is {}".format(cmd_str, ctype, config_entries))
        st.log("")

        if not len(config_entries):
            st.log("NHT - Zero ospf config records for vrf {}".format(vrf))
            result = False
        else:
            vrf_str = vrf
            if vrf == 'default' : vrf_str = ''
            vrf_match = {u'vrf_name': vrf_str }
            st.log("NHT - match entries {} + {} in vrf entries".format(vrf_match, match))

            vrf_records = filter_and_select(config_entries, None, vrf_match)
            if not len(vrf_records):
                st.log("NHT - VRF record not found for vrf {}.".format(vrf))
                result = False
            else :
                match_count = 0
                for cfg_match in match_list :
                    if len(cfg_match) == 0 :
                        st.log("NHT - Empty input match consider record with vrf {} as matched".format(vrf))
                        match_count += 1
                        continue

                    #st.log("NHT - vrf {} cfg_match {} ".format(vrf, cfg_match))
                    #st.log("NHT - vrf records matching vrf {} are {}".format(vrf, vrf_records))
                    match_result = False
                    for vrf_record in vrf_records:
                        matched_record = filter_and_select([vrf_record], None, cfg_match)
                        match_result = True if len(matched_record) else False
                        if match_result :
                            match_count += 1
                            break

                    if match_result is False :
                        st.log("NHT - Vrf config didnot match {}".format(cfg_match))

                if match_count == len(match_list) :
                    result = True

        cli_type_map[ctype] = result
        if result is not True :
            break

    result_str = "Success" if result else "Failed"
    st.log("NHT - Vrf config validation {} check {}".format(match, result_str))
    return result

def verify_nht_unconfig(dut, vrf='', match=None, cli_type=''):
    result = verify_nht_config(dut, vrf=vrf, match=match, cli_type=cli_type)
    result = False if result else True
    result_str = "Success" if result else "Failed"
    st.log("NHT - Vrf Unconfig validation {} check {}".format(match, result_str))
    return result


