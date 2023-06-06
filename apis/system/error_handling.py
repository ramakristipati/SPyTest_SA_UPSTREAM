# This file contains the list of API's which performs Error handling operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import re
from spytest import st
from utilities.common import filter_and_select
import apis.common.asic as asicapi
from apis.common import redis
#from apis.system.interface import verify_ifname_type
from utilities.utils import get_supported_ui_type_list, convert_intf_name_to_component
try:
    import apis.yang.codegen.messages.system as umf_system
except ImportError:
    pass


def verify_error_db(dut, table, **kwargs):
    """
    Verify error db using redis cli
    :param dut:
    :param table:
    :param kwargs:
    :return:
    """
    match = ""
    if table == "ERROR_ROUTE_TABLE":
        vrfKey = ""
        if 'vrf' in kwargs:
            vrfKey = kwargs["vrf"] + ":"
        command = redis.build(dut, redis.ERROR_DB, "hgetall {}:{}{}/{}".format(table, vrfKey, kwargs["route"], kwargs["mask"]))
        if kwargs["opcode"] == "create":
            match = {"nhp": kwargs["nhp"], "rc": kwargs["rc"], "ifname": kwargs["port"], "opcode": kwargs["opcode"]}
        elif kwargs["opcode"] == "remove":
            match = {"rc": kwargs["rc"], "opcode": kwargs["opcode"]}
        elif "rc" not in kwargs and "opcode" not in kwargs:
            match = {"genid": kwargs["genid"]}

    elif table == "ERROR_NEIGH_TABLE":
        st.log("table")
        command = redis.build(dut, redis.ERROR_DB, "hgetall {}:{}:{}".format(table, kwargs["port"], kwargs["nhp"]))
        if kwargs["opcode"] == "create":
            match = {"mac": kwargs["mac"], "rc": kwargs["rc"], "ifname": kwargs["port"], "opcode": kwargs["opcode"]}
        elif kwargs["opcode"] == "remove":
            match = {"rc": kwargs["rc"], "opcode": kwargs["opcode"]}
        elif "rc" not in kwargs and "opcode" not in kwargs:
            match = {"ifname": kwargs["port"], "mac": kwargs["mac"]}
    output = st.show(dut, command)
    st.debug(output)
    if 0 == len(output) or 'nhg' not in output[0]:
        st.error("output len {} is empty or nexthop_group not found in ERROR_ROUTE_TABLE ".format(len(output)))
        return False
    nhg = output[0]['nhg']
    command = redis.build(dut, redis.APPL_DB, "hgetall {}:{}".format("NEXT_HOP_GROUP_TABLE", nhg))
    # Since the nexthop ip address and interfacename has changed to nexthop group, skip changing interface name
    # as interface name does not exist in the route table entry now
    #output = _get_entries_with_native_port(dut, output, **kwargs)
    output1 = st.show(dut, command)
    st.debug(output1)
    if 0 == len(output1) or 'nhp' not in output1[0] or 'ifname' not in output1[0]:
        st.error("output1 len {} is empty or nexthop ip address or ifname not found in NEXT_HOP_GROUP_TABLE ".format(len(output1)))
        return False
    output[0]['nhp'] = output1[0]['nhp']
    output[0]['interface'] = output1[0]['ifname']
    output = _get_entries_with_native_port(dut, output, **kwargs)
    st.debug(output)
    st.debug(match)
    output[0]['ifname'] = output[0]['interface']
    if not filter_and_select(output, None, match):
        st.error("No match found")
        return False
    return True


def verify_show_error_db(dut, table=None, **kwargs):
    """
    Verify Error Database.
    :param dut:
    :param table:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list()+['rest-patch','rest-put'] else cli_type
    return_output = kwargs.pop('return_output', False)
    if cli_type == 'click':
        command = "show error_database"
        if table:
            command = "show error_database {}".format(table)
    if cli_type == 'klish':
        command = "show error-database"
        if not table: table = "ALL"
        command = "show error-database {}".format(table)
    if 'error' in kwargs:
        command += " | grep {}".format(kwargs.pop('error'))

    output = st.show(dut, command, type=cli_type)
    output = _get_entries_with_native_port(dut, output, **kwargs)
    st.debug(output)
    if return_output:
        return output
    for each in kwargs.keys():
        if not filter_and_select(output, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            return False
    return True


def verify_show_error_db_multi(dut, table, *argv, **kwargs):
    """
    Verify multiple Error Database entries.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param : dut:
    :param : table:
    :param : result: Expected result(Default True)
    :param : iteration: default(30)
    :param : argv: list  of dict arguments to verify
    :return:
    """
    exp_result = kwargs.get("result", True)
    iteration = kwargs.get("iteration", 30)
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list()+['rest-patch','rest-put'] else cli_type
    kwargs['return_output'] = True
    i = 1
    while True:
        output = verify_show_error_db(dut, table=table, **kwargs)
    #    output = _get_entries_with_native_port(dut, output, **kwargs)
        st.debug(output)
        result = True
        for each_row in argv:
            row_match = filter_and_select(output, None, each_row)
            if not row_match:
                st.log("Entry not found - {}".format(', '.join(["{}='{}'".format(k, each_row[k]) for k in each_row])))
                result = False
            else:
                st.log("Entry found - {}".format(', '.join(["{}='{}'".format(k, each_row[k]) for k in each_row])))
        if result == exp_result:
            return True
        if i >= iteration:
            return False
        i += 1
        st.wait(1)


def get_num_entries_error_db(dut, ifname_type=None):
    """
    To Get total entries in Error Database using redis cli
    :param dut:
    :return:
    """
    command = redis.build(dut, redis.ERROR_DB, "keys ERROR.*")
    output = st.show(dut, command)
    output = _get_entries_with_native_port(dut, output, ifname_type=ifname_type)
    st.debug(output)
    return len(output)


def get_num_entries_show_error_db(dut, table=None, error=None, ifname_type=None, **kwargs):
    """
    To Get total entries in Error Database using show command
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param table:
    :param error:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list()+['rest-patch','rest-put'] else cli_type
    st.banner("cli_type : {}".format(cli_type))
    kwargs['return_output'] = True
    kwargs['error'] = error
    output = verify_show_error_db(dut, table=table, **kwargs)
    return len(output)


def get_num_entries_show_error_db_simple(dut, table=None, error=None):
    """
    To Get total entries in Error Database using show command using wc -l
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param table:
    :param error:
    :return:
    """
    command = "show error_database"
    if table:
        command += " {}".format(table)
    if error:
        if isinstance(error, list):
            error = '"' + r'\|'.join(error) + '"'
        command += " | grep {}".format(error)
    command += " | wc -l"
    output = st.config(dut, command, max_time=1200)
    x = re.search(r"\d+", output)
    return int(x.group())


def clear_error_db(dut, table=None, **kwargs):
    """
    Clear Error database
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param table:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list()+['rest-patch','rest-put'] else cli_type
    if cli_type == 'click':
        command = "sonic-clear error_database"
        if table:
            command = "sonic-clear error_database {}".format(table)
        st.config(dut, command)
    if cli_type == 'klish':
        if not table: table = 'ALL'
        command = 'clear error-database {}'.format(table)
        st.config(dut, command, type=cli_type, conf=False)
    return True


def config_bgp_error_handling(dut, **kwargs):
    """
    To Configure BGP error handling.
    :param : dut:
    :param : action: enable|disable
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if "action" not in kwargs:
        st.error("Mandatory param 'action' not provided")
        return False
    if cli_type in get_supported_ui_type_list():
        system_obj = umf_system.System()
        if kwargs["action"] == "enable":
            system_obj.SuppressFibPending = "ENABLED"
        else:
            system_obj.SuppressFibPending = "DISABLED"
        result = system_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: {} of suppress fib pending'.format(kwargs["action"]))
            return False
        else:
            return True
    elif cli_type == 'klish':
        if kwargs["action"] == "enable":
            command = "suppress-fib-pending"
        else:
            command = "no suppress-fib-pending"
    elif cli_type == "click":
        st.log('command not supported in click mode')
        return False
    st.config(dut, command, type=cli_type)
    return True

def config_global_error_handling(dut, **kwargs):
    """
    To Configure Global error handling.
    :param : dut:
    :param : action: enable|disable
    :return:
    """

    "NOTE: KLISH support for this command is not yet present, so enforcing click cli mode"
    cli_type = 'click'
    if "action" not in kwargs:
        st.error("Mandatory param 'action' not provided")
        return False

    if kwargs["action"] == "enable":
        command = "config error-handling enable"
    else:
        command = "config error-handling disable"

    st.config(dut, command, type=cli_type)
    return True

def verify_error_db_redis(dut, table, **kwargs):
    """
    Verify error db using redis cli
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :table:
    :param :route:
    :param :mask:
    :param :ifname:
    :param :nhp:
    :param :operation:
    :param :rc:
    :param :result: (Default True)
    :param :iteration: default(30)
    :return:
    """
    port = kwargs.pop("ifname")
    #port = st.get_other_names(dut, [port])[0] if "/" in port else port
    port = convert_intf_name_to_component(dut, intf_list=port, component='applications')
    exp_result = kwargs.get("result", True)
    iteration = kwargs.get("iteration", 30)
    command = ''
    if table == "ERROR_ROUTE_TABLE":
        command = redis.build(dut, redis.ERROR_DB, "hgetall {}:{}/{}".format(table, kwargs.pop("route"), kwargs.pop("mask")))
    elif table == "ERROR_NEIGH_TABLE":
        command = redis.build(dut, redis.ERROR_DB, "hgetall {}:{}:{}".format(table, port, kwargs.pop("nhp")))
    else:
        st.error("Invalid table name - {}".format(table))

    i = 1

    while True:
        output = st.show(dut, command)
        if "nhp" in kwargs and table == "ERROR_ROUTE_TABLE":
            nhg = output[0]['nhg']
            command = redis.build(dut, redis.APPL_DB, "hgetall {}:{}".format("NEXT_HOP_GROUP_TABLE", nhg))
            output1 = st.show(dut, command)
            st.debug(output1)
            output[0]['nhp'] = output1[0]['nhp']
        st.debug(output)
        result = True
        for each in kwargs.keys():
            if not filter_and_select(output, None, {each: kwargs[each]}):
                st.error("No match for {} = {} in redis cli".format(each, kwargs[each]))
                result = False
        if result == exp_result:
            return True
        if i >= iteration:
            return False
        i += 1
        st.wait(1)


def verify_route_count_bcmshell(dut, route_count, af='ipv4', itter=30, delay=1, flag='ge', timeout=120):
    """
    Poll and verify the route count using asic api
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param route_count:
    :param af:
    :param itter:
    :param delay:
    :param flag:
    :param timeout:
    :return:
    """
    i = 1
    while True:
        if af == 'ipv4':
            curr_count = asicapi.get_ipv4_route_count(dut, timeout=timeout)
        if af == 'ipv6':
            curr_count = asicapi.get_ipv6_route_count(dut, timeout=timeout)

        if flag == 'ge' and int(curr_count) >= int(route_count):
            st.log("Route count matched Provided {}, Detected {} - flag = {}".format(route_count, curr_count, flag))
            return True
        if flag == 'e' and int(curr_count) == int(route_count):
            st.log("Route count matched Provided {}, Detected {} - flag = {}".format(route_count, curr_count, flag))
            return True
        if flag == 'le' and int(curr_count) <= int(route_count):
            st.log("Route count matched Provided {}, Detected {} - flag = {}".format(route_count, curr_count, flag))
            return True
        if i > itter:
            st.log("Max {} tries Exceeded. Exiting..".format(i))
            return False
        i += 1
        st.log("Route count NOT matched Provided {}, Detected {} - flag = {}".format(route_count, curr_count, flag))
        st.wait(delay)


def check_for_container_error(out):
    """
    Error handing - Check and failed the test case if container error detected.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param out:
    :return:
    """
    if "Error response from daemon" in out:
        st.report_fail('container_not_running')


def eh_not_installed_route_options(dut, **kwargs):
    """
    Error handing - Not installed route Show / Get / Clear API.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    if 'mode' not in kwargs:
        st.error("Mandatory parameter mode not found")

    af1 = 'ipv6'
    af2 = 'ipv6'
    if 'ipv4' in kwargs['mode']:
        af1 = 'ipv4'
        af2 = 'ip'

    if kwargs['mode'] == "clear_{}_route_vtysh_not_installed".format(af1):
        out = st.config(dut, 'clear {} route not-installed '.format(af2), type='vtysh', conf=False)
        return out
    if kwargs['mode'] == "clear_{}_route_sonic_not_installed".format(af1):
        out = st.config(dut, 'sonic-clear {} route not-installed '.format(af2))
        return out

    # Sonic - MODE
    if "{}_route_sonic_not_installed".format(af1) in kwargs['mode']:
        command = 'show {} route not-installed | grep .'.format(af2)
        if 'show' in kwargs['mode']:
            out = st.show(dut, command)
            out = _get_entries_with_native_port(dut, out, **kwargs)
            st.debug(out)
            return out
        else:
            out = st.config(dut, command + ' | wc -l', skip_error_check=True)
            check_for_container_error(out)
            count = re.search(r"\d+", out).group()
            st.log("Detected route count {}".format(count))
            return int(count)

    if "{}_route_sonic_for_not_installed".format(af1) in kwargs['mode']:
        command = 'show {} route | grep "> r" '.format(af2)
        if 'show' in kwargs['mode']:
            out = st.show(dut, command)
            out = _get_entries_with_native_port(dut, out, **kwargs)
            st.debug(out)
            return out
        else:
            out = st.config(dut, command + ' | wc -l', skip_error_check=True)
            check_for_container_error(out)
            count = re.search(r"\d+", out).group()
            st.log("Detected route count {}".format(count))
            return int(count)

    # vtysh = MODE
    if "{}_route_vtysh_not_installed".format(af1) in kwargs['mode']:
        out = st.show(dut, 'show {} route not-installed'.format(af2), type='vtysh')
        out = _get_entries_with_native_port(dut, out, **kwargs)
        st.debug(out)
        if 'show' in kwargs['mode']:
            return out
        else:
            st.log("Detected route count {}".format(len(out)))
            return len(out)

    if "{}_route_vtysh_for_not_installed".format(af1) in kwargs['mode']:
        out = st.show(dut, 'show {} route | grep "#"'.format(af2), type='vtysh')
        out = _get_entries_with_native_port(dut, out, **kwargs)
        st.debug(out)
        if 'show' in kwargs['mode']:
            return out
        else:
            st.log("Detected route count {}".format(len(out)))
            return len(out)


def verify_num_entries_show_error_db(dut, entry_count, itter=30, delay=1, flag='ge', table=None, error=None):
    """
    Poll and verify the show error db entries
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param entry_count:
    :param itter:
    :param delay:
    :param flag:
    :param table:
    :param error:
    :return:
    """

    i = 1
    while True:
        curr_count = get_num_entries_show_error_db_simple(dut, table=table, error=error)
        if flag == 'ge' and int(curr_count) >= int(entry_count):
            st.log("Entry count matched Provided {}, Detected {} - flag = {}".format(entry_count, curr_count, flag))
            return True
        if flag == 'e' and int(curr_count) == int(entry_count):
            st.log("Entry count matched Provided {}, Detected {} - flag = {}".format(entry_count, curr_count, flag))
            return True
        if flag == 'le' and int(curr_count) <= int(entry_count):
            st.log("Entry count matched Provided {}, Detected {} - flag = {}".format(entry_count, curr_count, flag))
            return True
        if i > itter:
            st.log("Max {} tries Exceeded. Exiting..".format(i))
            return False
        i += 1
        st.log("Route count NOT matched Provided {}, Detected {} - flag = {}".format(entry_count, curr_count, flag))
        st.wait(delay)


def eh_bcm_debug_show(dut, af='both', table_type='all', ifname_type=None):
    """
    Error handling debug API
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param af:
    :param table_type:
    :return:
    """
    st.banner("Error handling DEBUG Calls - START")
    if af == 'ipv4' or af == 'both':
        if table_type == 'route' or table_type == 'all':
            asicapi.dump_l3_defip(dut)
        if table_type == 'nbr' or table_type == 'all':
            asicapi.dump_l3_l3table(dut)
    if af == 'ipv6' or af == 'both':
        if table_type == 'route' or table_type == 'all':
            asicapi.dump_l3_ip6route(dut)
        if table_type == 'nbr' or table_type == 'all':
            asicapi.dump_l3_ip6host(dut)
    if table_type == 'all':
        verify_show_error_db(dut, ifname_type=ifname_type)
    st.banner("Error handling DEBUG Calls - END")


def _get_entries_with_native_port(dut, output, **kwargs):
#    cli_type = st.get_ui_type(dut, **kwargs)
#    ifname_type = kwargs.get("ifname_type", "")
#    verify_ifname_type(dut, mode='standard')
#    st.log("OUTPUT:{}".format(output))
    for entry in output:
        entry.update(interface=convert_intf_name_to_component(dut, intf_list=entry['interface'],component='applications'))
        #entry.update(interface=st.get_other_names(dut, [entry['interface']])[0] if (cli_type == 'klish' and ifname_type == "alias") else entry.get('interface'))
    st.log("OUTPUT1:{}".format(output))
    return output


def get_egress_intf(dut):
    """
    Get egress intf from - asic command 'l3 egress show'
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    out = asicapi.bcm_show(dut, "bcmcmd 'l3 egress show'")
    rv = re.findall(r"(\d+)\s+\w+:\w+:", out)
    st.debug(rv)
    if rv:
        return rv[0]
