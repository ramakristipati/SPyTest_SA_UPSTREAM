
import re
from spytest import st, cutils
import apis.system.basic as basic_api

def build_cmd(cmd):
    if "bcmcmd" not in cmd:
        parts = cmd.split("|", 1)
        parts[0] = "bcmcmd '{}'".format(parts[0].strip())
        cmd = " |".join(parts)
    return cmd

def asic_show(dut, command, **kwargs):
    cmd = build_cmd(command)
    if st.is_feature_supported("bcmcmd", dut):
        return st.show(dut, cmd, **kwargs)
    st.debug("Show Command '{}' not executed".format(cmd))
    return ""

def asic_config(dut, command, **kwargs):
    cmd = build_cmd(command)
    if st.is_feature_supported("bcmcmd", dut):
        return st.config(dut, cmd, **kwargs)
    st.debug("Config Command '{}' not executed".format(cmd))
    return ""

def bcm_show(dut, cmd, skip_tmpl=True, max_time=0):
    return asic_show(dut, cmd, skip_tmpl=skip_tmpl, max_time=max_time)

def bcm_config(dut, cmd, skip_error_check=True):
    return asic_config(dut, cmd, skip_error_check=skip_error_check)

def dump_l3_intf(dut):
    bcm_show(dut, "bcmcmd 'l3 intf show'")

def dump_l3_egress(dut):
    bcm_show(dut, "bcmcmd 'l3 ecmp egress show'")

def dump_l3_alpm(dut):
    bcm_show(dut, 'bcmcmd "l3 alpm show brief"')

def dump_l2(dut):
    bcm_show(dut, 'bcmcmd "l2 show"')

def dump_vlan(dut):
    bcm_show(dut, 'bcmcmd "vlan show"')

def dump_multicast(dut):
    bcm_show(dut, 'bcmcmd "multicast show"')

def dump_ipmc_table(dut):
    bcm_show(dut, 'bcmcmd "ipmc table show"')

def dump_kernel_fdb(dut,vlan_id=None):
    if vlan_id is None:
        st.show(dut, 'sudo bridge fdb show', skip_tmpl=True)
    else:
        st.show(dut, 'sudo bridge fdb show vlan {}'.format(vlan_id), skip_tmpl=True)

def dump_ports_info(dut):
    bcm_config(dut, 'bcmcmd "d chg port"')

def dump_trunk(dut):
    bcm_config(dut, 'bcmcmd "trunk show"')

def dump_l3_defip(dut):
    if basic_api.is_td4_platform(dut) or basic_api.is_th4_platform(dut):
        bcm_show(dut, "bcmcmd 'l3 route show'")
    else:
        bcm_show(dut, "bcmcmd 'l3 defip show'")

def dump_l3_ip6route(dut):
    if basic_api.is_td4_platform(dut) or basic_api.is_th4_platform(dut):
        bcm_show(dut, "bcmcmd 'l3 route show v6=1'")
    else:
        bcm_show(dut, "bcmcmd 'l3 ip6route show'")

def dump_l3_l3table(dut):
    if basic_api.is_td4_platform(dut) or basic_api.is_th4_platform(dut):
        bcm_show(dut, "bcmcmd 'l3 host show'")
    else:
        bcm_show(dut, "bcmcmd 'l3 l3table show'")

def dump_l3_ip6host(dut):
    if basic_api.is_td4_platform(dut) or basic_api.is_th4_platform(dut):
        bcm_show(dut, "bcmcmd 'l3 host show v6=1'")
    else:
        bcm_show(dut, "bcmcmd 'l3 ip6host show'")

def dump_counters(dut, interface=None):
    if not interface:
        command = 'bcmcmd "show c"'
    else:
        command = 'bcmcmd "show c {}"'.format(interface)
    bcm_show(dut, command, skip_tmpl=True)

def clear_counters(dut):
    bcm_config(dut, 'bcmcmd "clear c"')

def get_counters(dut, interface=None, skip_tmpl=False):
    if not interface:
        command = 'bcmcmd "show c"'
    else:
        command = 'bcmcmd "show c {}"'.format(interface)
    return bcm_show(dut, command, skip_tmpl=skip_tmpl)


def get_ipv4_route_count(dut, timeout=120, **kwargs):
    grep_cmd = kwargs.get('grep_cmd', '')
    if basic_api.is_td4_platform(dut) or basic_api.is_th4_platform(dut):
        if grep_cmd:
            command = 'bcmcmd "l3 route show" | grep {} | wc -l'.format(str(grep_cmd))
        else:
            command = 'bcmcmd "l3 route show" | wc -l'
    else:
        if grep_cmd:
            command = 'bcmcmd "l3 defip show" | grep {} | wc -l'.format(str(grep_cmd))
        else:
            command = 'bcmcmd "l3 defip show" | wc -l'
    output = bcm_show(dut, command, max_time=timeout)
    x = re.search(r"\d+", output)
    if x:
        return int(x.group()) - 5
    else:
        return -1

def get_ipv6_route_count(dut, timeout=120, **kwargs):
    grep_cmd = kwargs.get('grep_cmd', '')
    if basic_api.is_td4_platform(dut) or basic_api.is_th4_platform(dut):
        if grep_cmd:
            command = 'bcmcmd "l3 route show v6=1" | grep {} | wc -l'.format(str(grep_cmd))
        else:
            command = 'bcmcmd "l3 route show v6=1" | wc -l'
    else:
        if grep_cmd:
            command = 'bcmcmd "l3 ip6route show" | grep {} | wc -l'.format(str(grep_cmd))
        else:
            command = 'bcmcmd "l3 ip6route show" | wc -l'
    output = bcm_show(dut, command, max_time=timeout)
    x = re.search(r"\d+", output)
    if x:
        return int(x.group()) - 7
    else:
        return -1


def get_pmap(dut):
    command = 'bcmcmd "show pmap"'
    return bcm_show(dut, command, skip_tmpl=False)

def exec_search(dut,command,param_list,match_dict,**kwargs):
    output = bcm_show(dut, 'bcmcmd "{}"'.format(command), skip_tmpl=False)
    if not output:
        st.error("output is empty")
        return False
    for key in match_dict.keys():
        if not cutils.filter_and_select(output,param_list,{key:match_dict[key]}):
            st.error("No match for key {} with value {}".format(key, match_dict[key]))
            return False
        else:
            st.log("Match found for key {} with value {}".format(key, match_dict[key]))
            return cutils.filter_and_select(output,param_list,{key:match_dict[key]})

def get_l2_out(dut, mac):
  return exec_search(dut,'l2 show',["gport"],{"mac":mac})

def get_l3_out(dut, mac):
  return exec_search(dut,'l3 egress show',["port"],{"mac":mac})

def dump_ecmp_info(dut):
    if basic_api.is_td4_platform(dut) or basic_api.is_th4_platform(dut):
        cmdlist = ["l3 ecmp show",
        "fd show",
        "l3 egress show"]
    else:
        cmdlist = ["l3 ecmp egress show",
        "g raw RTAG7_HASH_FIELD_BMAP_1",
        "g raw RTAG7_HASH_FIELD_BMAP_2",
        "g raw RTAG7_HASH_FIELD_BMAP_3",
        "g raw RTAG7_IPV4_TCP_UDP_HASH_FIELD_BMAP_1",
        "g raw RTAG7_IPV4_TCP_UDP_HASH_FIELD_BMAP_2",
        "g raw RTAG7_IPV6_TCP_UDP_HASH_FIELD_BMAP_1",
        "g raw RTAG7_IPV6_TCP_UDP_HASH_FIELD_BMAP_2",
        "g raw RTAG7_HASH_SEED_A",
        "g raw RTAG7_HASH_SEED_B",
        "d chg RTAG7_PORT_BASED_HASH",
        "g raw HASH_CONTROL",
        "l3 egress show"]
    for cmd in cmdlist:
        bcm_show(dut, 'bcmcmd "{}"'.format(cmd))

def dump_threshold_info(dut, test, platform, mode):
    """
    BCMCMD debug prints for Threshold feature.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param test:
    :param platform:
    :return:
    """
    if mode == "asic_portmap":
        bcm_show(dut, 'bcmcmd "ps"')
        bcm_show(dut, 'bcmcmd "show portmap"')
        return

    platform = platform.lower()
    hw_constants = st.get_datastore(dut, "constants")
    cmd = []
    # TH and TH2
    if platform in hw_constants["TH_PLATFORMS"] + hw_constants["TH2_PLATFORMS"]:
        cmd.append("g MMU_GCFG_BST_TRACKING_ENABLE")
        cmd.append("g THDI_BST_TRIGGER_STATUS_TYPE")
        cmd.append("g THDU_BST_STAT")
        cmd.append("g MMU_THDM_DB_DEVICE_BST_STAT")
        cmd.append("g THDI_BST_PG_SHARED_PROFILE_XPE0")
        cmd.append("g THDI_BST_PG_SHARED_PROFILE_XPE1")
        cmd.append("g THDI_BST_PG_SHARED_PROFILE_XPE2")
        cmd.append("g THDI_BST_PG_SHARED_PROFILE_XPE3")
        cmd.append("g THDI_BST_PG_HDRM_PROFILE_XPE0")
        cmd.append("g THDI_BST_PG_HDRM_PROFILE_XPE1")
        cmd.append("g THDI_BST_PG_HDRM_PROFILE_XPE2")
        cmd.append("g THDI_BST_PG_HDRM_PROFILE_XPE3")
        cmd.append("g OP_UC_QUEUE_BST_THRESHOLD")
        cmd.append("g MMU_THDM_DB_QUEUE_MC_BST_THRESHOLD_PROFILE")
        if test in ['shared', 'headroom']:
            cmd.append("d chg THDI_PORT_PG_BST_XPE0_PIPE0")
            cmd.append("d chg THDI_PORT_PG_BST_XPE0_PIPE3")
            cmd.append("d chg THDI_PORT_PG_BST_XPE1_PIPE0")
            cmd.append("d chg THDI_PORT_PG_BST_XPE1_PIPE3")
            cmd.append("d chg THDI_PORT_PG_BST_XPE2_PIPE1")
            cmd.append("d chg THDI_PORT_PG_BST_XPE2_PIPE2")
            cmd.append("d chg THDI_PORT_PG_BST_XPE3_PIPE1")
            cmd.append("d chg THDI_PORT_PG_BST_XPE3_PIPE2")
        elif test in ['unicast']:
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE0_PIPE0")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE0_PIPE1")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE1_PIPE2")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE1_PIPE3")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE2_PIPE0")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE2_PIPE1")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE3_PIPE2")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE3_PIPE3")
        elif test in ['multicast']:
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE0_PIPE0")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE0_PIPE1")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE1_PIPE2")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE1_PIPE3")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE2_PIPE0")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE2_PIPE1")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE3_PIPE2")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE3_PIPE3")

    # TD3
    elif platform in hw_constants["TD3_PLATFORMS"]:
        cmd.extend(["g MMU_GCFG_BST_TRACKING_ENABLE", "g THDI_BST_TRIGGER_STATUS_TYPE"])
        cmd.extend(["g THDU_BST_STAT", "g MMU_THDM_DB_DEVICE_BST_STAT"])
        if test in ['shared', 'headroom']:
            cmd.extend(["d chg THDI_PORT_PG_BST_XPE0_PIPE0", "d chg THDI_PORT_PG_BST_XPE0_PIPE1"])
        elif test in ['unicast']:
            cmd.extend(["d chg MMU_THDU_BST_QUEUE_XPE0_PIPE0", "d chg MMU_THDU_BST_QUEUE_XPE0_PIPE1"])
        elif test in ['multicast']:
            cmd.extend(["d chg MMU_THDM_DB_QUEUE_BST_XPE0_PIPE0", "d chg MMU_THDM_DB_QUEUE_BST_XPE0_PIPE1"])

    # TD2
    elif platform in hw_constants["TD2_PLATFORMS"]:
        cmd.extend(["g BST_TRACKING_ENABLE", "g MMU_THDM_DB_DEVICE_BST_STAT"])
        cmd.extend(["g THDI_BST_TRIGGER_STATUS_TYPE_PIPEX", "g THDI_BST_TRIGGER_STATUS_TYPE_PIPEY"])
        if test in ['shared', 'headroom']:
            cmd.extend(["d chg THDI_PORT_PG_BST_X", "d chg THDI_PORT_PG_BST_Y"])
        elif test in ['unicast']:
            cmd.extend(["d chg MMU_THDU_XPIPE_BST_QUEUE", "d chg MMU_THDU_YPIPE_BST_QUEUE"])
        elif test in ['multicast']:
            cmd.extend(["d chg MMU_THDM_DB_QUEUE_BST_0", "d chg MMU_THDM_DB_QUEUE_BST_1"])

    # TH3
    elif platform in hw_constants["TH3_PLATFORMS"]:
        cmd.append("g MMU_GLBCFG_BST_TRACKING_ENABLE")
        cmd.append("g MMU_THDI_BST_PG_SHARED_PROFILE")
        cmd.append("g MMU_THDI_BST_PG_HDRM_PROFILE")
        cmd.append("g MMU_THDO_MC_QUEUE_TOT_BST_THRESHOLD")
        cmd.append("g MMU_THDO_QUE_TOT_BST_THRESHOLD")
        cmd.append("d MMU_THDI_PORT_BST_CONFIG_PIPEx (x=0-3)")
        cmd.append("d MMU_THDI_PORT_PG_SHARED_BST_PIPEx (x=0-3)")
        cmd.append("d MMU_THDO_BST_TOTAL_QUEUE_ITMx (x=0-1)")

    else:
        st.error('Unhandled platform - {}'.format(platform))

    for each_cmd in ['bcmcmd "{}"'.format(e) for e in cmd]:
        bcm_config(dut, each_cmd, skip_error_check=True)

def get_intf_pmap(dut, interface_name=None):
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    This API is used to get the interface pmap details
    :param dut: dut
    :param interface_name: List of interface names
    :return:
    """
    import apis.system.interface as interface_obj
    ##Passing the cli_type as click in the API call "interface_status_show" because the lanes information is available only in click CLI.
    ##Please refer the JIRA: SONIC-22102 for more information.
    interfaces = cutils.make_list(interface_name) if interface_name else ''
    if interfaces:
        if any("/" in interface for interface in interfaces):
            interfaces = st.get_other_names(dut, interfaces)
            key = 'alias'
        else:
            key = 'interface'
        st.debug("The interfaces list is: {}".format(interfaces))
        interface_list = interface_obj.interface_status_show(dut, interfaces=interfaces, cli_type='click')
    else:
        key = 'alias' if interface_obj.show_ifname_type(dut, cli_type='klish') else 'interface'
        interface_list = interface_obj.interface_status_show(dut, cli_type='click')
    interface_pmap = dict()
    pmap_list = get_pmap(dut)
    for detail in cutils.iterable(interface_list):
        lane = detail["lanes"].split(",")[0] if "," in detail["lanes"] else detail["lanes"]
        for pmap in pmap_list:
            if pmap["physical"] == lane:
                interface_pmap[detail[key]] = pmap["interface"]
    return interface_pmap

def remove_vlan_1(dut):
    bcm_config(dut, 'bcmcmd "vlan remove 1 PortBitMap=all"')


def dump_dropcounter_info(dut):
    """
    Author: MA Raheem Ali(mohammed.raheem-ali@broadcom.com)
    This API is used to get the Drop Counter details
    :param dut: dut
    :return:
    """
    import apis.qos.copp as copp_api
    copp_api.get_cpu_queue_counters(dut)
    bcm_show(dut, 'bcmcmd "cstat * z"')
    bcm_show(dut, 'bcmcmd "mirror dest show"')
    bcm_show(dut, 'bcmcmd "mirror show"')
    bcm_show(dut, 'bcmcmd "fp show group 5"')


def l3_table_clear(dut):
    """
    Author: MA Raheem Ali(mohammed.raheem-ali@broadcom.com)
    This API is used to clear L3 Table
    :param dut:
    :return:
    """
    platform = basic_api.get_hwsku(dut).lower()
    hw_constants = st.get_datastore(dut, "constants", "default")
    if platform in hw_constants['TD4_PLATFORMS']+hw_constants['TH4_PLATFORMS']:
        command = "bcmcmd 'l3 host clear'"
    else:
        command = "bcmcmd 'l3 l3table clear'"
    bcm_config(dut, command, skip_error_check=True)

def clear_l3_tables(dut,clear_command):
    """
    Author: Mounika Thota(mounika.thota@broadcom.com)
    This API is used to clear L3 Tables
    :param dut:
    :return:
    """
    command = ("bcmcmd '{}'".format(clear_command))
    bcm_config(dut, command, skip_error_check=True)

def get_counter_cpu(dut,queue,value='diff'):
    cli_out = get_counters(dut)
    queue = 'PERQ_PKT(' + queue + ').cpu0'
    fil_out = cutils.filter_and_select(cli_out, [value], {"key": queue})
    if not fil_out:
        st.error('queue: {} not found in output: {}'.format(queue, cli_out))
        return False
    else:
        fil_out = fil_out[0]

    fil_out[value] = re.sub(r"\+", "", fil_out[value])
    return fil_out[value]

def verify_counter_cpu(dut,queue,value,tol):
    queue_mc = queue
    nooftimes = 3
    if isinstance(queue, bool): return False
    queue = 'PERQ_PKT(' + queue + ').cpu0'
    queue_mc = 'MC_PERQ_PKT(' + queue_mc + ').cpu0'
    for itercountvar in range(nooftimes):
        if itercountvar != 0:
            st.wait(5)
        cli_out = get_counters(dut)
        fil_out = cutils.filter_and_select(cli_out, ["time"], {"key": queue})
        if not fil_out:
            fil_out = cutils.filter_and_select(cli_out, ["time"], {"key": queue_mc})
        if not fil_out:
            st.error('queue: {} not found in output: {}'.format(queue, cli_out))
            if itercountvar < (nooftimes - 1):
                continue
            return False
        else:
            if not fil_out[0]['time']:
                st.error('queue: {} value is null in the output: {}'.format(queue, fil_out))
                if itercountvar < (nooftimes - 1):
                    clear_counters(dut)
                    continue
                return False
            fil_out = fil_out[0]

        if not fil_out['time']:
            st.error('queue: {} value is null in the output: {}'.format(queue, cli_out))
            if itercountvar < (nooftimes - 1):
                continue
            return False

        fil_out['time'] = re.sub(r'|'.join((',', '/s')), "", fil_out['time'])
        ob_value = int(fil_out['time'])
        start_value = int(value) - int(tol)
        end_value = int(value) + int(tol)
        if ob_value >= start_value and ob_value <= end_value:
            st.log('obtained value {} for queue: {} is in the range b/w '
                   '{} and {}'.format(ob_value,queue,start_value,end_value))
            return True
        else:
            st.error('obtained value {} for queue: {} is NOT in the range b/w '
                     '{} and {}'.format(ob_value, queue, start_value, end_value))
            if itercountvar < (nooftimes - 1):
                clear_counters(dut)
                continue
            return False

def check_wred_counter(dut, value=None):
    if not st.is_feature_supported("bcmcmd", dut):
        return None
    queue_dict_list = get_counters(dut)
    for queue_dict in queue_dict_list:
        if (queue_dict['key'] == 'WRED_PKT_GRE.'):
            if int(queue_dict['value'].replace(",", "")) == 0:
                st.error("{} queue_traffic_failed".format(value))
                return False
    return True

def check_cos_counter(dut, value=None):
    if not st.is_feature_supported("bcmcmd", dut):
        return None
    queue_dict_list = get_counters(dut)
    for queue_dict in queue_dict_list:
        if (queue_dict['key'] == 'MC_PERQ_PKT(1).cpu0'):
            if int(queue_dict['value'].replace(",", "")) == 0:
                st.error("{} queue_traffic_failed".format(value))
                return False
    return True

