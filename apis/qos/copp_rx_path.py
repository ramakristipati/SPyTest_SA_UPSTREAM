# This file contains the list of API's which performs copp rx path operations.
# @author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest import st

FILE_PATH = "/proc/bcm/knet/rx_drop"

def get_rx_drop(dut, **kwargs):
    """
    To get RX Drop table
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = 'click'
    cmd = "cat {}".format(FILE_PATH)
    show_out = st.show(dut, cmd, type=cli_type)
    out = {'queues_status': [], "cpu_rx_queues":[]}
    for each in show_out:
        out['max'] = each['max']
        out['drop'] = each['drop']
        out['resume'] = each['resume']
        out['status'] = each['status'] if each['status'] else out['status']
        if each['cpu']:
            include_keys = ['cpu', 'counter_pkts', 'high_watermark', 'high_watermark_val', 'last_q_size', 'drop_pkts']
            rv = [{each_key: each[each_key] for each_key in each if each_key in include_keys}]
            out['queues_status'].append(rv)
        if each['rx_cpu']:
            include_keys = ['rx_cpu', 'rx_cpu_selected', 'rx_q_counter_pkts', 'rx_q_drop_pkts', 'net_rx_drop']
            rv = [{each_key: each[each_key] for each_key in each if each_key in include_keys}]
            out['cpu_rx_queues'].append(rv)
    return out


def config_rx_drop(dut, **kwargs):
    """
    To Config - KNET Rx Drop Thresholds
    :param dut:
    :param kwargs:
    :return:
    Usage: config_rx_drop(dut, enable_queues='0xfffff', drop='3000', resume='1500')
    """
    cli_type = 'click'
    cmd = []
    if 'enable_queues' in kwargs:
        cmd.append('echo "enable_queues={}" > {}'.format(kwargs['enable_queues'], FILE_PATH))
    if 'drop' in kwargs:
        cmd.append('echo "drop_threshold={}" > {}'.format(kwargs['drop'], FILE_PATH))
    if 'resume' in kwargs:
        cmd.append('echo "resume_threshold={}" > {}'.format(kwargs['resume'], FILE_PATH))
    return st.config(dut, cmd, type=cli_type)


def verify_dmesg(dut, filter=None):
    """
    To get dmesg
    :param dut:
    :param filter:
    :return:
    """
    cli_type = 'click'
    cmd = "sudo dmesg"
    if filter:
        cmd += " | grep {}".format(filter)
    out = st.show(dut, cmd, type=cli_type, skip_tmpl=True, skip_error_check=True, faster_cli=False, max_time=1200)
    out_list = out.strip().split('\n')[:-1]
    for _ in range(out_list.count("'")):
        out_list.remove("'")
    return out_list


def clear_rx_drop(dut, **kwargs):
    """
    To clear - KNET Rx Drop Counters
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = 'click'
    cmd = 'echo "clear_stats" > {}'.format(FILE_PATH)
    return st.config(dut, cmd, type=cli_type)


def get_rx_drop_counterss(dut, **kwargs):
    """
    To get - KNET Counters
    :param dut:
    :param mode: stats | dstats
    :param kwargs:
    :return:
    Usage1 :  get_counters(dut, mode='stats')
    Usage2 :  get_counters(dut, mode='dstats')
    Usage3 :  get_counters(dut, mode='dstats', key='Tx drop no skb')
    """
    cli_type = 'click'
    mode = kwargs.get('mode', 'stats')
    if mode not in ['stats', 'dstats']:
        return None
    cmd = "/proc/bcm/knet/{}".format(mode)
    out = st.show(dut, cmd, type=cli_type)
    out2 = {i['key']: int(i['value']) for i in out}
    if kwargs.get('key'):
        return out2.get(kwargs['key'])
    else:
        return out2
