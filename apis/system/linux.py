import re
from spytest import st
import apis.system.port as port_api

def process_kill(dut, process="ib_write_bw"):
    """
    API to kill process id in Linux
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param process:
    :return:
    """
    st.config(dut, "pkill -9 " + process)

def show_uname(dut):
    """
    API to display system OS details
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :return:
    """
    st.show(dut, "uname -a", skip_tmpl=True)

def set_pfc_priority(dut,ifname,pfc_priority):
    """
    API to enable PFC of specific priority
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param ifname: netdevice
    :param pfc_priority: Example 3
    :return:
    """
    ibvdevice_id = return_ibvdevice_for_netdevice(dut=dut,netdevice=ifname,param="deviceid")
    plist = [0,0,0,0,0,0,0,0]
    plist[pfc_priority] = 1
    p_str = ""
    for x in range(len(plist)): p_str=p_str+","+str(plist[x])
    p_str = p_str.lstrip(',')
    if "mlx" in ibvdevice_id:
        st.config(dut, "mlnx_qos -i {} --pfc {}".format(ifname,p_str))
        st.show(dut, "mlnx_qos -i {}".format(ifname), skip_tmpl=True)
    else:
        st.config(dut, "bnxtqos -dev={} set_pfc enabled={}".format(ifname,pfc_priority))
        st.show(dut, "bnxtqos -dev={} get_qos".format(ifname), skip_tmpl=True)

def set_trust_dscp(dut,ifname,ibdevice):
    """
    API to enable trust dscp on RDMA server and client
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param ibdevice: ibdevice id
    :param ifname: netdevice
    :return:
    NOTE: Required only in mlx chip server not required in Broadcom NIC server as it is set by default
          In case on MLX Server, set and display operation supported
          In case of BRCM Server, it will only display dscp to priority mapping as per IEEE 8021QAZ
    """
    if "mlx" in ibdevice:
        st.config(dut, "mlnx_qos -i {} --trust=dscp".format(ifname))
        st.show(dut, "mlnx_qos -i {}".format(ifname), skip_tmpl=True)
    else:
        st.show(dut, "bnxtqos -dev={} get_dscp2prio".format(ifname), skip_tmpl=True)

def show_server_pfc_frames(dut,ifname,ibdevice,priority):
    """
    API to display PFC pause farmes for given interface in RDMA Server
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param ifname:
    :param ibdevice:
    :return: dictionary with key and value pair
    """
    if "mlx" in ibdevice:
        output = st.config(dut, "ethtool -S {} | grep pause".format(ifname))
        regexp_match1 = re.search(r"rx_prio{}(.*)pause(.*): (\d+)".format(priority), output)
        regexp_match2 = re.search(r"tx_prio{}(.*)pause(.*): (\d+)".format(priority), output)
    else:
        output = st.config(dut, "ethtool -S {} | grep x_pfc_ena_frames_pri".format(ifname))
        regexp_match1 = re.search(r"r(.*)x_pfc_ena_frames_pri(.*){}: (\d+)".format(priority), output)
        regexp_match2 = re.search(r"t(.*)x_pfc_ena_frames_pri(.*){}: (\d+)".format(priority), output)
    dict1 = {}
    if not regexp_match1:
        dict1['rx_pfc{}_frames'.format(priority)] = None
    if not regexp_match2:
        dict1['tx_pfc{}_frames'.format(priority)] = None
    rx_value = regexp_match1.group(3) if regexp_match1 else '0'
    tx_value = regexp_match2.group(3) if regexp_match2 else '0'
    if regexp_match1 and regexp_match2:
        return {'rx_pfc{}_frames'.format(priority):rx_value, 'tx_pfc{}_frames'.format(priority):tx_value}
    else:
        return dict1


def show_server_cnp_frames(dut,ibdevice):
    """
    API to display ECN CNP Tx and Rx count for given interface in RDMA Server
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param ibdevice:
    :return: dictionary with key and value pair
    :return:
    """
    output1 = st.config(dut, "cat /sys/kernel/debug/bnxt_re/{}/info | grep \"CNP Tx Pkts\"".format(ibdevice), skip_tmpl=True)
    output2 = st.config(dut, "cat /sys/kernel/debug/bnxt_re/{}/info | grep \"CNP Rx Pkts\"".format(ibdevice), skip_tmpl=True)
    regexp_match1 = re.search(r"CNP Tx Pkts(.*): (\d+)", output1)
    regexp_match2 = re.search(r"CNP Rx Pkts(.*): (\d+)", output2)
    dict1 = {}
    if not regexp_match1:
        dict1['CNP_Tx_Pkts'] = None
    elif not regexp_match2:
        dict1['CNP_Rx_Pkts'] = None
    else:
        tx_value = regexp_match1.group(2)
        rx_value = regexp_match2.group(2)
        return {'CNP_Tx_Pkts':tx_value, 'CNP_Rx_Pkts':rx_value}
    return dict1


def show_vport_rdma_stats(dut,ifname,ibdevice):
    """
    API to return ethtool details for interface ifname
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param ifname:
    :return:
    """
    if "mlx" in ibdevice:
        output = st.config(dut, "ethtool -S {} | grep rdma".format(ifname), skip_tmpl=True)
        regexp_match1 = re.search(r"rx_vport(.*)rdma(.*)_unicast_packets: (\d+)", output)
        regexp_match2 = re.search(r"rx_vport(.*)rdma(.*)_unicast_bytes: (\d+)", output)
        regexp_match3 = re.search(r"tx_vport(.*)rdma(.*)_unicast_packets: (\d+)", output)
        regexp_match4 = re.search(r"tx_vport(.*)rdma(.*)_unicast_bytes: (\d+)", output)
        if not regexp_match1 or not regexp_match2 or not regexp_match3 or not regexp_match4:
            return {'rx_rdma_packets':None, 'rx_rdma_bytes':None, \
                    'tx_rdma_packets':None, 'tx_rdma_bytes':None}
        else:
            return {'rx_rdma_packets':regexp_match1.group(3),'rx_rdma_bytes':regexp_match2.group(3), \
                    'tx_rdma_packets':regexp_match3.group(3),'tx_rdma_bytes':regexp_match4.group(3)}
    else:
        ibvdevice_id = return_ibvdevice_for_netdevice(dut=dut,netdevice=ifname,param="deviceid")
        ibvdevice = ibvdevice_id.rstrip("/1")
        output = st.config(dut, "cat /sys/kernel/debug/bnxt_re/{}/info | grep \"RoCE Only\"".format(ibvdevice), skip_tmpl=True)
        regexp_match1 = re.search(r"RoCE Only(.*)Rx Pkts: (\d+)", output)
        regexp_match2 = re.search(r"RoCE Only(.*)Rx Bytes: (\d+)", output)
        regexp_match3 = re.search(r"RoCE Only(.*)Tx Pkts: (\d+)", output)
        regexp_match4 = re.search(r"RoCE Only(.*)Tx Bytes: (\d+)", output)
        if not regexp_match1 or not regexp_match2 or not regexp_match3 or not regexp_match4:
            return {'rx_rdma_packets':None, 'rx_rdma_bytes':None, \
                    'tx_rdma_packets':None, 'tx_rdma_bytes':None}
        else:
            return {'rx_rdma_packets':regexp_match1.group(2),'rx_rdma_bytes':regexp_match2.group(2), \
                    'tx_rdma_packets':regexp_match3.group(2),'tx_rdma_bytes':regexp_match4.group(2)}

def return_ibvdevice_for_netdevice(dut,netdevice,param):
    """
    API to return ibvdevice for given netdevice
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param netdevice:
    :return:
    """
    output = st.config(dut, "rdma link show | grep {}".format(netdevice), skip_tmpl=True)
    regexp_match = re.search(r"link (.*) state (.*) physical_state (.*) netdev ", output)
    if not regexp_match: return ""
    if param == "deviceid": return regexp_match.group(1)
    if param == "devicestate": return regexp_match.group(2)
    if param == "devicepstate": return regexp_match.group(3)

def run_rdma_traffic(server, client, s_ib_dev, c_ib_dev, client_ip, s_outfile="server",c_outfile="client",**kwargs):
    """
    API to run RDMA Server and Client specific tool ib_write_bw on Linux machine
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param server:
    :param client:
    :param s_ib_dev | Example: 'mlx5_0':
    :param c_ib_dev | Example: 'mlx5_0':
    :param c_ip | Example: '192.168.1.1':
    :param s_outfile | Example: '/tmp/server':
    :param c_outfile | Example: '/tmp/client':
    :kwargs : optional arg "run_all_size" to pass -a : --all  Run sizes from 2 till 2^23
    :kwargs : optional arg "s_net_device" - Server net device
    :kwargs : optional arg "c_net_device" - Client net device
    :return True|False:
    """
    if "ib_read_bw" in kwargs:
        process_kill(dut=server, process="ib_read_bw")
        process_kill(dut=client, process="ib_read_bw")
    else:
        process_kill(dut=server, process="ib_write_bw")
        process_kill(dut=client, process="ib_write_bw")

    s_stat1 = {};s_stat2 = {}
    c_stat1 = {};c_stat2 = {}
    s_stat1 = show_vport_rdma_stats(dut=server,ifname=kwargs["s_net_device"],ibdevice=s_ib_dev)
    c_stat1 = show_vport_rdma_stats(dut=client,ifname=kwargs["c_net_device"],ibdevice=c_ib_dev)

    s_pfc_s1 = show_server_pfc_frames(dut=server,ifname=kwargs["s_net_device"],ibdevice=s_ib_dev,priority='3')
    c_pfc_s1 = show_server_pfc_frames(dut=client,ifname=kwargs["c_net_device"],ibdevice=c_ib_dev,priority='3')

    if "bnxt" in s_ib_dev:
        s_cnp_stat1 = show_server_cnp_frames(dut=server,ibdevice=s_ib_dev)
        c_cnp_stat1 = show_server_cnp_frames(dut=client,ibdevice=c_ib_dev)

    st.banner("Step 1 API:  #### Creating files from RDMA server & client traffic stats output redirection ####")
    st.config(server, "touch /tmp/{}".format(s_outfile))
    st.config(client, "touch /tmp/{}".format(c_outfile))

    st.banner("Step 2 API: Starting the RDMA Server preftest tool instance ####")
    if "mlx" in s_ib_dev:
        if "run_all_size" in kwargs:
            st.config(server, "ib_write_bw -R -d {} -i 1 --report_gbits -a >/tmp/{} 2>&1 &".format(s_ib_dev,s_outfile))
        elif "ib_read_bw" in kwargs:
            st.config(server, "ib_read_bw -R -d {} -i 1 --report_gbits -D 10 >/tmp/{} 2>&1 &".format(s_ib_dev,s_outfile))
        else:
            if "queue_pair" in kwargs:
                st.config(server, "ib_write_bw -R -d {} -i 1 --report_gbits -D 10 -q {} >/tmp/{} 2>&1 &".format(s_ib_dev,kwargs['queue_pair'],s_outfile))
            else:
                st.config(server, "ib_write_bw -R -d {} -i 1 --report_gbits -D 10 >/tmp/{} 2>&1 &".format(s_ib_dev,s_outfile))
    else:
        if "run_all_size" in kwargs:
            st.config(server, "ib_write_bw -d {} -F --report_gbits -a -x 1 -R >/tmp/{} 2>&1 &".format(s_ib_dev,s_outfile))
        elif "ib_read_bw" in kwargs:
            st.config(server, "ib_read_bw -d {} -F --report_gbits -s 65536 -x 1 -R -b -a >/tmp/{} 2>&1 &".format(s_ib_dev,s_outfile))
        else:
            if "queue_pair" in kwargs:
                st.config(server, "ib_write_bw -d {} -F --report_gbits -x 1 -R -q {} -a >/tmp/{} 2>&1 &".format(s_ib_dev,kwargs['queue_pair'],s_outfile))
            else:
                st.config(server, "ib_write_bw -d {} -F --report_gbits -s 65536 -x 1 -R -a >/tmp/{} 2>&1 &".format(s_ib_dev,s_outfile))

    st.wait(5,"Waiting for 5 seconds after RDMA Server is started before RDMA client is initiated")
    st.banner("Step 3 API: Starting the RDMA Client preftest tool instance ####")
    if "mlx" in s_ib_dev:
        if "run_all_size" in kwargs:
            cmd = "ib_write_bw -R -d {} -i 1 --report_gbits {} -a -T 106 >/tmp/{} 2>&1 &".format(c_ib_dev,client_ip,c_outfile)
            retry_till_no_error(client,cmd,retry=4,timeout=11)
        elif "ib_read_bw" in kwargs:
            cmd = "ib_read_bw -R -d {} -i 1 --report_gbits {} -D 10 -T 106 -b >/tmp/{} 2>&1 &".format(c_ib_dev,client_ip,c_outfile)
            retry_till_no_error(client,cmd,retry=4,timeout=11)
        else:
            if "queue_pair" in kwargs:
                cmd = "ib_write_bw -R -d {} -i 1 --report_gbits {} -D 10 -T 106 -q {} >/tmp/{} 2>&1 &".format(c_ib_dev,client_ip,kwargs['queue_pair'],c_outfile)
                retry_till_no_error(client,cmd,retry=4,timeout=11)
            else:
                cmd = "ib_write_bw -R -d {} -i 1 --report_gbits {} -D 10 -T 106 -b >/tmp/{} 2>&1 &".format(c_ib_dev,client_ip,c_outfile)
                retry_till_no_error(client,cmd,retry=4,timeout=11)
    else:
        if "run_all_size" in kwargs:
            #st.config(client, "ib_write_bw -d {} -F --report_gbits {} -a -x 1 -R -T 106 >/tmp/{} 2>&1 &".format(c_ib_dev,client_ip,c_outfile))
            cmd = "ib_write_bw -d {} -F --report_gbits {} -a -x 1 -R -T 106".format(c_ib_dev,client_ip)
            retry_till_no_error(client,cmd,retry=4,timeout=30)
        elif "ib_read_bw" in kwargs:
            #st.config(client, "ib_read_bw -d {} -F --report_gbits -s 65536 {} -x 1 -R -T 106 -b >/tmp/{} 2>&1 &".format(c_ib_dev,client_ip,c_outfile))
            cmd = "ib_read_bw -d {} -F --report_gbits -s 65536 {} -x 1 -R -T 106 -b".format(c_ib_dev,client_ip)
            retry_till_no_error(client,cmd,retry=4,timeout=11)
        else:
            if "queue_pair" in kwargs:
                #st.config(client, "ib_write_bw -d {} -F --report_gbits -x 1 -R -T 106 {} -q {} -a >/tmp/{} 2>&1 &".format(c_ib_dev,client_ip,kwargs['queue_pair'],c_outfile))
                cmd = "ib_write_bw -d {} -F --report_gbits -x 1 -R -T 106 {} -q {} -a".format(c_ib_dev,client_ip,kwargs['queue_pair'])
                retry_till_no_error(client,cmd,retry=4,timeout=11)
            else:
                #st.config(client, "ib_write_bw -d {} -F --report_gbits -s 32768 {} -x 1 -R -T 106 >/tmp/{} 2>&1 &".format(c_ib_dev,client_ip,c_outfile))
                cmd = "ib_write_bw -d {} -F --report_gbits -s 65536 {} -x 1 -R -T 106".format(c_ib_dev,client_ip)
                retry_till_no_error(client,cmd,retry=10,timeout=11)

    if "run_all_size" in kwargs and "mlx" in s_ib_dev:
        st.wait(20,"Wating for 20 sec to run RDMA traffic of all sizes from 2 till 2^23 and stops before collecting the stats")
        if "stats" in kwargs:
            port_api.get_interface_counters_all(kwargs['stats']['dut1'], port=kwargs['stats']['port1'])
            port_api.get_interface_counters_all(kwargs['stats']['dut2'], port=kwargs['stats']['port2'])
        st.wait(100,"Wating for 100 sec to run RDMA traffic of all sizes from 2 till 2^23 and stops before collecting the stats")
    else:
        st.wait(10,"Waiting for 10 seconds so that RDMA traffic stops before collecting the stats")
        if "stats" in kwargs:
            port_api.get_interface_counters_all(kwargs['stats']['dut1'], port=kwargs['stats']['port1'])
            port_api.get_interface_counters_all(kwargs['stats']['dut2'], port=kwargs['stats']['port2'])

    process_kill(server, process="ib_write_bw")
    if "bnxt" not in s_ib_dev:
        process_kill(client, process="ib_write_bw")

    st.banner("Step 4 API: Showing RDMA Server RoCEv2 ib_write_bw otuput ####")
    st.config(server, "cat /tmp/{}".format(s_outfile),skip_error_check=True)
    st.banner("Step 5 API:  #### Showing RDMA Client RoCEv2 ib_write_bw output ####")
    st.config(client, "cat /tmp/{}".format(c_outfile),skip_error_check=True)

    s_pfc_s2 = show_server_pfc_frames(dut=server,ifname=kwargs["s_net_device"],ibdevice=s_ib_dev,priority='3')
    c_pfc_s2 = show_server_pfc_frames(dut=client,ifname=kwargs["c_net_device"],ibdevice=c_ib_dev,priority='3')
    s_pfc_s1 = convert_dict_val_str_int(s_pfc_s1)
    c_pfc_s1 = convert_dict_val_str_int(c_pfc_s1)
    s_pfc_s2 = convert_dict_val_str_int(s_pfc_s2)
    c_pfc_s2 = convert_dict_val_str_int(c_pfc_s2)
    s_tx_pfc3_test = s_pfc_s2['tx_pfc3_frames']-s_pfc_s1['tx_pfc3_frames']
    c_tx_pfc3_test = c_pfc_s2['tx_pfc3_frames']-c_pfc_s1['tx_pfc3_frames']
    s_rx_pfc3_test = s_pfc_s2['rx_pfc3_frames']-s_pfc_s1['rx_pfc3_frames']
    c_rx_pfc3_test = c_pfc_s2['rx_pfc3_frames']-c_pfc_s1['rx_pfc3_frames']

    st.banner("Step 6 API: PFC 3 Pause frames Tx and Rx by Server & Client Nodes")
    st.log("  Client PFC3 Rx Pause Frames during this RDMA traffic test = {}".format(c_rx_pfc3_test))
    st.log("  Server PFC3 Rx Pause Frames during this RDMA traffic test = {}".format(s_rx_pfc3_test))
    st.log("  Client PFC3 Tx Pause Frames during this RDMA traffic test = {}".format(c_tx_pfc3_test))
    st.log("  Server PFC3 Tx Pause Frames during this RDMA traffic test = {}".format(s_tx_pfc3_test))

    if "bnxt" in s_ib_dev:
        s_cnp_stat2 = show_server_cnp_frames(dut=server,ibdevice=s_ib_dev)
        c_cnp_stat2 = show_server_cnp_frames(dut=client,ibdevice=c_ib_dev)
        s_cnp_stat1 = convert_dict_val_str_int(s_cnp_stat1)
        c_cnp_stat1 = convert_dict_val_str_int(c_cnp_stat1)
        s_cnp_stat2 = convert_dict_val_str_int(s_cnp_stat2)
        c_cnp_stat2 = convert_dict_val_str_int(c_cnp_stat2)
        s_cnp_tx = s_cnp_stat2['CNP_Tx_Pkts'] - s_cnp_stat1['CNP_Tx_Pkts']
        c_cnp_tx = c_cnp_stat2['CNP_Tx_Pkts'] - c_cnp_stat1['CNP_Tx_Pkts']
        s_cnp_rx = s_cnp_stat2['CNP_Rx_Pkts'] - s_cnp_stat1['CNP_Rx_Pkts']
        c_cnp_rx = c_cnp_stat2['CNP_Rx_Pkts'] - c_cnp_stat1['CNP_Rx_Pkts']
        st.banner("   ECN CNP Tx and Rx Pkt Pkts during this test by Server & Client Nodes  ")
        st.log("  Client ECN CNP Tx Pkts during this RDMA traffic test = {}".format(c_cnp_tx))
        st.log("  Server ECN CNP Tx Pkts during this RDMA traffic test = {}".format(s_cnp_tx))
        st.log("  Client ECN CNP Rx Pkts during this RDMA traffic test = {}".format(c_cnp_rx))
        st.log("  Server ECN CNP Rx Pkts during this RDMA traffic test = {}".format(s_cnp_rx))

    s_stat2 = show_vport_rdma_stats(dut=server,ifname=kwargs["s_net_device"],ibdevice=s_ib_dev)
    c_stat2 = show_vport_rdma_stats(dut=client,ifname=kwargs["c_net_device"],ibdevice=c_ib_dev)

    s_stat1 = convert_dict_val_str_int(s_stat1)
    s_stat2 = convert_dict_val_str_int(s_stat2)
    c_stat1 = convert_dict_val_str_int(c_stat1)
    c_stat2 = convert_dict_val_str_int(c_stat2)

    Tx = s_stat2['tx_rdma_packets']-s_stat1['tx_rdma_packets']
    Rx = c_stat2['rx_rdma_packets']-c_stat1['rx_rdma_packets']
    Loss1 = Tx - Rx
    st.banner("Step 7 API: RDMA Traffic Packet loss in the direction Server to Client")
    st.log("    RDMA Server Total Tx Packets   = {}    ".format(Tx))
    st.log("    RDMA Client Total Rx Packets   = {}    ".format(Rx))
    st.log("    Pkt loss from Server to Client = {} \n".format(Loss1))

    Tx = c_stat2['tx_rdma_packets']-c_stat1['tx_rdma_packets']
    Rx = s_stat2['rx_rdma_packets']-s_stat1['rx_rdma_packets']
    Loss2 = Tx - Rx
    st.banner("Step 8 API: RDMA Traffic Packet loss in the direction Client to Server")
    st.log("    RDMA Client Total Tx Packets  = {}    ".format(Tx))
    st.log("    RDMA Server Total Rx Packets  = {}    ".format(Rx))
    st.log("    Pkt loss from Cient to Server = {} \n".format(Loss2))

    Tx = s_stat2['tx_rdma_bytes']-s_stat1['tx_rdma_bytes']
    Rx = c_stat2['rx_rdma_bytes']-c_stat1['rx_rdma_bytes']
    Loss3 = Tx - Rx
    st.banner("Step 9 API: RDMA Traffic Loss in bytes in the direction Server to Client")
    st.log("    RDMA Server Total Tx Bytes       =   {}    ".format(Tx))
    st.log("    RDMA Client Total Rx Bytes       =   {}    ".format(Rx))
    st.log("    Bytes loss from Server to Client = {} \n".format(Loss3))

    Tx = c_stat2['tx_rdma_bytes']-c_stat1['tx_rdma_bytes']
    Rx = s_stat2['rx_rdma_bytes']-s_stat1['rx_rdma_bytes']
    Loss4 = Tx - Rx
    st.banner("Step 10 API: RDMA Traffic Loss in bytes in the direction Client to Server")
    st.log("    RDMA Client Total Tx Bytes      =   {}    ".format(Tx))
    st.log("    RDMA Server Total Rx Bytes      =   {}    ".format(Rx))
    st.log("    Bytes loss from Cient to Server = {} \n".format(Loss4))

    if "run_all_size" not in kwargs:
        if Loss1 > 15:
            st.error("RDMA Traffic Pkt loss from Server to Client is {}".format(Loss1))
            return False
        elif Loss2 > 15:
            st.error("RDMA Traffic Pkt loss from Client to Server is {}".format(Loss2))
            return False
        else:
            st.log("PASS:RDMA Traffic Pkt loss from Server to Client is {}".format(Loss1))
            st.log("PASS:RDMA Traffic Pkt loss from Client to Server is {}".format(Loss2))
            return True
    else:
        st.log("RDMA Traffic Pkt loss from Server to Client is {}".format(Loss1))
        st.log("RDMA Traffic Pkt loss from Client to Server is {}".format(Loss2))
        return True

def convert_dict_val_str_int(dict={}):
    for a, x in dict.items():
        dict[a]=int(x) if x is not None else 0
    return dict

def show_server_route(dut,family='ipv4'):
    """
    API to display IPv4 and IPv6 routes in server
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param family: ipv4 |i ipv6
    :return: show output from server
    """
    if family == 'ipv4':
        st.show(dut, "/sbin/route", skip_tmpl=True)
    elif family == 'ipv6':
        st.show(dut, "/sbin/route -A inet6", skip_tmpl=True)

def retry_till_no_error(dut,cmd,retry=4,timeout=11):
    success = False
    for i in range(1,retry):
        result = st.config(dut,cmd,timeout=11)
        if 'socket' not in result and 'Unexpected' not in result and \
                'Unable' not in result and 'RDMA_CM_EVENT_REJECTED' not in result: 
            success = True
        if success:
            break
        else:
            process_kill(dut=dut, process="ib_write_bw")
            process_kill(dut=dut, process="ib_read_bw")
            st.wait(5,"Linux command shows error so doing {} retry..".format(i))

def ping(dut, ip_address="172.16.2.1",count='3'):
    """
    API to intiate ping from the Linux
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param ip_address:
    :return:
    """
    output = st.config(dut, "ping " + ip_address + " -c "+count)
    if 'Unreachable' in output or '100% packet loss' in output:
        st.log("Either IP is unrechable or packet loss is seen")
        return False
    else:
        st.log("Dest IP is rechable..")
        return True

def apply_netplan(dut):
    st.config(dut, "netplan apply")
