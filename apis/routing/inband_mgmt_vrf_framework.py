from spytest import st
import re

def create_delete_logical_interface(dut, int_type, int_id_list, add = True):
    """
    Example invocation:
    # result = create_delete_logical_interface(vars.D1, [10,20], Vlan, True)

    Attempt to configure or de-configure logical interface with the interface id specified by the
    interface id and interface type.

    Parameters:

    :dut: Device under test
    :param int_type: Type of interface eg: Vlan, PortChannel
    :param int_id_list: list of Interface ids for logical interface
    :param add: bool value set to True (the default value) to add/configure
     interface or set to False to delete/de-configure the interface.
    :return: bool value set to True if the add/delete was successful, or
     set to False if the add/delete failed.
    """
    if int_type.lower() == "vlan":
        interface_type = "Vlan "
    elif int_type.lower() == "portchannel":
        interface_type = "PortChannel "
    elif int_type.lower() == "loopback":
        interface_type = "Loopback "
    else:
        st.log("Invalid interface type {} specified for logical interface creation or deletion.".format(int_type))
        return False

    interface_cmd_str = ""
    no_string = ""
    cfg_type_string = "configuring"

    if not add:
       no_string = "no "
       cfg_type_string = "de-configuring"
    st.log("{} {}".format(cfg_type_string, interface_type))

    for interface_id in int_id_list:
        interface_cmd_str += "{}interface {} {}\n".format(no_string, interface_type, interface_id)
        #interface_cmd_str += "exit\n"

    try:
        output = st.config(dut, interface_cmd_str, type='klish')
        if re.search("%Error", output):
            st.log("Failure executing cmds:\n" + interface_cmd_str + ": Error message: " + output)
            return False
        st.log("Succeeded {} interface {}.".format(cfg_type_string, interface_type))
        return True
    except ValueError as err_msg:
        st.log("Exception {} interface(s):\n"
               "Error message: {}".format(cfg_type_string, err_msg))
        return False

def create_delete_subinterface(dut,interface,add=True):
    """
    Example invocation:
    # result = create_delete_subinterface(vars.D1, 'Ethernet4.4')

    Attempt to create Ethernet/Portchannel subinterface

    Parameters:

    :dut: Device under test
    :param interface: Ethernet/Portchannel subinterface
    :param add: bool value set to True (the default value) to add/configure, set to False to remove/deconfigure
    :return: bool value set to True if add/delete was successful, or
     set to False otherwise.
    """

    interface_cmd_str = ""
    no_string = ""
    cfg_type_string = "configuring"

    if not add:
       no_string = "no "
       cfg_type_string = "de-configuring"
    st.log("{} {}".format(cfg_type_string, interface))

    interface_cmd_str += "{}interface {}\n".format(no_string, interface)

    try:
        output = st.config(dut, interface_cmd_str, type='klish')
        if re.search("%Error", output):
            st.log("Failure executing cmds:\n" + interface_cmd_str + ": Error message: " + output)
            return False
        st.log("Succeeded {} .".format(cfg_type_string))
        return True
    except ValueError as err_msg:
        st.log("Exception '{}' :\n"
               "Error message: {}".format(cfg_type_string, err_msg))
        return False

def run_traceroute_vrf(dut,ip,vrf,family='ip'):
    """
    Example invocation:
    # result = run_traceroute_vrf(vars.D1, '1.1.1.1', 'mgmt', 'ipv4')

    Trace route to ipv4/ipv6

    Parameters:

    :dut: Device under test
    :param ip: ipv4/ipv6 address
    :param vrf: VRF name
    :param family: 'ipv6' for ipv6 ip address and 'ip'(default value) for ipv4 address
    :return: bool value set to True if able to find route to ip, else set to False
    """
    cmdstr = "traceroute vrf {} {}".format(vrf,ip)
    if family=="ipv6":
        cmdstr = "traceroute6 vrf {} {}".format(vrf,ip)

    try:
        output = st.config(dut, cmdstr, type='klish')
        output="\n".join(output.split("\n")[1:])
        if re.search("%Error", output):
            st.log("Failure executing cmds:\n" + cmdstr + ": Error message: " + output)
            return False
        elif re.search(ip, output):
            st.log("Succeeded in tracing route to "+ip)
            return True
        st.log("Failed in  tracing route to {}.".format(ip))
        return False
    except ValueError as err_msg:
        st.log("Exception {} :\n"
                "Error message: {}".format(cmdstr, err_msg))
        return False

def add_vlanid_to_subinterface(dut, int_name, vlan_id, add = True):
    """
    Example invocation:
    # result = add_vlanid_to_subinterface(vars.D1, 'Ethernet1.1', '100', add = True)

    Add/remove Vlan-id from subinterface

    Parameters:

    :dut: Device under test
    :param int_name: subinterface name eg: Ethernet1.1 or PortChannel 10.1
    :param vlan_id: vlan-id used for encapsultion
    :param add: bool value set to True (the default value) to add/configure
     interface or set to False to delete/de-configure the interface.
    :return: bool value set to True if the add/delete was successful, or
     set to False if the add/delete failed.
    """
    interface_cmd_str = ""
    cfg_type_string = "configuring"

    interface_cmd_str = "interface {} \n".format(int_name)

    if not add:
       cfg_type_string = "de-configuring"
       st.log("{} {}".format(cfg_type_string, int_name))
       interface_cmd_str += "no encapsulation"
    else:
        st.log("{} {}".format(cfg_type_string, int_name))
        interface_cmd_str += "encapsulation dot1q vlan-id {} \n".format(vlan_id)

    interface_cmd_str += 'exit\n'
    try:
        output = st.config(dut, interface_cmd_str, type='klish')
        if re.search("%Error", output):
            st.log("Failure executing cmds:\n" + interface_cmd_str +
                   ": Error message: " + output)
            return False
        else:
            st.log("Succeeded {} VRF forwarding.".format(cfg_type_string))
            return True

    except ValueError as err_msg:
        st.log("Exception during VRF forwarding configuration:\n" +
               "Error message: " + str(err_msg))
        return False


def add_interface_to_vrf_config(dut, int_name, vrf_name = "mgmt", add = True):
    """
    Example invocation:
    # result = add_interface_to_vrf(vars.D1, 'Ethernet1', vrf_name = "mgmt", add = True)

    Add/remove logical or Physical interface to mgmt vrf

    Parameters:

    :dut: Device under test
    :param int_name: interface name eg: Ethernet1 or Vlan 10 or PortChannel 10
    :param vrf_name: name of vrf to which interface needs to be added
    :param add: bool value set to True (the default value) to add/configure
     interface or set to False to delete/de-configure the interface.
    :return: bool value set to True if the add/delete was successful, or
     set to False if the add/delete failed.
    """
    interface_cmd_str = ""
    no_string = ""
    cfg_type_string = "configuring"

    if not add:
       no_string = "no "
       cfg_type_string = "de-configuring"

    st.log("{} {}".format(cfg_type_string, int_name))

    interface_cmd_str = "interface {} \n".format(int_name)
    interface_cmd_str += "{}ip vrf forwarding {} \n".format(no_string,vrf_name)
    interface_cmd_str += 'exit\n'
    try:
        output = st.config(dut, interface_cmd_str, type='klish', skip_error_check = True)
        if re.search("Error", output):
            st.log("Failure executing cmds:\n" + interface_cmd_str +
                   ": Error message: " + output)
            return False
        else:
            st.log("Succeeded {} VRF forwarding.".format(cfg_type_string))
            return True

    except ValueError as err_msg:
        st.log("Exception during VRF forwarding configuration:\n" +
               "Error message: " + str(err_msg))
        return False

def add_interfaces_to_vrf_using_range_cmd(dut, intf_type, int_range, vrf_name="mgmt", add = True):
    """
    Example invocation:
    # result = add_interfaces_to_vrf_using_range_cmd(vars.D1, 'Ethernet', "1-3",vrf_name = "mgmt", add = True)
    # result = add_interfaces_to_vrf_using_range_cmd(vars.D1, 'Ethernet', "1,3",vrf_name = "mgmt", add = True)

    Add/Remove logical or Physical interface to mgmt vrf using range cmd

    Parameters:

    :dut: Device under test
    :param intf_type: interface type eg: Ethernet or Vlan  or PortChannel
    :param int_range: range of interfaces to be added to vrf eg: "1-3" (means add first 3 interfaces to vrf)
                        or "1,3"(means add 1st and 3rd interface to vrf)
    :param vrf_name: name of vrf to which interface needs to be added
    :param add: bool value set to True (the default value) to add/configure
     interface or set to False to delete/de-configure the interface.
    :return: bool value set to True if the add/delete was successful, or
     set to False if the add/delete failed.
    """
    ifname_type =  st.get_ifname_type(dut)
    intf_name_prefix = intf_type
    if ((intf_type.lower()=="ethernet") and (ifname_type == 'alias')):
            intf_name_prefix = 'Eth'

    Ethernet_all_ports = st.get_all_ports(dut)
    st.log("Ethernet_all_ports = {}".format(Ethernet_all_ports))

    intf_range = ""

    if int_range == "" :
        return False
    elif intf_type.lower() == "ethernet":
        if int_range.find('-') != -1 :
            temp_range = int_range.split("-")
            st.log("temp_range = {}".format(temp_range))
            try:
                intf_range = Ethernet_all_ports[int(temp_range[0])].strip(intf_name_prefix) + "-" + Ethernet_all_ports[int(temp_range[1])].strip(intf_name_prefix)
            except ValueError as err_msg:
                st.log("Exception during interface range configuration:\n" +
                        "Error message: " + str(err_msg))
                return False
        elif int_range.find(',') != -1 :
            temp_range = int_range.split(",")
            try:
                intf_range = Ethernet_all_ports[int(temp_range[0])].strip(intf_name_prefix) + "," + Ethernet_all_ports[int(temp_range[1])].strip(intf_name_prefix)
            except ValueError as err_msg:
                st.log("Exception during interface range configuration:\n" +
                        "Error message: " + str(err_msg))
                return False
        else :
            return False
    else:
        intf_range = int_range

    interface_cmd_str = ""
    no_string = ""
    cfg_type_string = "configuring"

    if not add:
       no_string = "no "
       cfg_type_string = "de-configuring"

    st.log("{} {} {}".format(cfg_type_string, intf_type, intf_range))
    interface_cmd_str = "interface range {} {} \n".format(intf_name_prefix,intf_range)
    interface_cmd_str += "{}ip vrf forwarding {} \n".format(no_string,vrf_name)
    interface_cmd_str += 'exit\n'

    try:
        output = st.config(dut, interface_cmd_str, type='klish', skip_error_check = True)
        if re.search("%Error", output):
            st.log("Failure executing cmds:\n" + interface_cmd_str +
                   ": Error message: " + output)
            return False
        else:
            st.log("Succeeded {} VRF forwarding for interface range.".format(cfg_type_string))
            return True

    except ValueError as err_msg:
        st.log("Exception during VRF forwarding configuration for interface range:\n" +
               "Error message: " + str(err_msg))
        return False

def verify_subinterface_created(dut,Interface):
    """
    Example invocation:
    # result = verify_subinterface_created(vars.D1,Ethernet1.1)

    Verify subinterface created

    Parameters:

    :dut: Device under test
    :param Interface: interface name eg: Ethernet1.1 or PortChannel 10.1
    :return: bool value set to True if the verification was successful,
     else set to False.
    """
    cmd = "show subinterfaces status"
    Interface_small=Interface.lower()
    if Interface_small.startswith("portchannel"):
        Interface = Interface.replace(" ","")
    try:
        output = st.show(dut, cmd , exec_mode='mgmt-user', type='klish')
        st.log(output)
        for result in output:
            if result["interface"]==Interface:
                st.log("Subinterface {} got created".format(Interface))
                return True
        st.log("Subinterface {} not created".format(Interface))
        return False

    except ValueError as err_msg:
        st.log("Exception executing {}: Error "
               "message: {}".format(cmd, str(err_msg)))
        return False

def verify_vlanid_added_to_subinterface(dut,Interface,vlanid):
    """
    Example invocation:
    # result = verify_vlanid_added_to_subinterface(vars.D1,Ethernet1.1,100)

    Verify vlan id is associated with subinterface

    Parameters:

    :dut: Device under test
    :param Interface: interface name eg: Ethernet1.1 or PortChannel 10.1
    :param vlanid: vlan id eg: 100
    :return: bool value set to True if the verification was successful,
     else set to False.
    """
    cmd = "show subinterfaces status"
    Interface_small=Interface.lower()
    if Interface_small.startswith("portchannel"):
        Interface = Interface.replace(" ","")
    try:
        output = st.show(dut, cmd , exec_mode='mgmt-user', type='klish')
        st.log(output)
        for result in output:
            if result["interface"]==Interface and result["vlan"]==vlanid:
                st.log("Vlan-id {} is added to subinterface {}".format(vlanid,Interface))
                return True
        st.log("Vlan-id {} is not added to subinterface {}".format(vlanid,Interface))
        return False

    except ValueError as err_msg:
        st.log("Exception executing {}: Error "
               "message: {}".format(cmd, str(err_msg)))
        return False

def show_interface_added_to_mgmtVrf(dut):
    """
    Example invocation:
    # result = show_interface_added_to_mgmtVrf_show(vars.D1)

    show interfaces associated to vrf

    Parameters:

    :dut: Device under test
    :return: output in form of dictionary if found else return None
    """
    cmd = "show ip vrf mgmt"
    try:
        output = st.show(dut, cmd , exec_mode='mgmt-user', type='klish')
        if output is None:
            st.log("Empty output executing {}".format(cmd))
            return None
    except ValueError as err_msg:
        st.log("Exception executing {}: Error "
               "message: {}".format(cmd, str(err_msg)))
        return None

    return output

def show_interface_added_to_Vrf(dut):
    """
    Example invocation:
    # result = verify_interface_added_to_Vrf_show(vars.D1)

    show interfaces associated to vrf

    Parameters:

    :dut: Device under test
    :return: output in form of dictionary if found else return None
    """
    cmd = "show ip vrf"
    try:
        output = st.show(dut, cmd , exec_mode='mgmt-user', type='klish')
        if output is None:
            st.log("Empty output executing {}".format(cmd))
            return None
    except ValueError as err_msg:
        st.log("Exception executing {}: Error "
               "message: {}".format(cmd, str(err_msg)))
        return None

    return output

def config_unconfig_ip_config(dut, cmd_str):
    """
    Example invocation:
    # result = config_unconfig_ip_config(vars.D1, 'interface Ethernet1 \n ip address 1.1.1.1/8')
    # result = config_unconfig_ip_config(vars.D1, 'interface Ethernet1 \n no ipv6 address 2000::!/8)

    Config/Unconfig ip addresss

    Parameters:

    :dut: Device under test
    :param cmd_str: cmd to add/remove ip/ipv6 address.
    :param cfg_type_string: specify configure or de-configure
    :return: bool value set to True if the add/delete was successful, or
     set to False if the add/delete failed.
    """
    try:
        output = st.config(dut, cmd_str, type='klish')
        if re.search("%Error", output):
            st.log("Failure executing cmds:\n" + cmd_str +
                   ": Error message: " + output)
            return False
        else:
            st.log("Succeeded configuring ip address.")
            return True

    except ValueError as err_msg:
        st.log("Exception during ip/ipv6 address configuration:\n" +
               "Error message: " + str(err_msg))
        return False

def add_remove_member_interfaces_to_logical_interface(dut,meb_intf, log_intf, add = True):
    """
    Example invocation:
    # result = add_remove_member_interfaces_to_logical_interface(vars.D1, 'Ethernet1', 'Vlan 10',add= "True")

    config/unconfig Ethernet as member of Vlan or portchannel

    Parameters:

    :dut: Device under test
    :param meb_intf: interface name eg: Ethernet1
    :param log_intf: logical interface eg: Vlan 10 or Portchannel 10
    :param add: bool value set to True (the default value) for configuring physical interface as
     member of logical interface else set to False to delete/de-configure .
    :return: bool value set to True if the config/unconfig was successful, or
     set to False otherwise.
    """
    no_string = ""
    cmd_str = ""

    if not add:
        no_string = "no "

    if log_intf.startswith("PortChannel"):
        list = log_intf.split()
        cmd_str = "interface {} \n".format(meb_intf)
        if not add:
            cmd_str += "{}channel-group \n".format(no_string)
        else:
            cmd_str += "channel-group {} \n".format(list[1])

    elif log_intf.startswith("Vlan"):
        log_intf = log_intf.replace('Vlan', 'Vlan ')
        cmd_str = "interface {} \n".format(meb_intf)
        cmd_str += "{}switchport trunk allowed {} \n".format(no_string,log_intf)
    else :
        st.log("logical interface not supported")
        return False

    try:
        output = st.config(dut, cmd_str, type='klish', skip_error_check=True)
        if re.search("Error", output):
            st.log("Failure executing cmds:\n" + cmd_str +
                   ": Error message: " + output)
            return False
        else:
            st.log("Succeeded configuring {} as member of {}.".format(meb_intf,log_intf))
            return True

    except ValueError as err_msg:
        st.log("Exception during configuring member interface:\n" +
               "Error message: " + str(err_msg))
        return False

def verify_ip_ipv6_routes(dut, intf, ipAddr, prefix, family, vrf_name):
    """
    Example invocation:
    # result = verify_ip_ipv6_routes(vars.D1, 'Ethernet1', '1.1.1.1', '24', 'ip' ,"mgmt")
    # result = verify_ip_ipv6_routes(vars.D1, 'Ethernet1', '2000::1', '24', 'ipv6' ,"mgmt")

    Verify ip/ipv6 routes are present for given vrf

    Parameters:

    :dut: Device under test
    :param intf: interface name eg: Ethernet1 or Vlan 10
    :param ipAddr: ip/ipv6 address to be configured eg: 1.1.1.1 or 2000::1
    :param prefix: is subnet mask eg 8, 24 etc
    :param family: specify ip or ipv6
    :param vrf_name: vrf name eg: mgmt
    :return: bool value set to True if the ip/ipv6 route present for vrf else
     set to False .
    """
    temp_name =""
    route = ""
    int_name = intf
    if int_name.startswith("PortChannel"):
        list = int_name.split()
        for i in list:
            temp_name += i
        int_name = temp_name
    if int_name == "eth0":
        int_name = "Management0"
    if family.lower() == "ip" :
        temp_ipAddr = ipAddr.split(".")
        st.log("temp_ipAddr = {}".format(temp_ipAddr))
        if int(prefix) < int("8") :
            route = "0.0.0.0/{}".format(prefix)
        elif int(prefix) < int("16") :
            route = "{}.0.0.0/{}".format(temp_ipAddr[0],prefix)
        elif int(prefix) < int("24") :
            route =  "{}.{}.0.0/{}".format(temp_ipAddr[0],temp_ipAddr[1],prefix)
        else :
            route = "{}.{}.{}.0/{}".format(temp_ipAddr[0],temp_ipAddr[1],temp_ipAddr[2],prefix)
    elif family.lower() == "ipv6" :
        temp_ipAddr = ipAddr.split("::")
        st.log("temp_ipAddr = {}".format(temp_ipAddr))
        route = "{}::/{}".format(temp_ipAddr[0],prefix)
    else :
        st.log("Unrecognized ip/ipv6 family : {}".format(family))
        return False


    st.log("route is {}".format(route))

    if family.lower() == "ip":
        cmd_str = "show ip route vrf {}".format(vrf_name)
    if family.lower() == "ipv6":
        cmd_str = "show ipv6 route vrf {}".format(vrf_name)

    try:
        output = st.show(dut, cmd_str , exec_mode='mgmt-user', type='klish', skip_error_check=True)
        st.log("####### show ip/ipv6 route vrf vrf_name ######")
        st.log(output)
        if output is None:
            st.log("Empty output executing {}".format(cmd_str))
            return False
        for result in output:
            if int_name in result['interface'] and route in result['ip_address']:
                st.log("{} Route present for interface {}".format(route,int_name))
                return True
        st.log("{} Route not present for interface {}".format(route,int_name))
        return False
    except ValueError as err_msg:
        st.log("Exception executing {}: Error "
               "message: {}".format(cmd_str, str(err_msg)))
        return False

def verify_ip_interface(dut,int_name,ipAddr,prefix,family,vrf_name="default"):
    """
    Example invocation:
    # result = verify_ip_interface(vars.D1, 'Ethernet1', '1.1.1.1', '24', 'ip' ,"mgmt")
    # result = verify_ip_interface(vars.D1, 'Ethernet1', '2000::1', '24', 'ipv6' ,"mgmt")

    verify ip/ipv6 assigned to particular vrf

    Parameters:

    :dut: Device under test
    :param intf: interface name eg: Ethernet1 or Vlan 10
    :param ipAddr: ip/ipv6 address to be configured eg: 1.1.1.1 or 2000::1
    :param prefix: is subnet mask eg 8, 24 etc
    :param family: specify ip or ipv6
    :param vrf_name: vrf name eg: mgmt
    :return: bool value set to True if the ip/ipv6 address present on interface for vrf else
     set to False .
    """
    temp_name = ""
    route = ""
    cmd_str = ""
    if int_name.startswith("PortChannel"):
        list = int_name.split()
        for i in list:
            temp_name += i
        int_name = temp_name
    if int_name == "eth0":
        int_name = "Management0"
    route = "{}/{}".format(ipAddr,prefix)
    cmd_str = "show {} interfaces".format(family)
    try:
        output = st.show(dut, cmd_str , exec_mode='mgmt-user', type='klish', skip_error_check=True)
        if output is None:
            st.log("Empty output executing {}".format(cmd_str))
            return False
        if vrf_name == "default":
            for result in output:
                if int_name in result['interface'] and route in result['ipaddr']:
                    st.log("{} address present for interface {} ".format(ipAddr, int_name))
                    return True
        else:
            for result in output:
                if int_name in result['interface'] and route in result['ipaddr'] and vrf_name in result['vrf']:
                    st.log("{} address present for interface {} in vrf {}".format(ipAddr, int_name, vrf_name))
                    return True

        st.log("{} address not present for interface {} in vrf {}".format(ipAddr, int_name, vrf_name))
        return False
    except ValueError as err_msg:
        st.log("Exception executing {}: Error "
               "message: {}".format(cmd_str, str(err_msg)))
        return False

def inband_mgmt_vrf_configure_vrfs (dut, vrf_list, add = True):
    """
    Example invocation:
    # result = inband_mgmt_vrf_configure_vrfs(vars.D1, ['Vrf1', 'Vrf2'])

    Attempt to configure or de-configure VRFs with the names specified by the
    input vrf_list.

    Parameters:

    :dut: Device under test
    :param vrf_list: List of VRF names (strings) to be configured or
     de-configured
    :param add: bool value set to True (the default value) to add/configure
     VRFs for the VRF names in the input vrf_list or set to False to
     delete/de-configure the VRFs.
    :return: bool value set to True if the add/delete was successful, or
     set to False if the add/delete failed.
    """
    vrf_cmd_string = ""
    no_string = ""
    cfg_type_string = "configuring"
    if not add:
        no_string = "no "
        cfg_type_string = "de-configuring"
    st.log("{} Mgmt VRF(s)".format(cfg_type_string))
    for vrf_name in vrf_list:
        vrf_cmd_string += "{}ip vrf {}\n".format(no_string, vrf_name)

    try:
        output = st.config(dut, vrf_cmd_string, type='klish', skip_error_check = True)
        if re.search("Error", output):
            st.log("Failure executing cmds:\n" + vrf_cmd_string +
                   ": Error message: " + output)
            return False

        st.log("Succeeded {} VRFs.".format(cfg_type_string))
        return True

    except ValueError as err_msg:
        st.log("Exception {} Mgmt VRF(s):\n"
               "Error message: {}".format(cfg_type_string, err_msg))
        return False

def check_ssh_login_from_dut(dut, ipaddr, username, password):
    """
    Example invocation:
    # result = check_ssh_login_from_dut(vars.D1, '1.1.1.1', 'admin' , 'YourPaSsWoRd')

    Attempt to do ssh from one switch to to another switch

    Parameters:

    :dut: Device under test
    :param ipaddr: ip address of interface or management ip : eg 1.1.1.1
    :param username: username to login into switch to which ssh to be done
    :param password: password of switch to which ssh to be done
    :return: bool value set to True if ssh is successful, or
     set to False otherwise.
    """
    cmd_str = "sshpass -p {} ssh {}@{}\n".format(password, username, ipaddr)
    try:
        output = st.config(dut, cmd_str, type='click')
        if re.search("%Error", output):
            st.log("Failure executing cmds:\n" + cmd_str +
                   ": Error message: " + output)
            return False
        else:
            st.log("Succeeded in SSH.")
            return True
    except ValueError as err_msg:
        st.log("Exception ssh to another device:\n" +
               "Error message: " + str(err_msg))
        return False

