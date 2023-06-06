
import re

from spytest import st
from utilities.common import filter_and_select

def config_pim_global_mgmt (dut, vrf, **kwargs):
    """
    Example invocation:

    # config_pim_global_mgmt(data.dut1, 'Vrf_pim3', config='yes', **cmd_dict)

    Apply pim configuration commands for the specified VRF.

    Inputs and keyword parameters:

    :param dut: Device under test
    :param vrf: name of the VRF for which configuration is to be applied
    :param config: String set to 'yes' to apply configuration; 'no' to remove it
    :param jp_interval: string specifying the jp interval value
    :param keepalive_time: string specifying the keepalive timer value
    :param ecmp: set to 'ecmp' to enable ecmp
    :param ecmp_rebalance: set to 'ecmp rebalance' to enable ecmp rebalance
    :param ssm_range_prefix: name of an SSM range prefix list
    :param rp_address: set rpaddress with the specified IP value
    :param spt_switchover: set spt_switchover value
    :return: Output from configuration command execution
    """
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        no_str = ""
    else:
        no_str = 'no '

    if vrf == 'default':
        vrf_str = ""
    else:
        vrf_str = ' vrf ' + vrf

    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0

    cmd_batch = ""
    val_str = ""
    if 'jp_interval' in kwargs:
        if no_str == "":
            val_str = kwargs['jp_interval']
        cmd_batch += (no_str + 'ip pim' + vrf_str + ' join-prune-interval ' +
                      val_str + '\n')

    if 'keepalive_time' in kwargs:
        if no_str == "":
            val_str = kwargs['keepalive_time']
        cmd_batch += (no_str + 'ip pim' + vrf_str + ' keep-alive-timer ' +
                      val_str + '\n')

    if no_str == 'no ':
        # Execute the "no" form of "ecmp rebalance" before possible executing
        # the "no" form of "ecmp".
        if 'ecmp_rebalance' in kwargs:
            cmd_batch += no_str + 'ip pim' + vrf_str + ' ecmp rebalance \n'
        if 'ecmp' in kwargs:
            cmd_batch += no_str + 'ip pim' + vrf_str + ' ecmp \n'
    else:
        if 'ecmp' in kwargs:
            cmd_batch += no_str + 'ip pim' + vrf_str + ' ecmp \n'
        if 'ecmp_rebalance' in kwargs:
            cmd_batch += no_str + 'ip pim' + vrf_str + ' ecmp rebalance \n'

    if 'ssm_range_prefix' in kwargs:
        if no_str == "":
            val_str = kwargs['ssm_range_prefix']
        cmd_batch += (no_str + 'ip pim' + vrf_str + ' ssm prefix-list ' +
                      val_str + '\n')

    if 'rp_address' in kwargs:
        val_str = kwargs['rp_address']
        if 'rp_prefix_list' in kwargs:
             val_str2 = kwargs['rp_prefix_list']
             if no_str == "":
                 cmd_batch += (no_str + 'ip pim' + vrf_str + ' rp-address ' +
                      val_str + ' prefix-list ' + val_str2 + '\n')
             else:
                 cmd_batch += (no_str + 'ip pim' + vrf_str + ' rp-address ' +
                      val_str + '\n')
        else:
             cmd_batch += (no_str + 'ip pim' + vrf_str + ' rp-address ' +
                      val_str + '\n')

    if 'spt_switchover' in kwargs:
        val_str = kwargs['spt_switchover']
        if 'spt_prefix_list' in kwargs:
             val_str2 = kwargs['spt_prefix_list']
             if no_str == "":
                 cmd_batch += (no_str + 'ip pim ' + vrf_str + ' spt-threshold ' +
                      val_str + ' prefix-list ' + val_str2 + '\n')
             else:
                 cmd_batch += (no_str + 'ip pim ' + vrf_str + ' spt-threshold ' +
                      val_str + '\n')
        else:
             cmd_batch += (no_str + 'ip pim ' + vrf_str + ' spt-threshold ' +
                      val_str + '\n')


    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, cmd_batch, type='klish',
                     skip_error_check=skip_error, max_time=maxtime)

def config_pim_intf_mgmt(dut, intf, **kwargs):
    """
    Example invocation:

    config_pim_intf_mgmt(data.dut1, intf='Ethernet 4', config='yes', **cmd_dict)

    Apply pim configuration commands for the specified interface.

    Inputs and keyword parameters:

    :param dut: Device under test
    :param intf: Interface to be configured
    :param config: bool value: True to apply configuration; False to remove it
    :param pim_mode: PIM mode enabled on the interface
    :param dr_priority: string specifying the designated router priority
    :param hello_intvl: string specifying the Hello interval
    :param bfd_enable: (value ignored; enable bfd)
    :return: Output from configuration command execution
    """

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        no_str = ""
    else:
        no_str = "no "

    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0

    cmd_batch = ""
    skip_error = bool(kwargs.get('skip_error', False))
    cmd_batch += 'interface {}\n'.format(intf)

    if ('pim_mode' in kwargs):
        cmd_batch += '{} ip pim {}\n'.format(no_str, kwargs['pim_mode'])

    if 'hello_intvl' in kwargs:
        if (no_str == ""):
            cmd_batch += 'ip pim hello {}\n'.format(kwargs['hello_intvl'])
        else:
            cmd_batch += 'no ip pim hello\n'

    if 'dr_priority' in kwargs:
        if (no_str == ""):
            cmd_batch += 'ip pim drpriority {}\n'.format(kwargs['dr_priority'])
        else:
            cmd_batch += 'no ip pim drpriority\n'

    if 'bfd_enable' in kwargs:
        cmd_batch += '{} ip pim bfd\n'.format(no_str)

    cmd_batch += "exit\n"
    output = st.config(dut, cmd_batch, type='klish',
                       skip_error_check=skip_error, max_time=maxtime)

    return output

def check_pim_output (output, chk_dict):
    """
    Utility "filter_and_select" function wrapper to check an output dictionary
    array for the key/value pairs specified by the input chk_dict.

    Inputs and keyword parameters:

    :param output: Array of dictionaries created by parsing output of "show"
     commands through a TextFSM template.
    :param chk_dict: Dictionary specifying key/value pairs to check for in
     each of the elements of the output array.
    :return: Return an array of each of the "output" dictionary entries that
     match the key/value pairs specified by the "chk_dict" dictionary
     if the check is successful. Otherwise, return None.
     """

    result = filter_and_select(output, None, chk_dict)
    if result is None:
        st.log("Output validation failed.")
        return None

    match_count = len(result)
    chk_count = len(chk_dict)
    if match_count > 0:
        st.log("Output successfully validated: {} values "
               "checked; {} entries "
               "matched." .format(chk_count, match_count))

    else:
        st.log("Output validation failed: {} entries "
               "checked, "
               "{} entries matched.".format(chk_count, match_count))
        st.log("chk_dict = {}".format(chk_dict))
        st.log("output = {}".format(output))

        return None

    return output


def verify_pim_global_mgmt(dut, cfg_vrf, output=None, show_type='vtysh',
                           skip_verify=False, pim=False, **vrf_parms):
    """

    Verify pim configuration commands for the specified VRF.

    Example invocation:

    verify_pim_global_mgmt(data.dut1, cfg_vrf='Vrf_pim3', **cfg_parm_dict)

    Inputs and keyword parameters:

    :param dut: Device under test
    :param cfg_vrf: name of the VRF for which configuration is to be verified
    :param output: cached result from previous "show running-configuration"
     command execution
    :param show_type: Optional string set to 'vtysh' or 'klish' (defaulted to
     'vtysh') to specify the source of the "show configuration" information
     to be used for the verification.
    :param vrf_parms: Dictionary specifying expected configuration
     attributes and values
    :param skip_verify: bool value set to True to skip verification. This
     is used to obtain raw output. It can, for example be used to obtain
     output for use in later verification checks on individual configuration
     values.
    :return: matching output from "show running-configuration" if verification
     is successful. (Otherwise, this return parameter is set to None.)
    """

    if ((cfg_vrf == 'default') and (show_type == 'vtysh')):
        vrf_str = ""
    else:
        vrf_str = cfg_vrf

    if 'skip_error' in vrf_parms:
        skip_error = vrf_parms['skip_error']
    else:
        skip_error = False

    if show_type == 'vtysh':
        show_str = "show running-config pimd"
    elif show_type == 'klish':
        if pim is False:
           show_str = "show running-configuration"
        else:
           show_str = "show running-configuration pim"
    else:
        st.log("Invalid configuration 'show' type {} specified for PIM "
               "global configuration verification.".format(show_type))
        return None

    if output is None:
        output = []
        output = st.show(dut, show_str,
                         skip_error_check=skip_error, type=show_type)
        if ((output is None) or (output == [])):
            st.log("PIM configuration is empty.")
            return None

    # Return the output and skip verification if requested.
    if skip_verify:
        st.log("Skipping output verification: Returning raw output.")
        return output

    # If the first output record is for an interface,
    # no global configuration was found: return None.
    if output[0]['interface'] != '':
        return None

    # Verify the configuration values for the target VRF.

    # For vtysh, verify all configuration for the VRF in one pass.
    # This is possible because all configuration items for a VRF are
    # contained in a single output array dictionary.
    if show_type == 'vtysh':
        chk_dict = vrf_parms
        chk_dict.update(pim_vrf=vrf_str)
        output = check_pim_output(output, chk_dict)
        if output is None:
            st.log("Failed to find expected values in 'show configuration' "
                   "output.")
            return None

    # Klish handling: Separate each configuration item in its own
    # check dictionary because the output contains a separate array
    # element dictionary for each command in a VRF.

    else:

        for chk_key, chk_value in vrf_parms.items():
            chk_dict = {chk_key : chk_value}
            chk_dict.update(vrf=vrf_str)

            output = check_pim_output(output, chk_dict)
            if output is None:
                st.log("Failed to find '{}' == '{}' in 'show configuration' "
                       "output.".format(chk_key, chk_value))
                return None

    st.log("Successfully found all specified values in output.")
    return output

def intf_dict_is_null(chk_dict):
    for key,value in chk_dict.items():
        if ((key != 'interface') and (value != '')):
            return False
    return True

def verify_pim_intf_mgmt (dut, intf, output=None, show_type='vtysh',
                          skip_verify=False, **intf_parms):
    """

    Verify pim configuration commands for the specified interface.

    Example invocation:

    verify_pim_intf_mgmt(data.dut1, intf='Ethernet 4', **cfg_parm_dict)

    Inputs and keyword parameters:

    :param dut: Device under test
    :param intf: name of the interface for which configuration is to be verified
    :param output: cached result from previous "show running-configuration"
     command execution
    :param show_type: Optional string set to 'vtysh', 'klish', 'klish_intf',
     or 'klish_intf_cfg' (defaulted to 'vtysh') to specify the source of
     the "show configuration" information to be used for the verification.
    :param skip_verify: bool value set to True to skip verification. This
     is used to obtain raw output. It can, for example be used to obtain
     output for use in later verification checks on individual configuration
     values.
    :parm intf_parms: Dictionary specifying expected configuration
     attributes and values
    :return: matching output from "show running-configuration" if verification
     is successful. (Otherwise, this return parameter is set to None.)
    """

    intf_nospc = re.sub(r"(PortChannel|Ethernet|Eth|Management|Vlan)(\s*)([\d\/\.]+)", "\\1\\3",
                        intf)

    if 'skip_error' in intf_parms:
        skip_error = intf_parms['skip_error']
    else:
        skip_error = False

    if show_type == 'vtysh':
        show_str = "show running-config pimd"
        type_parm = 'vtysh'
    elif show_type == 'klish':
        show_str = "show running-configuration"
        type_parm = 'klish'
    elif show_type == 'klish_intf':
        if "." in intf:
            show_str = "show running-configuration subinterface {}".format(intf)
        else:
            show_str = "show running-configuration interface {}".format(intf)
        type_parm = 'klish'
    elif show_type == 'klish_intf_cfg':
        show_str_pfx = "interface {}\n".format(intf)
        show_str = show_str_pfx + "show configuration"
        type_parm = 'klish'
    else:
        st.log("Invalid configuration 'show' type {} specified for PIM "
               "interface configuration verification.".format(show_type))
        return None

    if output is None:
        output = []
        if show_type == 'klish_intf_cfg':
            # Obtain raw output by sending the "show" command via the st.config
            # API (to enable execution of the "show" command from within
            # interface configuration mode). Use the st.parse_show API to
            # invoke the template for 'show configuration' to parse the output.
            output = st.config(dut, show_str,
                               skip_error_check=skip_error, type='klish')
            if ((output is not None) and (output != [])):
                output = st.parse_show(dut, "show configuration", output)
        else:
            output = st.show(dut, show_str,
                             skip_error_check=skip_error, type=type_parm)
        if ((output is None) or (output == [])):
            st.log("PIM configuration is empty.")
            return None

    # Return the output and skip verification if requested.
    if skip_verify:
        st.log("Skipping output verification: Returning raw output.")
        return output

    # Find the dictionary for the target interface in the 'show' output
    # and verify that the output values match the expected values.
    chk_dict = intf_parms

    if (('klish' in show_type) and
        ('PortChannel' in intf)): 
        chk_ifname = intf
    else:
        # FIXME: Shouldn't PortChannel output have the same format as the
        # others?
        chk_ifname = intf_nospc
    chk_dict.update(interface=chk_ifname)

    # Skip detailed checking of output if the expected output fields
    # are NULL and no entry for the target interface is present in the output.
    # This is a correct result.
    if ((intf_dict_is_null(chk_dict)) and
        (not interface_in_dict_array(chk_ifname, output))):
        st.log("Successfully verified absence of PIM configuration "
               "for interface {}".format(intf))
        return None

    matched_output = check_pim_output(output, chk_dict)
    if (matched_output is None):
        st.log("Failed to find expected values in 'show configuration' "
               "output.")
        return None

    st.log("Successfully found all specified values in output.")

    return matched_output

def pim_mgmt_show (dut, cmd_str, vrf=None, mroute=False, **kwargs):
    """
    Example invocation:

    # output = pim_mgmt_show(vars.D1, "topology 233.7.6.5", "Vrf_blue")

    Execute the specified PIM "show" command and return the output.

    Inputs and keyword parameters:

    :param dut: Device under test
    :param cmd_str: PIM specific "show" command and arguments
    :param vrf: (optional) name of the VRF for which the "show" command is
     to be executed; If not specified, the command is executed for the
     default VRF.
    :param mroute: bool value (defaulted to False) set if the command is an
     mroute show command. Otherwise, the command is assumed to be a
     PIM show command.
    :kwargs Keyord arguments to pass to the low level "show" command.
    :return: Output from show command execution (or None if an error occurs).
    """

    # Initialize sub-strings for the command to be sent.
    if vrf is not None:
        vrf_str = " vrf {}".format(vrf)

    # Set up the command string, appending needed sub-strings.
    if mroute:
        full_cmd = "show ip mroute"
    else:
        full_cmd = "show ip pim"

    if  vrf is not None:
        full_cmd += vrf_str
    if cmd_str is not None:
        full_cmd += " " + cmd_str
    full_cmd += " | no-more"

    try:
        output = st.show(dut, full_cmd, exec_mode='mgmt-user', **kwargs)
        if output is None:
            st.log("Empty output executing {}".format(full_cmd))
            return None

        if not isinstance(output, list):
            if re.search("Error", output):
                st.log("Failure executing {}. Error "
                       "message: {}".format(full_cmd, output))
            else:
                st.log("Failure executing {}: wrong output format. "
                       "Output: {}".format(full_cmd, output))
            return None
        else:
            st.log("Succeeded executing {}".format(full_cmd))

    except ValueError as err_msg:
        st.log("Exception executing {}: Error "
               "message: {}".format(full_cmd, str(err_msg)))
        return None

    return output

def pim_mgmt_clear (dut, cmd_str, vrf=None, mroute=False):
    """
    Example invocation:

    # result = pim_mgmt_clear(vars.D1, "interfaces", "Vrf_blue")

    Execute the specified PIM/mroute "clear" command and return the output.

    Inputs and keyword parameters:

    :param dut: Device under test
    :param cmd_str: PIM specific "clear" command and arguments
    :param vrf: (optional) name of the VRF for which the "clear" command is
     to be executed; If not specified, the command is executed for the
     default VRF.
    :param mroute: bool value (defaulted to False) set if the command is an
     mroute clear command. Otherwise, the command is assumed to be a
     PIM clear command.
    :return: bool value set to True for successful execution or False for
     failure
    """

    # Initialize sub-strings for the command to be sent.
    if vrf is not None:
        vrf_str = " vrf {} ".format(vrf)

    # Set up the command string, appending needed sub-strings.
    if mroute:
        full_cmd = "clear ip mroute"
    else:
        full_cmd = "clear ip pim"

    if  vrf is not None:
        full_cmd += vrf_str
    if cmd_str is not None:
        full_cmd += " " + cmd_str

    try:
        output = st.config(dut, full_cmd, type='klish', conf=False)
        if output is None:
            st.log("Empty output executing {}".format(full_cmd))
            return False

        if re.search("Error", output):
            st.log("Failure executing {}. Error "
                   "message: {}".format(full_cmd, output))
            return False
        else:
            st.log("Succeeded executing {}".format(full_cmd))

    except ValueError as err_msg:
        st.log("Exception executing {}: Error "
               "message: {}".format(full_cmd, str(err_msg)))
        return False

    return True

def pim_execute_bgp_restart(dut):
    """
    :param dut: Device under test
    :return: bool indication set to True if successful
    """

    cmd = "service bgp restart"
    try:
        output = st.show(dut, cmd, exec_mode='root-user', skip_tmpl=True)
        if output is None:
            st.log("Empty output executing 'service bgp restart.")
            return False

        if re.search("Error", output):
            st.log("Failure executing 'service bgp restart: "
                   "Error message: " + output)
            return False
        else:
            st.log("Succeeded executing 'service bgp restart'")

    except ValueError as err_msg:
        st.log("Exception executing 'service bgp restart': "
               "Error message: " + str(err_msg))
        return False

    st.log("Waiting for 'system ready' after BGP restart")
    ready = False
    retries_remaining = 10
    while ((not ready) and (retries_remaining > 0)):
        st.wait(10)
        output = st.show(dut, "show system status", exec_mode='root-user',
                         skip_tmpl=True)
        if (re.search("System is ready", output)):
            ready = True
            break

        retries_remaining -= 1

    if not ready:
        st.log("Timed out waiting for System Ready after BGP restart")
        return False

    st.log("System ready after BGP restart.")
    return True

def interface_in_dict_array (ifname, dict_array):

    """
    Determine if any of the entries in the input dictionary array
    contain an "interface" entry (key) with a value matching the
    input ifname.

    :param ifname: String specifying the interface name to be searched
     for in the input dictionary array.
    :param dict_array: Array of dictionaries to be searched.
    :return: bool value set to True if a dictionary entry matching
     the input ifname is found in the input ditionary array or False
     if the input ifname is not found in the input dictionary array.
    """

    for dict_entry in dict_array:
        if (('interface' in dict_entry.keys()) and
            (dict_entry['interface'] == ifname)):
            return True

    return False
