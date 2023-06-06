import re
import os
import sys
from collections import OrderedDict

from spytest import st
from apis.common import fastpath_config as config

from utilities import common as utils

class FastpathHooks(object):

    def get_vars(self, dut, phase=None):
        if phase:
            st.banner("get_vars({}-{})".format(dut, phase))

        retval = dict()
        try:
            #output = st.show(dut, "show version")
            output = st.show(dut, "devsh taDebugSysInfo")
            retval["version"] = output[0]["version"]
        except:
            st.warn("Failed to read version", dut=dut)
        return retval

    def is_kdump_supported(self, dut):
        return False

    def pre_load_image(self, dut):
        return False

    def post_cli_recovery(self, scope, dut, cmd, attempt=0):
        # scope is session/module/function
        # return True to bail-out, False to ignore, None to retry
        return True

    def post_reboot(self, dut, is_upgrade=False):
        return config.post_reboot(dut, is_upgrade)

    def post_config_reload(self, dut):
        return config.post_config_reload(dut)

    def post_login(self, dut, **kwargs):
        return config.post_login(dut, **kwargs)

    def post_session(self, dut):
        return config.post_session(dut)

    def init_config(self, dut, type, hwsku=None, profile="na"):
        return config.init(dut, type)

    def extend_config(self, dut, type, ifname_type="none"):
        return config.extend(dut, type)

    def verify_config(self, dut, type):
        return config.verify(dut, type)

    def save_config(self, dut, type):
        return config.save(dut, type)

    def apply_config(self, dut, phase):
        return config.apply(dut, phase)

    def clear_config(self, dut, **kwargs):
        kwargs.setdefault("on_cr_recover", "retry5")
        return config.clear(dut, **kwargs)

    def shutdown(self, dut, portlist):
        st.config(dut, "shutdown", exec_mode='fp-intf-config', interface=",".join(portlist))
        return True

    def noshutdown(self, dut, portlist):
        st.config(dut, "no shutdown", exec_mode='fp-intf-config', interface=",".join(portlist))
        return True

    def get_status(self, dut, port_csv):
        st.log("TODO: get_status {}".format(port_csv), dut=dut)
        return {}

    def get_interface_status(self, dut, port_csv):
        retval = self.get_status(dut, port_csv)
        return retval[0]["oper"] if retval else None

    def show_version(self, dut, **kwargs):
        kwargs.setdefault("on_cr_recover", "retry5")
        return st.show(dut, "devsh taDebugSysInfo", **kwargs)

    def get_system_status(self, dut, service=None, **kwargs):
        return True

    def verify_topology(self, hooks, check_type, threads=True, skip_tgen=False):
        from apis.common import checks
        return checks.verify_topology(hooks, check_type, threads, skip_tgen)

    # breakout = ["0/1", "4x10G", "0/2", "4x10G"]
    def set_port_defaults(self, dut, breakout, speed):
        rv1, rv2 = True, True
        if breakout:
            for x in range(0,len(breakout),2):
                command = "hardware profile portmode {}".format(breakout[x+1])
                rv1 = st.config(dut, command, exec_mode='fp-intf-config', interface=breakout[x])
        if speed:
            st.log("TODO: set_port_defaults-speed {}".format(speed), dut=dut)
        return bool(rv1 and rv2)

    def clear_logging(self, dut, **kwargs):
        pass

    def fetch_syslogs(self, dut, severity=None, since=None):
        pass

    def ifa_enable(self, dut):
        pass

    def ztp_disable(self, dut, **kwargs):
        pass

    def kdump_enable(self, dut):
        return True

    def upgrade_image(self, dut, url, max_time=1800, skip_error_check=False, migartion=True):
        ui = utils.parse_url(url)
        cmd = "copy ftp://{}@{}{} backup".format(ui["user"], ui["ip"], ui["path"])
        output = st.config(dut, cmd, on_cr_recover="retry5",
                           confirm=[["Remote Password:", ui["pwd"]], [".*(y/n)", "y"]])
        if "File transfer operation completed successfully" in output:
            st.config(dut, "copy backup active")
            st.config(dut, "boot system backup")
            return "success"
        return "error"

    def set_mgmt_ip_gw(self, dut, ipmask, gw, **kwargs):
        pass

    def get_mgmt_ip(self, dut, interface, **kwargs):
        cmd = "show serviceport"
        kwargs.setdefault("on_cr_recover", "retry5")
        output = st.show(dut, cmd, **kwargs)
        ipaddr = output[0]['ip_address']
        return ipaddr

    def renew_mgmt_ip(self, dut, interface, **kwargs):
        st.log("TODO: renew_mgmt_ip {}".format(interface), dut=dut)

    def upgrade_libsai(self, dut, url):
        pass

    def get_ifname_type(self, dut):
        return st.get_ifname_type(dut)

    def set_ifname_type(self, dut, ifname_type):
        pass

    def get_physical_ifname_map(self, dut):
        cmd = "devsh 'taDebugPortInfo All,PHYSICAL'"
        entries = st.show(dut, cmd)
        retval = OrderedDict()
        for entry in entries:
            interface = entry.get("interface")
            retval[interface] = interface
        return retval

    def debug_system_status(self, dut, log_file=None):
        pass

    def dut_reboot(self, dut, **kwargs):
        st.config(dut, "write memory confirm")
        kwargs["max_time"] = kwargs.pop("max_time", 1000)
        kwargs["min_time"] = kwargs.pop("min_time", 30)
        kwargs["skip_error_check"] = True
        kwargs["expect_reboot"] = True
        output = st.config(dut, "reload", confirm=[[".*(y/n)", "y"]], **kwargs)
        return output

    def get_onie_grub_config(self, dut, mode):
        return "", []

    def init_features(self, fgroup, fsupp=None, funsupp=None):
        from apis.common.fastpath_features import Feature
        return Feature(fgroup, fsupp, funsupp)

    def init_support(self, hooks, cfg, dut=None):
        from apis.common.support import Support
        return Support(hooks, cfg, dut)

    def init_prompts(self, model=None, logger=None, normal_user_mode=None):
        from apis.common.fastpath_prompts import Prompts
        return Prompts("fastpath", logger, normal_user_mode)

    def exec_ssh_remote_dut(self, dut, ipaddress, username, password, command=None, timeout=30, **kwargs):
        pass

    def verify_prompt(self, dut, prompt):
        regex_onie_resque = r"\s+Please press Enter to activate this console.\s*$"
        prompt = prompt.replace("\\", "")
        if re.compile(r"\(Unit \d+\)>\s*$").match(prompt):
            st.wait(5)
            return False, True
        if "Applying Global configuration, please wait ..." in prompt:
            st.wait(1)
            return False, True
        if "Applying Interface configuration, please wait ..." in prompt:
            st.wait(1)
            return False, True
        if re.compile(r"(.*[#|>]\s*$)").match(prompt):
            return True, False
        if re.compile(r".*\(config.*\)#\s*$").match(prompt):
            return True, False
        if re.compile(r"\S+\s+login:\s*$").match(prompt):
            return True, False
        if re.compile(r"User:\s*$").match(prompt):
            return True, False
        if re.compile(r"[Pp]assword:\s*$").match(prompt):
            return True, False
        if re.compile(r"Enter old password:\s*$").match(prompt):
            return True, False
        if re.compile(r"Enter new password:\s*$").match(prompt):
            return True, False
        if re.compile(r"^\s*ONIE:/ #\s*$").match(prompt):
            return True, False
        if re.compile(r"^\s*grub rescue>\s*$").match(prompt):
            return True, False
        if re.compile(regex_onie_resque).match(prompt):
            return True, False
        if re.compile(r"\(dhcp-\d+-\d+-\d+-\d+\)\s*[#|>]\s*$").match(prompt):
            return True, False
        if re.compile(r"\(localhost\)\s*[#|>]\s*$").match(prompt):
            return True, False
        if re.compile(r"\(Broadcom FASTPATH Routing\)\s*[#|>]\s*$").match(prompt):
            return True, False
        if re.compile(r"\(Routing\)\s*[#|>]\s*$").match(prompt):
            return True, False
        if re.compile(r"Closing console session. Press ^c in \d+s to exit").match(prompt):
            return True, False
        if re.compile(r"^\s*admin\@localhost\:\~\$$").match(prompt):
            return True, False
        if re.compile(r"^\s*root\@localhost\:\/home\/admin#$").match(prompt):
            return True, False
        return False, False

    def get_base_prompt(self, dut, **kwargs):
        prompts=[]
        prompts.append(r"dhcp-\d+-\d+-\d+-\d+")
        prompts.append("localhost")
        prompts.append("Broadcom FASTPATH Routing")
        prompts.append("Routing")
        return "|".join(prompts)

    def get_hostname(self, dut, **kwargs):
        output = st.show(dut, "devsh taDebugSysInfo", **kwargs)
        return output[0]["hostname"]

    def set_hostname(self, dut, name):
        pass

    def verify_device_info(self, dut, phase):
        return True

    def dump_config_db(self, dut):
        pass

    def show_sai_profile(self, dut):
        pass

    def is_reboot_confirm(self, dut):
        return False

    def show_dut_time(self, dut):
        pass

    def gnmi_cert_config_ensure(self, dut):
        pass

    def get_mode(self, dut, which):
        if which == "normal-user":
            return "fp-priv-user"
        return "unknown-mode"

    def get_regex(self, dut, which, *args):
        if which == "sudopass":
            return None
        if which == "login":
            return r"(User|\S+\s+login):\s*$"
        if which == "login_anywhere":
            return r"User:\s*"
        if which == "anyprompt":
            if st.get_device_type(dut) in ["icos"]:
                return r"[#|>|\$]\s*$"
            return r"[#|>]\s*$"
        return "unknown"

    def get_default_pass(self, dut):
        return ""

    def get_templates_info(self, dut, model):
        model = "fastpath" if model != "sonic" else model
        #return "fp_templates", model
        return "templates", model

    def get_custom_ui(self, dut):
        return "click"

    def get_cli_type_record(self, dut, cli_type):
        file_name = sys._getframe(5).f_code.co_filename
        file_name = os.path.basename(file_name)
        func_name = sys._getframe(5).f_code.co_name
        return "{}::{},{}".format(file_name, func_name, cli_type)

    def verify_ui_support(self, dut, cli_type, cmd):
        return cli_type

    def audit(self, atype, dut, *args, **kwargs):
        return None

    def read_syslog(self, dut, lvl, phase, name):
        return ""

    def read_core(self, dut, name):
        return ""

    def read_tech_support(self, dut, name):
        return ""

    def read_sysinfo(self, dut, scope, name):
        return {}

    def get_command(self, dut, which, *args):
        if which == "reboot":
            if st.get_device_type(dut) in ["icos"]:
                return "reload os", "y"
            return "reboot", None
        return None, None

    def check_kdump_files(self, dut):
        return False

    def clear_kdump_files(self, dut):
        return False

    def check_core_files(self, dut):
        return False

    def clear_core_files(self, dut):
        return False

    def save_config_db(self, dut, scope, name):
        return False

    def save_running_config(self, dut, scope, name):
        return False

    def verify_config_replace(self, dut, scope, res, desc):
        return res, desc

    def verify_command(self, dut, cmd, cli_type):
        return cmd

