from spytest import st

def set_timeouts(dut, default):
    if default:
        st.config(dut, "no serial timeout", on_cr_recover="retry5", exec_mode="fp-line-console-config")
        st.config(dut, "no terminal length", on_cr_recover="retry5")
    else:
        st.config(dut, "serial timeout 0", on_cr_recover="retry5", exec_mode="fp-line-console-config")
        st.config(dut, "terminal length 0", on_cr_recover="retry5")

def post_login(dut, **kwargs):
    set_timeouts(dut, False)

def post_session(dut):
    set_timeouts(dut, True)

def post_init_config(dut):
    st.log("TODO: post init config", dut=dut)

def post_reboot(dut, is_upgrade=False):
    st.log("TODO: post reboot", dut=dut)
    return False

def post_config_reload(dut):
    st.log("TODO: post config reload", dut=dut)

def init(dut, type="base"):
    if type == "base":
        if not st.get_args("skip_init_config"):
            st.config(dut, "clear config", expect_reboot=True, reboot_wait=30, confirm="y")
        set_timeouts(dut, False)
        st.config(dut, "no logging console", on_cr_recover="retry5", exec_mode="fp-config")
    gcov_config(dut)
    return True

def extend(dut, type="base"):
    st.log("TODO: extend {} config".format(type), dut=dut)
    return True

def verify(dut, type="base"):
    st.log("verify {} config if needed".format(type), dut=dut)
    return True

def _apply(dut):
    st.config(dut, "clear config", expect_reboot=True, reboot_wait=30, confirm="y",min_time=30)
    st.config(dut, "script list", on_cr_recover="ignore")
    st.config(dut, "script apply spytest-base-config.scr", on_cr_recover="retry5", confirm="y")
    return True

# phase 0: session init 1: module init 2: session clean
def apply(dut, phase):
    st.log("TODO: apply config phase: {}".format(phase), dut=dut)
    if phase in [0, 2]:
        return True

    if st.get_args("skip_load_config") in ["base"]:
        return True

    return _apply(dut)

def save(dut, type="base"):
    st.config(dut, "write memory confirm", on_cr_recover="retry5")
    cmd = "show running-config spytest-{}-config.scr".format(type)
    st.config(dut, cmd, on_cr_recover="retry5", confirm="y")
    return True

def clear(dut, **kwargs):
    return _apply(dut)

def gcov_config(dut):
    cmd = "devshell osapiGcovConfig(10.52.145.178, /root/FTPTest)"
    st.config(dut, cmd, exec_mode="fp-config")
