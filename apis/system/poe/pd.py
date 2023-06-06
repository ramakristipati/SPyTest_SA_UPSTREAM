#############################################################################
# API Title    : Configure and Show commands of PoE tester device (Reachtech)
# Author       : Venkat Moguluri
# Mail-id      : venkata.moguluri@broadcom.com
#############################################################################
#RT-PoE5>version
#Reach PoE Tester Model RT-PoE5/24
#PN 53-0005-11 Rev A 0/1, SW 1.01, Oct 18 2018
#Copyright (C) 2018 by Reach Technology, a Novanta Company
#RT-PoE5>
#############################################################################

from spytest import st


def pd_reset(dut):
    command="reset"
    return st.config(dut, command, sudo=False)

def pd_show_all(dut):
    command = "show all"
    output = st.show(dut, command, skip_tmpl=True)
    return st.parse_show(dut, command, output, "poe_show_all.tmpl")


def config_pd_interface(dut, iface, **kwargs):
    if 'single' in kwargs:
        command = "{} single {}".format(iface, kwargs['single'])
        st.config(dut, command, sudo=False)
    if 'pd_class' in kwargs:
        command = "{} class {}".format(iface, kwargs['pd_class'])
        st.config(dut, command, sudo=False)
    if 'detect' in kwargs:
        command = "{} detect {}".format(iface, kwargs['detect'])
        st.config(dut, command, sudo=False)
    if 'cap' in kwargs:
        command = "{} cap {}".format(iface, kwargs['cap'])
        st.config(dut, command, sudo=False)
    if 'set' in kwargs:
        command = "{} seti {}".format(iface, kwargs['set'])
        st.config(dut, command, sudo=False)
    if 'pwr' in kwargs:
        command = "{} pwr {}".format(iface, kwargs['pwr'])
        st.config(dut, command, sudo=False)
    if 'ext' in kwargs:
        command = "{} external {}".format(iface, kwargs['ext'])
        st.config(dut, command, sudo=False)
    if 'connect' in kwargs:
        command = "{} connect {}".format(iface, kwargs['connect'])
        st.config(dut, command, sudo=False)
    return True
