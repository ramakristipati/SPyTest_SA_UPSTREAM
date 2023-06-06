from spytest import st
from utilities.utils import get_interface_number_from_name

# Read bytes from the transceiver of the remote DUT
def cmis_read(dut, intf='Ethernet0', offset=0, length=1):
    bytes = []
    while len(bytes) < length:
        bytes.append(0)

    for _ in range(3):
        try:
            for i in range(length):
                cmd = "sudo sfputil dump -p {0} -s {1} -l 1".format(intf, offset + i)
                output = st.show(dut, cmd, skip_tmpl=True, type="click")
                bytes[i] = int(output.split()[2], 16)
            break
        except Exception as ex:
            st.log("cmis_read: parser failure: {0}".format(ex))

    return bytes

def config_intf_xcvr_diag(dut, intf, feat='loopback', mode='media-side-input', enable=True, **kwargs):

    '''
    :param dut:
    :param intf:
    :param feat:
        value: loopback (default)
    :param mode:
        value: <media-side-output|media-side-input|host-side-output|host-side-input>
    :param enable:
        value: <True|False>, default is True
    :param skip_error:
    :return:

    :mode
    :
    import apis.system.cmis as cmis_api
    cmis_api.config_intf_xcvr_diag(dut=data.dut1, intf='Ethernet17', mode='media-side-input')
    cmis_api.config_intf_xcvr_diag(dut=data.dut1, intf='Ethernet17', mode='media-side-input',enable=False)
    '''

    st.log('API: config_intf_xcvr_diag - DUT: {}, intf: {}, mode: {}, kwargs: {}'.format(dut, intf, mode, kwargs))

    #cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)

    intf_info = get_interface_number_from_name(intf)
    ret = ''
    if enable:
        cmd = 'interface transceiver diagnostics {0} {1} {2} {3}'.format(feat, mode, intf_info['type'], intf_info['number'])
    else:
        cmd = 'no interface transceiver diagnostics {0} {1} {2} {3}'.format(feat, mode, intf_info['type'], intf_info['number'])
    try:
        ret = st.config(dut, cmd, skip_error_check=skip_error, type="klish")
    except Exception as e:
        st.log(e)
        return False
    if 'Error' in ret:
        st.error("{0}".format(ret))
        return False
    return True


def get_intf_xcvr_diag_capability(dut, intf, **kwargs):

    '''
    :param dut:
    :param intf:
    :return:

    :mode
    :
    import apis.system.cmis as cmis_api
    cmis_api.config_intf_diagnostics(dut=data.dut1, intf='Ethernet17', mode='media-side-input')
    cmis_api.config_intf_diagnostics(dut=data.dut1, intf='Ethernet17', mode='media-side-input',enable=False)
    '''

    st.log('API: get_intf_xcvr_diag_capability - DUT: {}, intf: {}, kwargs: {}'.format(dut, intf, kwargs))

    #cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)

    intf_info = get_interface_number_from_name(intf)
    output = ''
    cmd = 'show interface transceiver diagnostics capability {0} {1}'.format(intf_info['type'], intf_info['number'])
    try:
        output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=skip_error, type="klish")
    except Exception as e:
        output = ''
        st.log(e)

    return output

def get_intf_xcvr_diag_status(dut, intf, **kwargs):

    '''
    :param dut:
    :param intf:
    :return:

    :mode
    :
    import apis.system.cmis as cmis_api
    cmis_api.config_intf_diagnostics(dut=data.dut1, intf='Ethernet17', mode='media-side-input')
    cmis_api.config_intf_diagnostics(dut=data.dut1, intf='Ethernet17', mode='media-side-input',enable=False)
    '''

    st.log('API: get_intf_xcvr_diag_status - DUT: {}, intf: {}, kwargs: {}'.format(dut, intf, kwargs))

    #cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)

    intf_info = get_interface_number_from_name(intf)
    output = ''
    cmd = 'show interface transceiver diagnostics status {0} {1}'.format(intf_info['type'], intf_info['number'])
    try:
        output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=skip_error, type="klish")
        #output = st.config(dut, cmd, skip_error_check=skip_error, type="klish")
    except Exception as e:
        output = ''
        st.log(e)

    return output
