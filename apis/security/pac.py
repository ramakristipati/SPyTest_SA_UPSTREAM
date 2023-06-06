from spytest import st
from utilities.utils import get_interface_number_from_name, segregate_intf_list_type, is_a_single_intf, get_supported_ui_type_list
from utilities.common import filter_and_select, make_list
import re
try:
    import apis.yang.codegen.messages.authmgr as umf_authmgr
    import apis.yang.codegen.messages.mab as umf_mab
    import apis.yang.codegen.messages.hostapd as umf_hostapd
    from apis.yang.utils.common import Operation
except ImportError:
    pass


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list()+['rest-patch', 'rest-put'] else cli_type
    return cli_type


def config_global_auth_params(dut, **kwargs):
    """
     Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:

    config_global_auth_params('dut1')
    config_global_auth_params('dut1',config='no')
    config_global_auth_params('dut1',mode='monitor')
    config_global_auth_params('dut1',mode='monitor',config='no')
    config_global_auth_params('dut1',mode='aaa',auth_type='radius')
    config_global_auth_params('dut1',mode='aaa',config='no')
    config_global_auth_params('dut1',mode='dot1x')
    config_global_auth_params('dut1',mode='dot1x',config='no')
    config_global_auth_params('dut1',mode='mab')
    config_global_auth_params('dut1',mode='mab',config='no')
    config_global_auth_params('dut1',mode='mab',group_size=2,separator=':',case='lowercase')
    config_global_auth_params('dut1',mode='mab',group_size=2,separator=':',case='lowercase',config='no')
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    mode = kwargs.pop('mode', None)
    cmd_list = []
    config = kwargs.pop('config', 'yes')
    config_cmd = '' if config == 'yes' else 'no'
    skip_error = kwargs.pop('skip_error_check', False)
    max_reauth = kwargs.pop('max_reauth', '')
    grp_size = kwargs.pop('group_size', None)
    separator = kwargs.pop('separator', None)
    case = kwargs.pop('case', None)
    if cli_type in ['click', 'rest-patch', 'rest-put']: cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        if mode == 'monitor':
            authmgr_obj = umf_authmgr.Authmgr()
            if config == 'yes':
                setattr(authmgr_obj, 'MonitorModeEnable', True)
                result = authmgr_obj.configure(dut, cli_type=cli_type)
            else:
                result = authmgr_obj.unConfigure(dut, target_attr=authmgr_obj.MonitorModeEnable, cli_type=cli_type)
        elif mode == 'dot1x':
            hostapd_obj = umf_hostapd.Hostapd()
            if config == 'yes':
                setattr(hostapd_obj, 'Dot1xSystemAuthControl', True)
                result = hostapd_obj.configure(dut, cli_type=cli_type)
            else:
                result = hostapd_obj.unConfigure(dut, target_attr=hostapd_obj.Dot1xSystemAuthControl, cli_type=cli_type)
        elif mode == 'mab':
            mab_obj = umf_mab.Mab()
            if config == 'yes':
                if grp_size:
                    setattr(mab_obj, 'GroupSize', grp_size)
                if separator:
                    setattr(mab_obj, 'Separator', separator)
                if case:
                    setattr(mab_obj, 'Case', case.upper())
                result = mab_obj.configure(dut, cli_type=cli_type)
            else:
                result = mab_obj.unConfigure(dut, target_path='mab-global-config', cli_type=cli_type)
        else:
            st.error('Provide valid option')
            return False
        if not result.ok():
            st.log('test_step_failed: Config PAC {}'.format(result.data))
            return False
        return True
    elif cli_type == 'klish':
        if not mode:
            cmd_list.append('{} authentication enable'.format(config_cmd))
        else:
            if mode == 'monitor':
                cmd_list.append('{} authentication monitor'.format(config_cmd))
            elif mode == 'max-reauth':
                cmd_list.append('{} authentication critical recovery max-reauth {}'.format(config_cmd, max_reauth))
            elif mode == 'dot1x':
                cmd_list.append('{} dot1x system-auth-control'.format(config_cmd))
            elif mode == 'mab':
                if config == 'no':
                    cmd_list.append('no mab request format attribute 1 ')
                else:
                    cmd = 'mab request format attribute 1'
                    if grp_size:
                        cmd += ' groupsize {}'.format(grp_size)
                    if separator:
                        cmd += ' separator {} '.format(separator)
                    if case:
                        cmd += case
                    cmd_list.append(cmd)
            elif mode == 'dynamic-vlan':
                cmd_list.append('{} authentication dynamic-vlan enable'.format(config_cmd))
        out = st.config(dut, cmd_list, type='klish', skip_error_check=skip_error)
        if 'Error' in out:
            return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_auth_noresponse_event(dut, intf_list, **kwargs):
    """
     Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    config_auth_noresponse_event('dut1',intf_list=['Ethernet10','Ethernet11'],vlan='10')
    config_auth_noresponse_event('dut1',intf_list=['Ethernet10','Ethernet11'],vlan='10',config='no')
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    vlan = kwargs.pop('vlan', '')
    config = kwargs.pop('config', 'yes')
    skip_error = kwargs.pop('skip_error_check', False)
    if cli_type in ['click', 'rest-patch', 'rest-put']: cli_type = 'klish'
    if type(intf_list) is not list: intf_list = [intf_list]

    if cli_type in get_supported_ui_type_list():
        try:
            for intf_item in intf_list:
                if config == 'yes':
                    authmgr_obj = umf_authmgr.Interface(Name=intf_item, GuestVlanId=vlan)
                    result = authmgr_obj.configure(dut, cli_type=cli_type)
                else:
                    authmgr_obj = umf_authmgr.Interface(Name=intf_item)
                    result = authmgr_obj.unConfigure(dut, target_attr=authmgr_obj.GuestVlanId, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Config PAC {}'.format(result.data))
                    return False
        except ValueError as exp:
            if skip_error:
                st.log('ValueError: {}'.format(exp))
                st.log('Negative Scenario: Errors/Expception expected')
                return False
            else:
                raise
        return True
    elif cli_type == 'klish':
        port_hash_list = segregate_intf_list_type(intf=intf_list, range_format=False)
        interface = port_hash_list['intf_list_all']
        cmd_list = list()
        for intf_item in interface:
            if not is_a_single_intf(intf_item):
                cmd_list.append('interface range {}'.format(intf_item))
            else:
                intf = get_interface_number_from_name(intf_item)
                cmd_list.append('interface {} {}'.format(intf['type'], intf['number']))
            if config == 'yes':
                cmd_list.append('authentication event no-response action authorize vlan {}'.format(vlan))
            else:
                cmd_list.append('no authentication event no-response action authorize vlan')
        cmd_list.append('exit')
        out = st.config(dut, cmd_list, type='klish', skip_error_check=skip_error)
        if 'Error' in out:
            return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_auth_fail_event(dut, intf_list, **kwargs):
    """
     Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    config_auth_fail_event('dut1',intf_list=['Ethernet10','Ethernet11'],max_attempts=[3,5])
    config_auth_fail_event('dut1',intf_list=['Ethernet10','Ethernet11'],vlan=30)
    config_auth_fail_event('dut1',intf_list=['Ethernet10','Ethernet11'],max_attempts=[3,5],config='no')
    config_auth_fail_event('dut1',intf_list=['Ethernet10','Ethernet11'],vlan=30,config='no')
    config_auth_fail_event('dut1',intf_list='Ethernet10',guest_vlan=30,config='yes')
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    vlan = kwargs.get('vlan', '')
    config = kwargs.get('config', 'yes')
    skip_error = kwargs.pop('skip_error_check', False)
    if cli_type in ['click', 'rest-patch', 'rest-put']: cli_type = 'klish'
    if type(intf_list) is not list: intf_list = [intf_list]
    retry = kwargs.get('max_attempts', '')
    guest_vlan = kwargs.get('guest_vlan')

    if cli_type in get_supported_ui_type_list():
        pac_attr = {'vlan': ['AuthFailVlanId', vlan if vlan else None], 'guest_vlan': ['GuestVlanId', guest_vlan if guest_vlan else None]}
        try:
            for intf_item in intf_list:
                authmgr_obj = umf_authmgr.Interface(Name=intf_item)
                if config == 'yes':
                    for key, attr_value in pac_attr.items():
                        if key in kwargs and attr_value[1] is not None:
                            setattr(authmgr_obj, attr_value[0], attr_value[1])
                    result = authmgr_obj.configure(dut, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Config PAC {}'.format(result.data))
                        return False
                else:
                    for key, attr_value in pac_attr.items():
                        if key in kwargs and attr_value[1] is not None:
                            target_attr = getattr(authmgr_obj, attr_value[0])
                            result = authmgr_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: Config PAC {}'.format(result.data))
                                return False
        except ValueError as exp:
            if skip_error:
                st.log('ValueError: {}'.format(exp))
                st.log('Negative Scenario: Errors/Expception expected')
                return False
            else:
                raise
        return True
    elif cli_type == 'klish':
        port_hash_list = segregate_intf_list_type(intf=intf_list, range_format=False)
        interface = port_hash_list['intf_list_all']
        cmd_list = list()
        for intf_item in interface:
            if not is_a_single_intf(intf_item):
                cmd_list.append('interface range {}'.format(intf_item))
            else:
                intf = get_interface_number_from_name(intf_item)
                cmd_list.append('interface {} {}'.format(intf['type'], intf['number']))

            if vlan:
                if config == 'yes':
                    cmd_list.append('authentication event fail action authorize vlan {}'.format(vlan))
                else:
                    cmd_list.append('no authentication event fail action authorize vlan')
            if retry:
                if config == 'yes':
                    cmd_list.append('authentication event fail retry {}'.format(retry))
                else:
                    cmd_list.append('no authentication event fail retry')
            if guest_vlan:
                if config == 'yes':
                    cmd_list.append('authentication event no-response action authorize vlan {}'.format(guest_vlan))
                else:
                    cmd_list.append('no authentication event no-response action authorize vlan')

        cmd_list.append('exit')
        out = st.config(dut, cmd_list, type='klish', skip_error_check=skip_error)
        if 'Error' in out:
            return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_auth_server_event(dut, intf_list, **kwargs):
    """
    Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:

    config_auth_server_event('dut1',intf_list=['Ethernet10','Ethernet11','Ethernet12'], event ='dead', action='reinitialize',vlan='10')
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    event = kwargs.pop('event', 'dead')
    action = kwargs.pop('action', '')
    vlan = kwargs.pop('vlan', '')
    config = kwargs.pop('config', 'yes')
    skip_error = kwargs.pop('skip_error_check', False)
    if cli_type in ['click', 'rest-patch', 'rest-put']: cli_type = 'klish'
    if type(intf_list) is not list: intf_list = [intf_list]
    if cli_type == 'klish':
        port_hash_list = segregate_intf_list_type(intf=intf_list, range_format=False)
        interface = port_hash_list['intf_list_all']
        cmd_list = list()
        for intf_item in interface:
            if not is_a_single_intf(intf_item):
                cmd_list.append('interface range {}'.format(intf_item))
            else:
                intf = get_interface_number_from_name(intf_item)
                cmd_list.append('interface {} {}'.format(intf['type'], intf['number']))
            if config == 'yes':
                cmd = 'authentication event server {} action '.format(event)
                if vlan:
                    cmd += 'vlan {}'.format(vlan)
                else:
                    cmd += action
                cmd_list.append(cmd)
            else:
                cmd_list.append('no authentication event server {} action'.format(event))
        cmd_list.append('exit')
        out = st.config(dut, cmd_list, type='klish', skip_error_check=skip_error)
        if 'Error' in out:
            return False
        return True


def config_auth_intf_params(dut, intf_list, cmd_type_list, **kwargs):
    """
    Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param interface:
    :param kwargs:
    :return:

    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='max-users',max_users=11)
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='port-control',port_control='force-unauath)
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='host-mode',host_mode='single-host')
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='reauth-timer',reauth_timer=10)
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='dot1x-server-timeout',dot1x_server_timeout=300)
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='auth-order',auth_order='dot1x mab')
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='auth-priority',auth_priority='mab dot1x')
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='periodic')
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='open')
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='mab',mab_auth_type='pap')
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='mab')
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list='mab-server-timeout',mab_server_timeout=300)
    config_auth_intf_params(dut='dut1',intf_list=['Ethernet10','Ethernet11'],cmd_type_list=['max-users','port-control','host-mode','reauth-timer],
       max_users=11,port_control='force-unauth',host_mode='sngle-host',reauth_timer=12)
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.pop('config', 'yes')
    skip_error = kwargs.pop('skip_error_check', False)
    if cli_type in ['click', 'rest-patch', 'rest-put']: cli_type = 'klish'
    config_cmd = 'no' if config == 'no' else ''
    if type(intf_list) is not list: intf_list = [intf_list]
    max_users = kwargs.pop('max_users', None)
    port_control = kwargs.pop('port_control', None)
    host_mode = kwargs.pop('host_mode', None)
    reauth_timer = kwargs.pop('reauth_timer', None)
    auth_order = kwargs.pop('auth_order', None)
    auth_priority = kwargs.pop('auth_priority', None)
    mab_authtype = kwargs.pop('mab_auth_type', None)
    pae = kwargs.pop('pae', 'authenticator')
    dot1x_quiet_period = kwargs.pop('dot1x_quiet_period', None)
    dot1x_server_timeout = kwargs.pop('dot1x_server_timeout', '30')
    mab_server_timeout = kwargs.pop('mab_server_timeout', '30')
    if type(cmd_type_list) is not list: cmd_type_list = [cmd_type_list]
    flag = "true" if config == 'yes' else "false"

    if cli_type in get_supported_ui_type_list():
        operation = Operation.UPDATE
        authmgr_obj = umf_authmgr.Authmgr()
        port_hash_list = segregate_intf_list_type(intf=intf_list, range_format=False)
        interface = port_hash_list['intf_list_all']
        pac_attr_list ={'dot1x_pae':['PortPaeRole',pae.upper() if pae else None],
                        'max-users':['MaxUsersPerPort', int(max_users) if max_users else None],
                        'port-control':['PortControlMode',port_control.upper().replace('-','_') if port_control else None],
                        'host-mode': ['HostControlMode',host_mode.upper().replace('-','_') if host_mode else None],
                        'reauth-timer':['ReauthPeriod',int(reauth_timer) if reauth_timer else None],
                        'dot1x-quiet-period': ['QuietPeriod', int(dot1x_quiet_period) if dot1x_quiet_period else None],
                        'dot1x-server-timeout':['ServerTimeout',int(dot1x_server_timeout) if dot1x_server_timeout else 30],
                        'auth-order':['MethodList',[i.upper() for i in auth_order.split(" ")] if auth_order else None],
                        'auth-priority':['PriorityList',[i.upper() for i in auth_priority.split(" ")] if auth_priority else None],
                        'mab':['MabEnable',flag],
                        'mab-server-timeout':['ServerTimeout',int(mab_server_timeout) if mab_server_timeout else 30],
                        'periodic':['ReauthEnable',flag],
                        'open':['OpenAuthenticationMode',flag],
                        }
        for intf_item in interface:
            auth_intf_obj = umf_authmgr.Interface(Name=intf_item,Authmgr=authmgr_obj)
            if config == 'yes':
                try:
                    for key, attr_value in pac_attr_list.items():
                        if key in cmd_type_list and attr_value[1] is not None:
                                if key in ['mab', 'mab-server-timeout']:
                                    mab_obj = umf_mab.Mab()
                                    mab_intf_obj = umf_mab.Interface(Name=intf_item, Mab=mab_obj)
                                    if mab_authtype:
                                        setattr(mab_intf_obj, attr_value[0], attr_value[1])
                                        setattr(mab_intf_obj, 'MabAuthType', mab_authtype.upper())
                                    else:
                                        setattr(mab_intf_obj, attr_value[0], attr_value[1])
                                    result = mab_intf_obj.configure(dut,operation=operation,cli_type=cli_type)
                                elif key == 'dot1x_pae':
                                    operation = Operation.CREATE
                                    setattr(auth_intf_obj, attr_value[0], attr_value[1])
                                    result = auth_intf_obj.configure(dut,operation=operation,cli_type=cli_type)
                                else:
                                    setattr(auth_intf_obj, attr_value[0], attr_value[1])
                                    result = auth_intf_obj.configure(dut,cli_type=cli_type)
                                if not result.ok():
                                    st.log('test_step_failed: PAC Interface config {}'.format(result.data))
                                    return False
                except ValueError as exp:
                    if skip_error:
                        st.log('ValueError: {}'.format(exp))
                        st.log('Negative Scenario: Errors/Expception expected')
                        return False
                    else:
                        raise
            else:
                def_val_dict = {'auth-order': ['DOT1X', 'MAB'], 'auth-priority': ['DOT1X', 'MAB'], 'reauth-timer': 3600,
                                'host-mode': 'MULTI_HOST', 'port-control': 'AUTO'}
                param_with_no_value = 0
                for key, attr_value in pac_attr_list.items():
                    if key in cmd_type_list and key in def_val_dict and attr_value[1] is None:
                        attr_value[1] = def_val_dict[key]
                    if key in cmd_type_list and attr_value[1] is not None:
                        param_with_no_value += 1
                        if key =='mab':
                            mab_obj = umf_mab.Mab()
                            mab_intf_obj = umf_mab.Interface(Name=intf_item, Mab=mab_obj)
                            for attr in ['MabEnable', 'MabAuthType', 'ServerTimeout']:
                                target_attr = getattr(mab_intf_obj, attr)
                                result = mab_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                                if not result.ok():
                                    st.log('test_step_failed: PAC Interface config  {}'.format(result.data))
                                    return False
                        else:
                            target_attr = getattr(auth_intf_obj, attr_value[0])
                            result = auth_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: PAC Interface config  {}'.format(result.data))
                                return False
                if param_with_no_value == 0:
                    result = auth_intf_obj.unConfigure(dut, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: PAC Interface config  {}'.format(result.data))
                        return False
        return True
    if cli_type == 'klish':
        port_hash_list = segregate_intf_list_type(intf=intf_list, range_format=False)
        interface = port_hash_list['intf_list_all']
        cmd_list = list()

        for intf_item in interface:
            if not is_a_single_intf(intf_item):
                cmd_list.append('interface range {}'.format(intf_item))
            else:
                intf = get_interface_number_from_name(intf_item)
                cmd_list.append('interface {} {}'.format(intf['type'], intf['number']))
            for cmd_type in cmd_type_list:
                if cmd_type == 'max-users':
                    if config == 'yes':
                        cmd_list.append('authentication max-users {}'.format(max_users))
                    else:
                        cmd_list.append('no authentication max-users')
                elif cmd_type == 'port-control':
                    if config == 'yes':
                        cmd_list.append('authentication port-control {}'.format(port_control))
                    else:
                        cmd_list.append('no authentication port-control')
                elif cmd_type == 'host-mode':
                    if config == 'yes':
                        cmd_list.append('authentication host-mode {}'.format(host_mode))
                    else:
                        cmd_list.append('no authentication host-mode')
                elif cmd_type == 'reauth-timer':
                    if config == 'yes':
                        cmd_list.append('authentication timer reauthenticate {}'.format(reauth_timer))
                    else:
                        cmd_list.append('no authentication timer reauthenticate')
                elif cmd_type == 'auth-order':
                    if config == 'yes':
                        cmd_list.append('authentication order {}'.format(auth_order))
                    else:
                        cmd_list.append('no authentication order')
                elif cmd_type == 'auth-priority':
                    if config == 'yes':
                        cmd_list.append('authentication priority {}'.format(auth_priority))
                    else:
                        cmd_list.append('no authentication priority')
                elif cmd_type == 'mab':
                    if mab_authtype and config == 'yes':
                            cmd_list.append('mab auth-type {}'.format(mab_authtype))
                    else:
                        cmd_list.append('{} mab '.format(config_cmd))
                elif cmd_type == 'mab-server-timeout':
                    if config =='yes':
                        cmd_list.append('mab timeout server-timeout {}'.format(mab_server_timeout))
                    else:
                        cmd_list.append('{} mab timeout server-timeout'.format(config_cmd))
                elif cmd_type == 'dot1x_pae':
                    if config == 'yes':
                        cmd_list.append('dot1x pae {}'.format(pae))
                    else:
                        cmd_list.append('no dot1x pae')
                elif cmd_type == 'dot1x-quiet-period':
                    if config =='yes':
                        cmd_list.append('dot1x timeout quiet-period {}'.format(dot1x_quiet_period))
                    else:
                        cmd_list.append('{} dot1x timeout quiet-period'.format(config_cmd))
                elif cmd_type == 'dot1x-server-timeout':
                    if config =='yes':
                        cmd_list.append('dot1x timeout server-timeout {}'.format(dot1x_server_timeout))
                    else:
                        cmd_list.append('{} dot1x timeout server-timeout'.format(config_cmd))
                elif cmd_type == 'mab-server-timeout':
                    if config == 'yes':
                        cmd_list.append('mab timeout server-timeout {}'.format(mab_server_timeout))
                    else:
                        cmd_list.append('no mab timeout server-timeout')
                elif cmd_type == 'periodic':
                    cmd_list.append('{} authentication periodic'.format(config_cmd))
                elif cmd_type == 'open':
                    cmd_list.append('{} authentication open'.format(config_cmd))
                else:
                    st.error("Incorrect cmd_type passed {}".format(cmd_type))
        cmd_list.append('exit')
        out = st.config(dut, cmd_list, type='klish', skip_error_check=skip_error)
        if 'Error' in out:
            return False
        return True


def clear_dot1x_stats(dut, **kwargs):
    """
    Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.pop('skip_error_check', False)
    if cli_type in ['click', 'rest-patch', 'rest-put']: cli_type = 'klish'
    interface = kwargs.pop('interface', None)
    if cli_type == 'klish':
        cmd = "clear dot1x statistics "
        if interface:
            intf = get_interface_number_from_name(interface)
            cmd += 'interface {} {}'.format(intf['type'], intf['number'])
        out = st.config(dut, cmd, type='klish', skip_error_check=skip_error, conf=False)
        if 'Error' in out:
            return False
        return True


def show_authentication(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    cmd = "show authentication"
    result = st.show(dut, cmd, type=cli_type)
    return result


def verify_authentication(dut, **kwargs):
    """
    Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    """
    parsed_output = show_authentication(dut, **kwargs)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return parsed_output
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}: Expected - {} Actual - {} ".format(each, kwargs[each],
                                                                                   parsed_output[0][each]))
            return False
    return True


def show_authentication_interface(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    interface = kwargs.get('interface', None)
    if not interface:
        cmd = 'show authentication interface all'
    else:
        intf = get_interface_number_from_name(interface)
        cmd = 'show authentication interface {} {}'.format(intf['type'], intf['number'])
    output = st.show(dut, cmd, type=cli_type)
    return output


def verify_authentication_interface(dut, **kwargs):
    """
    Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    """
    ret_val = True
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        interface = make_list(kwargs.get('interface')) if kwargs.get('interface') else None
        port_control_mode = kwargs.get('port_control_mode').upper().replace('-', '_') if kwargs.get('port_control_mode') else None
        host_mode = kwargs.get('host_mode').upper().replace('-', '_') if kwargs.get('host_mode') else None
        open_auth_dict = {'Disabled': 'false', 'Enabled': 'true'}
        open_auth = open_auth_dict[kwargs.get('open_auth')] if kwargs.get('open_auth') else None
        auth_order_configured = [i.upper() for i in kwargs.get('auth_order_configured').split(" ")] if kwargs.get('auth_order_configured') else None
        auth_order_enabled = [i.upper() for i in kwargs.get('auth_order_enabled').split(" ")] if kwargs.get('auth_order_enabled') else None
        auth_priority_configured = [i.upper() for i in kwargs.get('auth_priority_configured').split(" ")] if kwargs.get('auth_priority_configured') else None
        auth_priority_enabled = [i.upper() for i in kwargs.get('auth_priority_enabled').split(" ")] if kwargs.get('auth_priority_enabled') else None
        reauth = kwargs.get('reauth', None)
        reauth_session_timeout_from_server = kwargs.get('reauth_session_timeout_from_server', None)
        reauth_period = kwargs.get('reauth_period', None)
        max_users = kwargs.get('max_users', None)
        guest_vlan = kwargs.get('guest_vlan', None)
        unauthenticated_vlan = kwargs.get('unauthenticated_vlan', None)
        authmgr_obj = umf_authmgr.Authmgr()
        auth_intf_check_dict ={'port_control_mode':['PortControlMode',port_control_mode],
                               'host_mode':['HostControlMode',host_mode],
                               'open_auth':['OpenAuthenticationMode',open_auth],
                               'auth_order_configured':['MethodList',auth_order_configured],
                               'auth_order_enabled':['EnabledMethodList',auth_order_enabled],
                               'auth_priority_configured':['PriorityList',auth_priority_configured],
                               'auth_priority_enabled':['EnabledPriorityList',auth_priority_enabled],
                               'reauth':['ReauthEnable',reauth.lower() if reauth else None],
                               'reauth_session_timeout_from_server':['ReauthPeriodFromServer',reauth_session_timeout_from_server],
                               'reauth_period':['ReauthPeriod',int(reauth_period) if reauth_period else None],
                               'max_users':['MaxUsersPerPort',int(max_users) if max_users else None],
                               'guest_vlan':['GuestVlanId',int(guest_vlan) if guest_vlan else None],
                               'unauthenticated_vlan':['AuthFailVlanId',int(unauthenticated_vlan) if unauthenticated_vlan else None]
        }
        auth_ifname_obj=None
        verify_attr=None
        verify_attr_val=None
        output=None
        for itf_each in interface:
            auth_intf_obj = umf_authmgr.Interface(Name=itf_each, Authmgr=authmgr_obj)
            for key, attr_value in auth_intf_check_dict.items():
                if key in kwargs and attr_value[1] is not None:
                    if key in ['auth_order_enabled','auth_priority_enabled']:
                        auth_ifname_obj = umf_authmgr.Ifname(Name=itf_each,Authmgr=authmgr_obj)
                        setattr(auth_ifname_obj, attr_value[0], attr_value[1])
                        if attr_value[0] == 'EnabledMethodList':
                            verify_attr='enabled-method-list'
                        elif attr_value[0] == 'EnabledPriorityList':
                            verify_attr = 'enabled-priority-list'
                        verify_attr_val = attr_value[1]
                    else:
                        setattr(auth_intf_obj, attr_value[0], attr_value[1])
            if auth_ifname_obj and verify_attr:
                result = auth_ifname_obj.get_payload(dut, target_path='state/{}'.format(verify_attr), cli_type=cli_type)
                if result:
                    output = result.payload
                else:
                    st.log('test_step_failed: Verify Authentication interface output')
                if not output['openconfig-authmgr:{}'.format(verify_attr)] == verify_attr_val:
                    st.log('test_step_failed: Verify Authentication interface output {}'.format(result.payload))
                    return False
            if auth_intf_obj:
                result = auth_intf_obj.verify(dut, target_path='state', match_subset=True, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Verify Authentication interface output {}'.format(result.data))
                    return False

    elif cli_type == 'klish':
        output = show_authentication_interface(dut, **kwargs)
        if len(output) == 0:
            st.error("Output is Empty")
            return False

        if 'return_output' in kwargs:
            return output

        kwargs = convert_kwargs_to_list(**kwargs)

        # convert kwargs into list of dictionary
        input_dict_list = []
        for i in range(len(kwargs[list(kwargs.keys())[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if not entries:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False
    return ret_val


def show_authentication_clients(dut, option, **kwargs):
    """

    :param dut:
    :param mac_addr:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    interface = kwargs.get('interface', None)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if option == 'all':
        cmd = 'show authentication clients all'
    elif option == 'interface':
        intf = get_interface_number_from_name(interface)
        cmd = 'show authentication clients {} {}'.format(intf['type'], intf['number'])

    output = st.show(dut, cmd, type=cli_type)
    return output


def verify_authentication_clients(dut, mac_addr, **kwargs):
    """
    Author:Sooriya.Gajendrababu@broadcom.com
    verify_authentication_clients(dut,mac_addr=['00:00:00:71:00:11','00:00:00:81:00:12'],option='all', interface=['Ethernet1','Ethernet6'], method='802.1x')
    verify_authentication_clients(dut,mac_addr=['00:00:00:44:00:01'],option='interface', interface=['Ethernet1'], user_name='User11', host_mode='single_host')
    :param dut:
    :param kwargs:
    :return:
    """
    ret_val = True
    mac_addr = make_list(mac_addr)
    option = kwargs.pop('option', 'interface')
    interface = kwargs.get('interface', None)
    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type in get_supported_ui_type_list():
        if interface is None:
            cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        kwargs = convert_kwargs_to_list(**kwargs)
        username = kwargs.get('username', kwargs.get('user_name', None))
        host_mode = kwargs.get('host_mode')
        interface = make_list(kwargs.get('interface', None))
        method = kwargs.get('method', None)
        control_mode = kwargs.get('control_mode', None)
        session_time = kwargs.get('session_time', None)
        session_timeout = kwargs.get('session_timeout', None)
        time_left_termination = kwargs.get('time_left_termination', None)
        termination_action_dict = {'Default': 0, 'RADIUS': 1}
        termination_action = kwargs.get('termination_action')
        dynamic_acl = kwargs.get('dynamic_acl', None)
        redirect_acl = kwargs.get('redirect_acl', None)
        redirect_url = kwargs.get('redirect_url', None)
        vlan_assigned_reason = kwargs.pop('vlan_assigned_reason', None)
        if vlan_assigned_reason:
            vlan_type = []
            vlan_id = []
            for v_entry in vlan_assigned_reason:
                vlan_assigned_reason_li = re.findall(r'^([A-Za-z]+)\s*\((\d+)\)$', v_entry)
                vlan_type.append(vlan_assigned_reason_li[0][0])
                vlan_id.append(vlan_assigned_reason_li[0][1])
            kwargs.update({"vlan_type": vlan_type})
            kwargs.update({"vlan_id": vlan_id})
        vlan_type = kwargs.get('vlan_type', None)
        vlan_id = kwargs.get('vlan_id', None)
        interface = interface * len(mac_addr) if len(mac_addr) != len(interface) else interface
        for index, mac in enumerate(mac_addr):
            if dynamic_acl and dynamic_acl[index] == 'None': dynamic_acl[index] = str()
            if redirect_acl and redirect_acl[index] == 'None': redirect_acl[index] = str()
            if redirect_url and redirect_url[index] == 'None': redirect_url[index] = str()
            intf = interface[index]
            authmgr_obj = umf_authmgr.Authmgr()
            auth_clientbase_dict = {'username': ['UserName', username[index] if username else None],
                                    'host_mode': ['HostControlMode', host_mode[index].upper().replace('-', '_') if host_mode else None],
                                    'vlan_type': ['VlanType', vlan_type[index].upper() if vlan_type else None],
                                    'vlan_id': ['VlanId', int(vlan_id[index]) if vlan_id else None],
                                    'method': ['AuthenticatedMethod', method[index].upper() if method else None],
                                    'control_mode': ['PortControlMode', control_mode[index].upper() if control_mode else None],
                                    'session_time': ['SessionTime', session_time[index] if session_time else None],
                                    'session_timeout': ['SessionTimeout', session_timeout[index] if session_timeout else None],
                                    'time_left_termination': ['TerminationActionTimeLeft', time_left_termination[index] if time_left_termination else None],
                                    'termination_action': ['TerminationAction', termination_action_dict[termination_action[index]] if termination_action else None],
                                    'dynamic_acl': ['DaclName', dynamic_acl[index] if dynamic_acl is not None else None],
                                    'redirect_acl': ['RedirectAclName', redirect_acl[index] if redirect_acl is not None else None],
                                    'redirect_url': ['RedirectUrl', redirect_url[index] if redirect_url is not None else None]}

            auth_intf_obj=None
            auth_client_obj = umf_authmgr.AuthenticatedClient(Name=intf, Macaddress=mac, Authmgr=authmgr_obj)
            for key, attr_value in auth_clientbase_dict.items():
                if key in kwargs and attr_value[1] is not None:
                    if key in ['host_mode','control_mode']:
                        auth_intf_obj = umf_authmgr.Interface(Name=intf, Authmgr=authmgr_obj)
                        setattr(auth_intf_obj, attr_value[0], attr_value[1])
                    else:
                        setattr(auth_client_obj,attr_value[0],attr_value[1])
            if auth_intf_obj:
                result = auth_intf_obj.verify(dut, target_path='state', match_subset=True, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Verify Authentication Clients output {}'.format(result.data))
                    return False
            if auth_client_obj:
                result = auth_client_obj.verify(dut,match_subset=True,cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Verify Authentication Clients output {}'.format(result.data))
                    return False
    elif cli_type == 'klish':
        output = show_authentication_clients(dut, option, **kwargs)
        if len(output) == 0:
            st.error("Output is Empty")
            return False

        if 'return_output' in kwargs:
            return output

        kwargs = convert_kwargs_to_list(**kwargs)
        keys_len = len(mac_addr) if len(mac_addr) > 0 else 1
        kwargs.update({"interface": [interface] * keys_len})
        kwargs.update({"mac_addr": mac_addr})
        # convert kwargs into list of dictionary
        input_dict_list = []
        for i in range(len(kwargs[list(kwargs.keys())[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                if key != 'interface':
                    temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if not entries:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False
            else:
                st.log("DUT {} -> Match Found {}".format(dut, input_dict))
    return ret_val


def show_dot1x(dut, option, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    interface = kwargs.get('interface', None)
    if option is None:
        cmd = "show dot1x"
    elif option == 'all':
        cmd = "show dot1x detail all"
    elif option == 'interface':
        intf = get_interface_number_from_name(interface)
        cmd = 'show dot1x detail {} {}'.format(intf['type'], intf['number'])
    output = st.show(dut, cmd, type=cli_type)
    return output


def verify_dot1x(dut, **kwargs):
    """
    Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    """
    option = kwargs.pop('option', None)
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        admin_mode = kwargs.get('admin_mode', None)
        interface = make_list(kwargs.get('interface')) if kwargs.get('interface') else None
        pae_capabilities = kwargs.get('pae_capabilities', None)
        authmgr_obj = umf_authmgr.Authmgr()
        hostapd_obj = umf_hostapd.Hostapd()
        if option is None:
            setattr(hostapd_obj, 'Dot1xSystemAuthControl', admin_mode)
            result = hostapd_obj.verify(dut, target_path='hostapd-global-config/state',match_subset=True,cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Verify Authentication output {}'.format(result.data))
                return False
        elif option == 'interface' or option == 'all':
            for intf_item in interface:
                auth_intf_obj = umf_authmgr.Interface(Name=intf_item, Authmgr=authmgr_obj)
                setattr(auth_intf_obj, 'PortPaeRole', pae_capabilities.upper())
                result = auth_intf_obj.verify(dut, target_path='state/port-pae-role', match_subset=True,cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Verify Authentication output {}'.format(result.data))
                    return False
    elif cli_type == 'klish':
        parsed_output = show_dot1x(dut, option, **kwargs)
        if len(parsed_output) == 0:
            st.error("OUTPUT is Empty")
            return False

        if 'return_output' in kwargs:
            return parsed_output
        for each in kwargs.keys():
            match = {each: kwargs[each]}
            entries = filter_and_select(parsed_output, None, match)
            if not entries:
                st.error("Match not found for {}: Expected - {} Actual - {} ".format(each, kwargs[each],parsed_output[0][each]))
                return False
    return True


def show_mab(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    interface = make_list(kwargs.get('interface')) if kwargs.get('interface') else None
    if not interface or len(interface) > 1:
        cmd = 'show mab'
    else:
        intf = get_interface_number_from_name(interface[0])
        cmd = 'show mab interface {} {}'.format(intf['type'], intf['number'])
    output = st.show(dut, cmd, type=cli_type)
    return output


def verify_mab(dut, **kwargs):
    """
    Author:Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    """

    ret_val = True
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        interface = make_list(kwargs.get('interface')) if kwargs.get('interface') else None
        groupsize = kwargs.get('groupsize', None)
        separator = kwargs.get('separator', None)
        case = kwargs.get('case', None)
        mab_obj = umf_mab.Mab()
        if not interface:
            setattr(mab_obj, 'GroupSize', int(groupsize) if groupsize else None)
            setattr(mab_obj, 'Separator', re.findall(r":|-|\.", separator)[0] if separator else None)
            setattr(mab_obj, 'Case', case.upper() if case else None)
            result = mab_obj.verify(dut, target_path='mab-global-config/state', match_subset=True, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Verify mab output {}'.format(result.data))
                return False
        else:
            kwargs = convert_kwargs_to_list(**kwargs)
            admin_mode = kwargs.get('admin_mode')
            auth_type = kwargs.get('auth_type', None)
            for index, intf in enumerate(interface):
                mab_intf_obj = umf_mab.Interface(Name=intf, Mab=mab_obj)
                setattr(mab_intf_obj, 'MabEnable', 'true' if admin_mode[index] == 'Enabled' else 'false' if admin_mode else None)
                setattr(mab_intf_obj, 'MabAuthType', auth_type[index].replace('-','_').upper() if auth_type else None)
                result = mab_intf_obj.verify(dut,target_path='state',match_subset=True, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Verify mab output {}'.format(result.data))
                    return False

    elif cli_type == 'klish':
        output = show_mab(dut, **kwargs)
        if len(output) == 0:
            st.error("Output is Empty")
            return False

        if 'return_output' in kwargs:
            return output
        interface = kwargs.get('interface', None)
        if not interface:
            common_param = ['groupsize', 'separator', 'case']
            for key in common_param:
                if key in kwargs:
                    if str(kwargs[key]) != str(output[0][key]):
                        st.error("Match not Found for {}: Expected - {} Actual- {}".format(key, kwargs[key], output[0][key]))
                        ret_val = False
                    else:
                        st.log("Match Found for {}: Expected - {} Actual- {}".format(key, kwargs[key], output[0][key]))
                    del kwargs[key]
        else:
            kwargs = convert_kwargs_to_list(**kwargs)

            # convert kwargs into list of dictionary
            input_dict_list = []
            for i in range(len(kwargs[list(kwargs.keys())[0]])):
                temp_dict = {}
                for key in kwargs.keys():
                    if key == 'auth_type':
                        temp_dict[key] = kwargs[key][i].replace('-','_').upper()
                    else:
                        temp_dict[key] = kwargs[key][i]
                input_dict_list.append(temp_dict)

            for input_dict in input_dict_list:
                entries = filter_and_select(output, None, match=input_dict)
                if not entries:
                    st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                    ret_val = False
    return ret_val


def show_authentication_history(dut, option, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    interface = kwargs.get('interface', None)
    if option == 'all':
        cmd = 'show authentication authentication-history all'
    else:
        intf = get_interface_number_from_name(interface)
        cmd = 'show authentication authentication-history {} {}'.format(intf['type'], intf['number'])
    output = st.show(dut, cmd, type=cli_type)
    return output


def verify_authentication_history(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    ret_val = True
    option = kwargs.pop('option', 'all')
    output = show_authentication_history(dut, option, **kwargs)
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    kwargs = convert_kwargs_to_list(**kwargs)

    # convert kwargs into list of dictionary
    input_dict_list = []
    for i in range(len(kwargs[list(kwargs.keys())[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output, None, match=input_dict)
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            ret_val = False
    return ret_val


def get_authentication_clients(dut, mac_addr, **kwargs):
    """
    Author: naveen.kumaraketi@broadcom.com
    verify_authentication_clients(dut,mac_addr=['00:00:00:71:00:11','00:00:00:81:00:12'],option='all', interface=['Ethernet1','Ethernet6'], method='802.1x')
    verify_authentication_clients(dut,mac_addr=['00:00:00:44:00:01'],option='interface', interface=['Ethernet1'], user_name='User11', host_mode='single_host')
    :param dut:
    :param kwargs:
    :return:
    """
    ret_val = []
    mac_addr = make_list(mac_addr)
    option = kwargs.pop('option', 'interface')
    match_key = kwargs.pop('key', None)
    interface = kwargs.get('interface', None)
    output = show_authentication_clients(dut, option, **kwargs)
    if len(output) == 0:
        st.error("Output is Empty")
        return ret_val
    if 'return_output' in kwargs:
        return output
    kwargs = convert_kwargs_to_list(**kwargs)
    keys_len = len(mac_addr) if len(mac_addr) > 0 else 1
    kwargs.update({"interface": [interface] * keys_len})
    kwargs.update({"mac_addr": mac_addr})
    # convert kwargs into list of dictionary
    input_dict_list = []
    for i in range(len(kwargs[list(kwargs.keys())[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            if key != 'interface':
                temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)
    for input_dict in input_dict_list:
        entries = filter_and_select(output, None, match=input_dict)
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            return ret_val
        if match_key is not None:
            ret_val.append(entries[0][match_key])
        else:
            ret_val.append(entries[0])
    return ret_val


def convert_kwargs_to_list(**kwargs):
    # Converting all kwargs to list
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    return kwargs


def clear_authentication(dut, **kwargs):
    """
    Author:naveen.kumaraketi@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.pop('skip_error_check', False)
    interface = kwargs.get('interface', None)
    clear_type = kwargs.get('clear_type', 'sessions')
    if cli_type in ['click', 'rest-patch', 'rest-put']: cli_type = 'klish'
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type == 'klish':
        if interface:
            intf = get_interface_number_from_name(interface)
            cmd = "clear authentication {} interface {} {}".format(clear_type, intf['type'],intf['number'])
        else:
            cmd = "clear authentication {} interface all".format(clear_type)
        out = st.config(dut, cmd, type='klish', skip_error_check=skip_error,conf=False)
        if 'Error' in out:
            return False
        return True
