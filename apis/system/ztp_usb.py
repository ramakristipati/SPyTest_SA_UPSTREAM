# This file contains the list of API's for operations on ZTP over USB

from spytest import st

from apis.system.boot_up import get_onie_grub_config as get_onie_grub_config_impl
import apis.system.connection as conn_obj
import apis.system.ztp as ztp_oper_api

from utilities.common import filter_and_select,make_list

def usb_enable(dut, config_type="yes", **kwargs):
    cli_type=st.get_ui_type(dut, **kwargs)
    no_form = "enable" if config_type == "yes" else "disable"
    if cli_type == "click":
        command = "config usb {}".format(no_form)
    else:
        command = "usb enable" if config_type == "yes" else "no usb"
    st.config(dut, command, type=cli_type)
    return True

def usb_mount(dut,mount = "yes", **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "click":
        command = "usbmount-helper mount" if mount == "yes" else "usbmount-helper umount"
    else:
        command = "usb mount" if mount == "yes" else "usb un-mount"
    st.config(dut, command, type=cli_type)
    return True

def usb_format(dut, type, format_type=None, device_type=None, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    format_type= "vfat" if not format_type else format_type
    device_type = "/dev/sdb" if not device_type else device_type
    if type == 'format':
        command = "usbmount-helper format {} {}".format(device_type,format_type)
    elif type == 'partition':
        command = "usbmount-helper partition {} ".format(device_type)
    st.config(dut, command, type=cli_type)
    return True

def get_mount_path(dut,**kwargs):
    result = show_usb_status(dut, type='status')
    for output in result:
        if output.get("mount_dir"):
            mount_path = output.get("mount_dir")
            usb_dir = (output.get("mount_dir").replace("/media/", "dir "))+':/'
            usb_num = output.get("mount_dir").replace("/media/", "")
            break
    if kwargs.get('return_output'):
        return mount_path,usb_dir,usb_num
    return True

def set_boot_mode_onie_install(dut, **kwargs):
    if kwargs.get('unset_onie_mode'):
        cmd_to_check_next_entry_status = "sudo grub-editenv /host/grub/grubenv list"
        onie_status = "next_entry=ONIE"
        result = st.config(dut, cmd_to_check_next_entry_status, faster_cli=False)
        st.log("Found next entry as {}".format(result))
        if onie_status in result:
            cmd_for_unset_onie_mode = "sudo grub-editenv /host/grub/grubenv unset next_entry"
            st.config(dut,cmd_for_unset_onie_mode,faster_cli=False)
    else:
        cmdlist, _ = get_onie_grub_config_impl(dut, "install")
        cmds = ";".join(cmdlist)
        st.config(dut, cmds, faster_cli=False)
    return True

def copy_usb_files(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    ssh_conn_obj = kwargs.get('ssh_conn_obj')
    src_path,dst_path = kwargs.get('src_path'),kwargs.get('dst_path')
    file_path = kwargs.get('usb_num') if cli_type=="klish" else kwargs.get('mount_path')
    retry_count = kwargs.get('retry_count',6)
    confirm = "y" if cli_type == "klish" else "None"
    if kwargs.get("copy"):
        form = "copy" if cli_type == "klish" else "cp"
        command = "{} {} {}".format(form,src_path, dst_path)
    if kwargs.get("delete"):
        form = "delete" if cli_type == "klish" else "rm -rf"
        if kwargs.get("delete_from_device"):
            path = src_path
        elif kwargs.get("delete_from_mount_path"):
            if cli_type == "click":
                path = "{}/{}".format(file_path,dst_path)
            else:
                path = "{}://{}".format(file_path,dst_path)
        else:
            path = kwargs.get('path_to_delete')
        command = "{} {}".format(form, path)
    if kwargs.get("ssh"):
        if cli_type == "klish":
            conn_obj.execute_command(ssh_conn_obj, "sonic-cli")
            conn_obj.execute_command(ssh_conn_obj, command)
            output = conn_obj.execute_command(ssh_conn_obj, command)
            if kwargs.get("delete"):
                output = conn_obj.execute_command(ssh_conn_obj, "y")
            conn_obj.execute_command(ssh_conn_obj, "exit")
        else:
            output = conn_obj.execute_command(ssh_conn_obj, command)
        if output and "invalid input detected" not in output.lower():
            return False
        st.log("As expected found Invalid input detected while changing file through non admin user")
        return True
    elif kwargs.get('install_image'):
        tmp = False
        command = "copy {} {}".format(src_path, dst_path)
        for _ in range(retry_count):
            output=st.show(dut,command, type = "klish", max_time = 900, skip_tmpl=True, skip_error_check=True)
            if output and "error" not in str(output).lower():
                tmp = True
                break
        return tmp
    elif kwargs.get('copy_json'):
        st.apply_json2(dut, kwargs.get('json_file'))
        command = "cp {} {}".format('/tmp/apply_json2.json',"{}/ztp.json".format(kwargs.get('mount_path')))
        st.config(dut,command,type = "click")
    else:
        st.config(dut,command, confirm=confirm,type=cli_type)
    return True

def verify_ztp_over_usb_status(dut, iteration=6, retry=3, expect_ipchange=False, expect_reboot=False, files_to_check=list(), **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    retry_count_if_no_response = 0
    value= False
    st.log("Verifying the ZTP status with iteration method ...")
    for _ in range(1, iteration + 1):
        response = ztp_oper_api.show_ztp_status(dut, expect_reboot=expect_reboot, expect_ipchange=expect_ipchange, cli_type=cli_type)
        if not response:
            st.log("Observed no response in ZTP status ... retrying {} .. ".format(retry_count_if_no_response))
            if retry_count_if_no_response > 5:
                st.error("show ztp status returned empty data...")
                return False
            st.wait(retry)
            retry_count_if_no_response += 1
            continue
        if "service" not in response or "status" not in response or "adminmode" not in response:
            st.log("Values of service or status or adminmode is not populated yet, retrying ...")
            st.wait(10)
            continue
        if response["adminmode"] == "True":
            if "service" not in response or "status" not in response or "adminmode" not in response:
                st.log("Values of service or status or adminmode is not populated yet, retrying ...")
                st.wait(retry)
            else:
                st.log("Found that admin mode as {}".format(response["adminmode"]))
                if response["service"] == "Inactive":
                    st.log("Found that service as {}".format(response["service"]))
                    if response["status"] == "FAILED":
                        st.log("Found that status as {}".format(response["status"]))
                        value= False
                    elif response["status"] == "SUCCESS":
                        st.log("Found that status as {}".format(response["status"]))
                        value= True
                    else:
                        st.log("ZTP status is not in expected values , retrying...")
                        st.wait(retry)
                elif response["service"] == "Processing" or response["service"] == "Active Discovery":
                    st.log("Found that service as {}".format(response["service"]))
                    if response["status"] == "IN-PROGRESS":
                        st.log("Found that status as {}".format(response["status"]))
                        st.log("Files - {}".format(response["filenames"]))
                        filenames = response["filenames"][0]
                        for file in files_to_check:
                            if filenames[file] == "Not Started":
                                st.log("Found that {} as {}".format(file,filenames[file]))
                                st.wait(60)
                                value= False
                            elif filenames[file] == "IN-PROGRESS":
                                st.log("Found that {} as {}".format(file, filenames[file]))
                                st.wait(300)
                                value= False
                            elif filenames[file] == "SUCCESS":
                                st.log("Found that {} as {}".format(file, filenames[file]))
                                value= True
                        st.wait(retry)
                    elif response["status"] == "FAILED":
                        st.log("Found that status as {}".format(response["status"]))
                        value= False
                    elif response["status"] == "Not Started":
                        st.log("Found that status as {}".format(response["status"]))
                        st.wait(retry)
                    elif response["status"] == "SUCCESS":
                        st.log("Found that status as {}".format(response["status"]))
                        st.wait(retry)
                        value= True
                    else:
                        st.log("ZTP status is not in expected values, retrying...")
                        st.wait(retry)
                elif response["service"] == "SUCCESS":
                    st.log("Found that service as {}".format(response["service"]))
                    value= True
        else:
            if not value:
                continue
            else:
                break
    if not value:
        st.log("Failed to load the image and config file from mount path through ZTP")
        return False
    else:
        st.log("Successfully loaded the build and config files into the device using ZTP over USB")
        return True

def verify_usb_files(dut,**kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    dir_path = kwargs.get('usb_dir') if cli_type == "klish" else kwargs.get('mount_path')
    if cli_type == "klish":
        output = st.show(dut, dir_path, type=cli_type)
        a = False
        for i in output:
            if i.get('file_name') == kwargs.get('copied_file'):
                a = True
                break
        return a
    else:
        if kwargs.get('copied_file') not in str(st.config(dut, 'ls -la {}'.format(dir_path))):
            return False
        return True

def show_usb_status(dut,type,max_retries=12,retry=5,**kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    expect_ipchange = kwargs.get('expect_ipchange',False)
    expect_reboot = kwargs.get('expect_reboot') if kwargs.get('expect_reboot') else False
    response = []
    if type not in ["status", "devices", "partitions"]:
        st.error("Unsupported Type values for show usb")
        return response
    command = "show usb {}".format(type)
    if type == "status" and cli_type == "klish":
        command = "show usb"
    response = st.show(dut, command, type=cli_type,expect_ipchange=expect_ipchange,expect_reboot=expect_reboot)
    if kwargs.get('mount_check') and cli_type == "click":
        pass
    else:
        for val in range(len(response)):
            if response[val].get('status') == 'Enabled' and response[val].get('form') == ''  and response[val].get('model_name') == '' and response[val].get('file') == '' and response[val].get('mount_dir') == '' and response[val].get('device_name') == '':
                del response[val]
            else:
                continue
    if kwargs.get('enable_check'):
        for _ in range(max_retries):
            a = True
            for output in response:
                if output.get('mount_dir')=='' or output.get('device_name')=='' or output.get('file')=='':
                    st.log("partitions are not detected, hence retrying...")
                    st.wait(retry)
                    response=show_usb_status(dut, type='status')
                    a=False
            if a:
                break
            else:
                continue
        return a
    return response

def verify_usb_status(dut, status = None, return_output = None, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    mount_range = make_list(kwargs.get("mount_range")) if kwargs.get("mount_range") else kwargs.get("mount_range")
    valid_devices = make_list(kwargs.get("valid_devices")) if kwargs.get("valid_devices") else kwargs.get("valid_devices")
    file_range = make_list(kwargs.get("file_range")) if kwargs.get("file_range") else kwargs.get("file_range")
    if kwargs.get('mount_check'):
        result = show_usb_status(dut, type='status', mount_check = kwargs.get('mount_check'))
    else:
        result = show_usb_status(dut, type='status')
    if not result:
        return False
    if return_output:
        return result
    if cli_type == "klish" and kwargs.get('disable_check'):
        output = result[0]
        if status:
            if output.get('status').lower() != status.lower():
                st.debug("Observed the status mismatch Expected: {}, Actual: {}".format(status, output.get("status")))
                return False
        if kwargs.get('form'):
            if output.get('form').lower() != kwargs.get('form').lower():
                st.error("Partitions are not unmounted properly")
                return False
        return True
    else:
        for output in result:
            if status:
                if output.get('status').lower() != status.lower():
                    st.debug("Observed the status mismatch Expected: {}, Actual: {}".format(status, output.get("status")))
                    return False
            if kwargs.get('form') and cli_type == "klish":
                if output.get('form').lower() != kwargs.get('form').lower():
                    st.error("Partitions are not unmounted properly")
                    return False
            if mount_range:
                if output.get('mount_dir') not in  mount_range:
                    st.debug("Observed the Mount Dir mismatch Expected: {}, Actual: {}".format(mount_range,output.get("mount_dir")))
                    return False
            if valid_devices:
                if output.get('device_name') not in valid_devices:
                    st.debug("Observed the Device Name mismatch Expected: {}, Actual: {}".format(valid_devices,output.get('device_name')))
                    return False
            if file_range:
                if output.get('file') not in file_range:
                    st.debug("Observed the File mismatch Expected: {}, Actual: {}".format(file_range,output.get('file')))
                    return False
        return True

def verify_usb_devices(dut, manufacturer=None, valid_devices=None, model=None, return_output=None):
    result = show_usb_status(dut, type='devices')
    if not result:
        return False
    if return_output:
        return result
    for output in result:
        if valid_devices:
            if output.get('device_name') not in valid_devices:
                st.debug("Obtained {} Device Name is not in the expected range".format(output.get('device_name')))
                return False
        if model:
            model_name = output.get('model_name').rstrip()
            if model_name not in model:
                st.debug("Model name not found on the output, Obtained value: {},Expected value: {} ".format(output.get('model_name'),model))
                return False
        if manufacturer:
            if output.get('file') not in manufacturer:
                st.log("Manufacturer not found on the output, Obtained value: {},Expected value: {}".format(output.get('file'),manufacturer))
                return False
    return True

def verify_usb_partitions(dut, verify_vals = None, return_output = None):
    result = show_usb_status(dut, type='partitions')
    if not result:
        return False
    if return_output:
        return result
    entries = filter_and_select(result, None, verify_vals)
    if not entries:
        st.error("Match not found for Expected - {} Actual - {} ".format(verify_vals,result))
        return False
    return True
