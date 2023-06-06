import re
from spytest import st
from apis.system.rest import config_rest

from utilities.common import filter_and_select, make_list
import utilities.utils as utils_obj

try:
    import apis.yang.codegen.messages.tpcm.TpcmRpc as umf_tpcm_rpc
    from apis.yang.codegen.yang_rpc_service import YangRpcService
except ImportError:
    pass


def delete_file_from_local_path(dut, filename, sudo=True, skip_error_check=True):
    sucmd = "sudo" if sudo else ""
    command = "{} rm {}".format(sucmd, filename)
    st.config(dut, command, skip_error_check=skip_error_check)


def commit_docker_image(dut,docker,image, vrf="default"):
    """
    purpose:
            This definition is used to commit existing docker's image

    Arguments:
    :param dut: device where the image needs to be saved
    :type dut: string
    :param docker: docker name
    :type docker: string
    :param image: image name
    :type image: string
    :return: None

    usage:
        commit_docker_image(dut1, "httpd:latest","image:test")
    Created by: Julius <julius.mariyan@broadcom.com
    """
    if vrf == "default":
        cmd = "docker -H unix:///run/docker-default.socket commit {} {}".format(docker,image)
    elif vrf == "mgmt":
        cmd = 'docker -H unix:///run/docker-mgmt.socket commit {} {}'.format(docker, image)
    return st.config(dut, cmd)


def save_docker_image(dut,image,options,vrf="default"):
    """
    purpose:
            This definition is used to save existing docker's image

    Arguments:
    :param dut: device where the image needs to be saved
    :type dut: string
    :param image: docker image name
    :type image: string
    :param options: rest all things can be specfied as part of options; for ex |gzip -c > /home/admin/mydocker.tar.gz
    :type options: string
    :return: None

    usage:
        save_docker_image(dut1, "httpd:latest","|gzip -c > /home/admin/mydocker.tar.gz")
    Created by: Julius <julius.mariyan@broadcom.com
    """
    if vrf == "default":
        cmd = "docker -H unix:///run/docker-default.socket save {} {}".format(image, options)
    elif vrf == "mgmt":
        cmd = "docker -H unix:///run/docker-mgmt.socket save {} {}".format(image,options)
    return st.config(dut, cmd)


def tpcm_operation(dut, action, docker_name, install_method="url",**kwargs ):
    """
    purpose:
            This definition is used to install/upgrade/uninstall third party container image

    Arguments:
    :param dut: device where the install/upgrade/uninstall needs to be done
    :type dut: string
    :param action: install/upgrade/uninstall
    :type action: string
    :param docker_name: docker name to be installed
    :type docker_name: string
    :param install_method: how the installation to be done; scp/sftp/url/pull etc
    :type install_method: string
    :param ser_name: remote server name
    :type ser_name: string
    :param user_name: user name
    :type user_name: string
    :param pwd: password
    :type pwd: string
    :param tag_name: tag name to be used for the image
    :type tag_name: string
    :param image_path: path for the image to be installed
    :type image_path: string
    :param file_name: file name
    :type file_name: string
    :param extra_args: additional arguments for the TPCM
    :type extra_args: string
    :param skip_data: whether to skip backup of data during upgrade
    :type skip_data: string
    :param cli_type: type of user interface
    :type cli_type: string
    :return: None

    usage:
    Install:
        tpcm_operation(dut1, "install","mydocker","url",image_path="http://myserver/path/test.tar.gz")
        tpcm_operation(dut1, "install","mydocker","scp",file_name="/images/test.tar.gz",
                    ser_name="10.10.10.10",user_name="test",pwd="password")
        tpcm_operation(dut1, "install","mydocker","sftp",file_name="/images/test.tar.gz",
                    ser_name="10.10.10.10",user_name="test",pwd="password")
        tpcm_operation(dut1, "install","mydocker","file",image_path="/media/usb/path/test.tar.gz")
        tpcm_operation(dut1, "install","mydocker","image",image_path="test.tar.gz",tag_name="test")
    Upgrade:
        tpcm_operation(dut1, "upgrade","mydocker","url", image_path="http://myserver/path/test.tar.gz")
        tpcm_operation(dut1, "upgrade","mydocker","url",image_path="http://myserver/path/test.tar.gz",skip_data="skip")
    Uninstall:
        tpcm_operation(dut1, "uninstall","mydocker")
    Created by: Julius <julius.mariyan@broadcom.com
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in utils_obj.get_supported_ui_type_list():
        service = YangRpcService()
        if action == "update":
            rpc = umf_tpcm_rpc.TpcmUpdateRpc()
            rpc.Input.docker_name = docker_name
            if "disk_limit" in kwargs:
                rpc.Input.disk_limit = kwargs["disk_limit"]
            if "vrf_name" in kwargs:
               rpc.Input.vrf_name = kwargs["vrf_name"]
            if "mem_limit" in kwargs:
                rpc.Input.docker_name = docker_name
                rpc.Input.mem_limit = kwargs["mem_limit"]
        elif action == "install":
            rpc = umf_tpcm_rpc.TpcmInstallRpc()
            rpc.Input.docker_name = docker_name
            if install_method == "pull":
                rpc.Input.image_source = "pull"
                if "tag_name" in kwargs:
                    rpc.Input.image_name = kwargs["image_path"] + ":" + kwargs["tag_name"]
                else:
                    rpc.Input.image_name = kwargs["image_path"]
            elif install_method == "url":
                rpc.Input.image_source = "url"
                rpc.Input.image_name = kwargs["image_path"]
            elif install_method == "scp" or install_method == "sftp":
                rpc.Input.image_source = install_method
                rpc.Input.image_name = kwargs["file_name"]
                rpc.Input.remote_server = kwargs["ser_name"]
                rpc.Input.username = kwargs["user_name"]
                rpc.Input.password = kwargs["pwd"]
            elif install_method == "image":
                rpc.Input.image_source = "image"
                rpc.Input.image_name = kwargs["image_path"]
            elif install_method == "file":
                rpc.Input.image_source = "file"
                rpc.Input.image_name = kwargs["image_path"]
            if "vrf_name" in kwargs:
                rpc.Input.vrf_name = kwargs["vrf_name"]
            if "extra_args" in kwargs:
                if kwargs['extra_args'] != "":
                    rpc.Input.args = kwargs["extra_args"]
            else:
                rpc.Input.args = "\"--memory=400m\""
        elif action == "upgrade":
            rpc = umf_tpcm_rpc.TpcmUpgradeRpc()
            rpc.Input.docker_name = docker_name
            if install_method == "pull":
                rpc.Input.image_source = "pull"
                rpc.Input.image_name = kwargs["image_path"] + ":" + kwargs["tag_name"]
                rpc.Input.remote_server = kwargs["ser_name"]
                rpc.Input.username = kwargs["user_name"]
                rpc.Input.password = kwargs["pwd"]
                rpc.Input.args = kwargs["extra_args"]
                rpc.Input.skip_data_migration = kwargs.get("skip_data", "no")
            elif install_method == "url":
                rpc.Input.image_source = "url"
                rpc.Input.image_name = kwargs["image_path"]
                rpc.Input.skip_data_migration = kwargs.get("skip_data", "no")
            elif install_method == "scp" or install_method == "sftp":
                rpc.Input.image_source = install_method
                rpc.Input.image_name = kwargs["file_name"]
                rpc.Input.remote_server = kwargs["ser_name"]
                rpc.Input.username = kwargs["user_name"]
                rpc.Input.password = kwargs["pwd"]
                rpc.Input.skip_data_migration = kwargs.get("skip_data", "no")
            elif install_method == "image":
                rpc.Input.image_source = "image"
                rpc.Input.image_name = kwargs["image_path"]
                rpc.Input.skip_data_migration = kwargs.get("skip_data", "no")
            elif install_method == "file":
                rpc.Input.image_source = "file"
                rpc.Input.image_name = kwargs["image_path"]
                rpc.Input.skip_data_migration = kwargs.get("skip_data", "no")
            if "vrf_name" in kwargs:
                rpc.Input.vrf_name = kwargs["vrf_name"]
        elif action == "uninstall":
            rpc = umf_tpcm_rpc.TpcmUninstallRpc()
            rpc.Input.docker_name = docker_name
            if "skip_data" in kwargs:
                rpc.Input.clean_data = kwargs.get("skip_data", "no")
            else:
                rpc.Input.clean_data = "no"
        result = service.execute(dut, rpc, timeout=60)
        if not result.ok():
            st.log('test_step_failed: {} for TPC {} failed as: {}'.format(install_method, docker_name, result.data))
            result = False
        else:
            result = True
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["tpcm_"+action]
        if action == "uninstall":
            if  "skip_data" in kwargs:
                payload = {"openconfig-system-ext:input" : {"clean-data" : kwargs.get("skip_data", "no"),
                           "docker-name" : docker_name}}
            else:
                payload = {"openconfig-system-ext:input" : {"clean-data" : "no", "docker-name" : docker_name}}
        elif action == "install":
            if "extra_args" not in kwargs:
                kwargs["extra_args"] = "--memory=400m"
            if install_method == "pull":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name, "image-source": "pull",
                            "image-name" : kwargs["image_path"]+ ":" +kwargs["tag_name"],
                            "args" : kwargs["extra_args"]}}
            elif install_method == "url":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name, "image-source": "url",
                            "image-name" : kwargs["image_path"], "args" : kwargs["extra_args"]}}
            elif install_method == "scp":
                payload = {"openconfig-system-ext:input": {"docker-name": docker_name, "image-source": "scp",
                                                           "image-name": kwargs["file_name"],
                                                           "remote-server": kwargs["ser_name"],
                                                           "username": kwargs["user_name"],
                                                           "password": kwargs["pwd"],
                                                           "args" : kwargs["extra_args"] }}
            elif install_method == "sftp":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "sftp",
                            "image-name" : kwargs["file_name"],"remote-server" : kwargs["ser_name"],
                            "username" : kwargs["user_name"], "password" : kwargs["pwd"],
                                                              "args" : kwargs["extra_args"]}}
            elif install_method == "image":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "image",
                            "image-name" : kwargs["image_path"], "args" : kwargs["extra_args"]}}
            elif install_method == "file":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "file",
                            "image-name" : kwargs["image_path"], "args" : kwargs["extra_args"]}}
        elif action == "upgrade":
            if install_method == "pull":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name, "image-source": "pull",
                            "image-name" : kwargs["image_path"]+ ":" +kwargs["tag_name"],
                            "remote-server" : kwargs["ser_name"], "username" : kwargs["user_name"],
                            "password" : kwargs["pwd"],"args" : kwargs["args"],
                            "skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "url":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name, "image-source": "url",
                            "image-name" : kwargs["image_path"],"skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "scp":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "scp",
                            "image-name" : kwargs["file_name"],"remote-server" : kwargs["ser_name"],
                            "username" : kwargs["user_name"], "password" : kwargs["pwd"],
                            "skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "sftp":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "sftp",
                            "image-name" : kwargs["file_name"],"remote-server" : kwargs["ser_name"],
                            "username" : kwargs["user_name"], "password" : kwargs["pwd"],
                            "skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "image":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "image",
                            "image-name" : kwargs["image_path"],
                            "skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "file":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "file",
                            "image-name" : kwargs["image_path"],"skip-data-migration" : kwargs.get("skip_data", "no")}}
        result = config_rest(dut, http_method='post', rest_url=url, json_data=payload,timeout=60)
    else:
        if action=="uninstall":
            cmd = 'tpcm {} name {}'.format(action, docker_name)
        elif action == "update":
            cmd = "tpcm update"
            if "disk_limit" in kwargs:
                cmd += " disk-limit {}".format(kwargs["disk_limit"])
            else:
                cmd += " name {}".format(docker_name)
        else:
            cmd = 'tpcm {} name {} {}'.format(action, docker_name,install_method)

        if "image_path" in kwargs:
            cmd += " {}".format(kwargs["image_path"])
        if "tag_name" in kwargs:
            cmd += ":{}".format(kwargs["tag_name"])
        if "ser_name" in kwargs:
            cmd += " {}".format(kwargs["ser_name"])
        if "user_name" in kwargs:
            cmd += " username {}".format(kwargs["user_name"])
        if "pwd" in kwargs:
            cmd += " password {}".format(kwargs["pwd"])
        if "file_name" in kwargs:
            cmd += " filename {}".format(kwargs["file_name"])
        if "vrf_name" in kwargs:
            cmd += " vrf-name {}".format(kwargs["vrf_name"])
        if "c_args" in kwargs:
            if kwargs['c_args'] != "":
                cmd += " cargs \"{}\"".format(kwargs['c_args'])
        if "extra_args" in kwargs:
            if kwargs['extra_args'] != "":
                cmd += " args \"{}\"".format(kwargs["extra_args"])
        else:
            if action == "install":
                cmd += " args \"--memory=400m\""
        if  "skip_data" in kwargs:
            if action == "upgrade":
                cmd += " skip-data-migration {}".format(kwargs.get("skip_data","no"))
            elif action == "uninstall":
                cmd += " clean_data {}".format(kwargs.get("skip_data", "no"))
        if "mem_limit" in kwargs:
            cmd += " memory {}".format(kwargs["mem_limit"])
        if "sys_ready" in kwargs:
            cmd += " start-after-system-ready {}".format(kwargs["sys_ready"])
        skip_error = kwargs.get("skip_error", False)
        output= st.config(dut, cmd,type=cli_type,skip_error_check=skip_error)
        if re.search("failed",output):
            result=False
        else:
            result=True
    return result


def verify_tpcm_list(dut, docker_list, image_list,status_list,**kwargs):
    """
    purpose:
            This definition is used to verify tpcm list

    Arguments:
    :param dut: device where the command needs to be executed
    :type dut: string
    :param docker_list: docker name list
    :type docker_list: list
    :param image_list: image name list
    :type image_list: list
    :param status_list: docker status list
    :type status_list: list
    :param cli_type: type of user interface
    :type cli_type: string
    :return: True/False; True for success case and Fail for failure case

    usage:
        verify_tpcm_list(dut1, docker_list=["docker1","docker2"],
                         image_list=["httpd:image1","httpd:image2"],status_list=["Up","Exited"])

	Created by: Julius <julius.mariyan@broadcom.com
    """
    success = True
    cli_type = st.get_ui_type(dut, **kwargs)
    docker_list = make_list(docker_list)
    image_list = make_list(image_list)
    status_list = make_list(status_list)
    vrf_run_list = make_list(kwargs.get("vrf_run_list", []))
    vrf_config_list = make_list(kwargs.get("vrf_config_list", []))
    if cli_type in utils_obj.get_supported_ui_type_list():
        service = YangRpcService()
        tpcm_obj = umf_tpcm_rpc.TpcmListRpc()
        if "vrf_name" in kwargs:
            tpcm_obj.Input.vrf_name=kwargs["vrf_name"]
        else:
            tpcm_obj.Input.vrf_name=""
        tpcm_out = service.execute(dut, tpcm_obj, timeout=60, verify='True')
        if tpcm_out:
            if tpcm_out.payload['openconfig-tpcm:output']['status-detail']:
                output= tpcm_out.payload['openconfig-tpcm:output']['status-detail']
                return parse_tpcm_list_output(output, docker_list, image_list, status_list)
        else:
            st.log("test_step_failed: No output found for tpcm verification")
            return False
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["tpcm_get"]
        payload = {"openconfig-system-ext:input": {"vrf-name": "string"}}
        rest_out = config_rest(dut, http_method="post", rest_url=url, json_data=payload, get_response=True)
        rest_out = rest_out['output']['openconfig-system-ext:output']['status-detail']
        for docker, image, status in zip(docker_list, image_list, status_list):
            docker_status = False
            for elem in rest_out:
                temp_out = elem.split('  ')
                temp_out = [x.strip(' ') for x in temp_out]
                out = list(filter(None, temp_out))
                if "CONTAINER NAME" not in out:
                    if docker in out:
                        docker_status = True
                        if out[1] == image and out[3].split(" ")[0] == status:
                            st.log("########## Match found for docker {} with status {} ########"
                                   "##".format(docker, status))
                        else:
                            st.error("########## Match NOT found for docker {}; expected image: {} but got: {};"
                                     "expected status : {} but got: {}".format(docker, image, out[1],
                                                                               status, out[3].split(" ")[0]))
                            success = False
            if not docker_status:
                success = False
    elif cli_type == "klish":
        if "vrf_name" in kwargs:
            vrf = " vrf {}".format(kwargs["vrf_name"])
        else:
            vrf = ""
        output = st.show(dut, "show tpcm list" + vrf, type=cli_type)
        if "vrf_run_list" in kwargs and "vrf_config_list" in kwargs:
            for docker, image, status, vrf_run, vrf_conf in zip(docker_list, image_list, status_list,
                                                                vrf_run_list, vrf_conf_list):
                fil_out = filter_and_select(output, ["status"], {'image': image, "cont_name": docker,
                                                                 'vrf_run': vrf_run, 'vrf_conf': vrf_conf})
                if not fil_out:
                    st.error("Docker {} with image {} NOT found in tpcm list output".format(docker, image))
                    success = False
                else:
                    if fil_out[0]["status"] == status:
                        st.log("########## Match found for docker {} with status {} ########"
                               "##".format(docker, status))
                    else:
                        st.error("########## Match NOT found for docker {}; expected status : {}"
                                 " but got {}".format(docker, status, fil_out[0]["status"]))
                        success = False
        else:
            for docker,image,status in zip(docker_list,image_list,status_list):
                fil_out = filter_and_select(output, ["status"], {'image': image,"cont_name" : docker})
                if not fil_out:
                    st.error("Docker {} with image {} NOT found in tpcm list output".format(docker,image))
                    success = False
                else:
                    if fil_out[0]["status"] == status:
                        st.log("########## Match found for docker {} with status {} ########"
                               "##".format(docker,status))
                    else:
                        st.error("########## Match NOT found for docker {}; expected status : {}"
                                 " but got {}".format(docker,status,fil_out[0]["status"]))
                        success = False
    return success


def parse_tpcm_list_output(output, docker_list, image_list, status_list):
    success = False
    output=get_tpcm_list_output(output)
    for docker, image, status in zip(docker_list, image_list, status_list):
        for elem in output:
            if docker in elem and image in elem:
                if status in elem:
                    st.log("MATCH FOUND for container name \"{}\" with status \"{}\"".format(docker, status))
                    success=True
                else:
                    st.log("MATCH NOT FOUND for container name \"{}\" with status \"{}\"".format(docker, status))
                    st.banner("Check this output for mode info {}".format(elem))
    return success


def get_tpcm_list_output(output):
    final_output = list()
    for elem in output:
        temp_out = elem.split('  ')
        temp_out = [x.strip(' ') for x in temp_out]
        temp_out = list(filter(None, temp_out))
        temp_out = elem.split(' ')
        output = list(filter(None, temp_out))
        final_output.append(output)
    return final_output


def tpcm_start_stop(dut, docker_name, operation, skip_error_check=True, docker_cmd=False):
    """
    To Perform container operations
    :param dut:
    :param docker_name:
    :param operation:
    :return:
    """
    util_name = "systemctl" if not docker_cmd else "docker"
    command = '{} {} {}'.format(util_name, operation, docker_name)
    return st.config(dut, command, skip_error_check=skip_error_check)

def create_file_in_tpc(dut, tpc, vrf, **kwargs):
    if vrf == "default":
        st.config(dut,"docker -H unix:///run/docker-default.socket exec -it {} dd if=/dev/zero of={} bs={} count={}".format(tpc, kwargs['file_name'], kwargs['mem_size'], kwargs['count']))
    elif vrf == "mgmt":
        st.config(dut,"docker -H unix:///run/docker-mgmt.socket exec -it {} dd if=/dev/zero of={} bs={} count={}".format(tpc, kwargs['file_name'], kwargs['mem_size'], kwargs['count']))


def verify_tpcm_stats(dut, tpc_name, vrf_name, **kwargs):
    """
    To verify tpcm stats info
    :param dut:
    :param id:
    :param name:
    :param cpu:
    :param memusage:
    :param memlimit:
    :param memperc:
    :param pid:
    :return: True/False
    """
    command = 'docker -H unix:///run/docker-{}.socket stats -a --no-stream'.format(vrf_name)
    output = st.show(dut, command)
    rv = filter_and_select(output, None, {'name': tpc_name})
    if not rv:
        st.error("No match for {} = {} in table".format('name', tpc_name))
        return False
    for each in kwargs.keys():
        if not filter_and_select(rv, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in NAME {} ".format(each, kwargs[each], tpc_name))
            return False
        else:
            st.log("Match found for {} = {} in NAME {}".format(each, kwargs[each], tpc_name))
    return True
