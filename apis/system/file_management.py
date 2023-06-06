from spytest import st
import re

def copy_file(dut,source, destination, **kwargs):
    """
    Copies file from source to destination, where destination could be local or remote
    source - startup-config, running-config, local filesystem path or remote location
    destination - startup-config, running-config, local filesystem path or remote location
    Author : Gowsalya Mariappan(Gowsalya_Mariappan@Dell.com)
    Usage:
        copy_file(dut, "startup-configuration", "running-configuration")
        copy_file(dut, "running-configuration", "config://file-1.txt")
        copy_file(dut, "running-configuration", "scp://admin:admin123@100.104.99.84/home/admin/config_backup.json")
        copy_file(dut, "running-configuration", "config://file_1.txt;file_2.txt", skip_error=True)
        copy_file(dut, "running-configuration", "config://file_6&ab.txt", skip_error=True)
    """
    st.log('Entering function copy_file() with args %s' %(str(locals())))
    cmd = "copy %s %s" %(source,destination)
    confirm = kwargs.get("confirm") if kwargs.get("confirm") else "y"
    skip_error = kwargs.get("skip_error") if kwargs.get("skip_error") else False
    try:
        st.config(dut, cmd, type="klish", confirm=confirm, conf=False, skip_error_check=skip_error)
    except:
        st.report_fail('Failed: copy_file did not succeed')

def dir_ls(dut, path, dir_cmd='yes', **kwargs):
    """
    List the contents of the directory or for a particular file
    path - Could be a local folder name or local file
    dir_cmd - "yes" for dir cmd , "no" for ls cmd as they give same output
    Author : Gowsalya Mariappan(Gowsalya_Mariappan@Dell.com)
    Usage:
        dir_ls(dut,"config:/", dir_cmd="yes")
        dir_ls(dut,"config:/hw_resources/uft/TD3.X3.yaml", dir_cmd="yes")
        dir_ls(dut,"config:/", dir_cmd="no", skip_error=True)
        dir_ls(dut,"home:/../user1/", dir_cmd="yes", skip_error=True)
    """
    st.log('Entering function dir() with args %s' %(str(locals())))
    if dir_cmd.lower() == "yes":
        cmd = "dir %s | no-more" %(path)
    else:
        cmd = "ls %s | no-more" %(path)
    skip_error = kwargs.get("skip_error") if kwargs.get("skip_error") else False
    # Call without template invoke for skip_error = True case,
    # meaning expecting error so no template is required
    if skip_error:
        output = st.config(dut, cmd, type="klish", confirm='y', conf=False, skip_error_check=True)
    else:
        output=st.cli_show(dut, cmd, skip_tmpl=False, mode = 'mgmt-user')

    return output

def delete_file(dut, path, **kwargs):
    """
    Delete the file as specified by the path.
    path - Local File path to be deleted
    Author : Gowsalya Mariappan(Gowsalya_Mariappan@Dell.com)
    Usage:
        delete_file(dut, "config://file_1.txt;file_2.txt", skip_error=True)
        delete_file(dut, "home://running-1.json")
    """
    st.log('Entering function delete_file() with args %s' %(str(locals())))
    confirm = kwargs.get("confirm") if kwargs.get("confirm") else "y"
    skip_error = kwargs.get("skip_error") if kwargs.get("skip_error") else False
    cmd = "delete {}". format(path)
    st.log("In delete_file, command to be executed is %s" %cmd)
    try:
        st.config(dut, cmd, type="klish", confirm=confirm, conf=False, skip_error_check=skip_error)
    except:
        st.report_fail('Failed: delete_file did not succeed')

def validate_file_name_dir_parsed_output(parsed_output, filename_to_verify):
    """
    This function verifies whether file in the argument is present in the parsed output data
    parsed_output - Parsed from the dir() function using template
    filename_to_verify - File name or a regular expression to verify its presence/match in parsed output
    Author : Gowsalya Mariappan(Gowsalya_Mariappan@Dell.com)
    Parsed output looks like:
    [{'file_name': 'asic_config_checksum', 'timestamp': '2021-11-09 04:39', 'type_of_file': '-'}, {'file_name': 'ccd_mgmt_sock', 'timestamp': '2021-11-09 15:35', 'type_of_file': 's'}, {'file_name': 'config_db.json', 'timestamp': '2021-11-09 15:36', 'type_of_file': '-'}, {'file_name': 'config_db_version_registry.json', 'timestamp': '2020-09-17 01:48', 'type_of_file': '-'}, {'file_name': 'constants.yml', 'timestamp': '2021-11-09 04:43', 'type_of_file': '-'}, {'file_name': 'copp_config.json', 'timestamp': '2021-11-09 05:33', 'type_of_file': '-'}, {'file_name': 'core_analyzer.rc.json', 'timestamp': '2021-11-09 04:43', 'type_of_file': '-'}, {'file_name': 'docker_limits.json', 'timestamp': '2021-11-09 04:43', 'type_of_file': '-'}, {'file_name': 'frr', 'timestamp': '2021-11-09 15:38', 'type_of_file': 'd'}, {'file_name': 'generated_services.conf', 'timestamp': '2021-11-09 04:45', 'type_of_file': '-'}, {'file_name': 'hamd', 'timestamp': '2021-11-09 04:41', 'type_of_file': 'd'}, {'file_name': 'hw_resources', 'timestamp': '2021-11-09 04:46', 'type_of_file': 'd'}, {'file_name': 'init_cfg.json', 'timestamp': '2021-11-09 04:43', 'type_of_file': '-'}, {'file_name': 'snmp.yml', 'timestamp': '2021-11-09 04:43', 'type_of_file': '-'}, {'file_name': 'sonic_branding.yml', 'timestamp': '2021-11-09 04:39', 'type_of_file': '-'}, {'file_name': 'sonic-config.tar', 'timestamp': '2021-11-09 11:11', 'type_of_file': '-'}, {'file_name': 'sonic-environment', 'timestamp': '2021-11-09 05:35', 'type_of_file': '-'}, {'file_name': 'sonic_version.yml', 'timestamp': '2021-11-09 04:46', 'type_of_file': '-'}, {'file_name': 'updategraph.conf', 'timestamp': '2021-11-09 04:43', 'type_of_file': '-'}]
    'filename_to_verify': 'config_db.json' or 'sonic_dump_sonic_\\d{8}_\\d{6}\\.tar\\.gz'
    """
    is_present =  False
    st.log('Entering function validate_file_name_dir_parsed_output with args %s' %(str(locals())))
    #Loop through list in parsed dict to check expected file is present
    # replace '+' in input file name with '\+' for regular expression
    filename_to_verify = filename_to_verify.replace('+', '\\+')
    filename_re = re.compile(r'%s' %filename_to_verify)
    for parsed_list in parsed_output:
        file_name_in_parsed_list = parsed_list['file_name']
        match_file_name = filename_re.search(file_name_in_parsed_list)
        if match_file_name:
            st.log("Expected file %s is present in dir command output " %(filename_to_verify))
            is_present = True

    st.log("Returning is_present as %r from validate_file_name_dir_parsed_output" %is_present)

    return is_present

def delete_file_from_folder_matching_pattern(dut, folder, pattern, **kwargs):
    """
    Delete the file(s) from the given folder matching the pattern
    folder - Local Folder in which delete need to be done
    pattern - regular expression pattern to match for filenames
    Author : Gowsalya Mariappan(Gowsalya_Mariappan@Dell.com)
    Usage:
        delete_file_from_folder_matching_pattern(dut, 'tech-support', 'sonic_dump_sonic_\\d{8}_\\d{6}\\.tar\\.gz')
    """
    st.log('Entering function delete_file_from_folder_matching_pattern() with args %s' %(str(locals())))
    #confirm = kwargs.get("confirm") if kwargs.get("confirm") else "y"
    delete_arg = "{}://". format(folder)
    dir_arg = "{}:/". format(folder)
    dir_output = dir_ls(dut, dir_arg)
    match_re = re.compile(r'%s' %pattern)
    for output_list in dir_output:
        file_name_in_parsed_list = output_list['file_name']
        match_file_name = match_re.search(file_name_in_parsed_list)
        if match_file_name:
            file_to_delete = match_file_name.group()
            st.log("Delete file %s matching pattern", match_file_name.group())
            delete_file(dut, delete_arg+file_to_delete)

def copy_file_after_matching_pattern(dut, source_dir, destination, pattern, **kwargs):
    """
    Copies file from source to destination, where destination could be local or remote
    source_dir - startup-config, running-config, local filesystem path or remote location
    destination - startup-config, running-config, local filesystem path or remote location
    pattern - regular expression pattern to match for retrieving the filename
    Author : Shreeja Rajkumar(Shreeja_R@Dell.com)
    Usage:
        copy_file_after_matching_pattern(dut, 'tech-support://', 'config://file.txt', 'sonic_dump_sonic_\\d{8}_\\d{6}\\.tar\\.gz')
    """
    st.log('Entering function copy_file_after_matching_pattern() with args %s' %(str(locals())))
    dir_arg = "{}". format(source_dir)
    dir_output = dir_ls(dut, dir_arg)
    match_re = re.compile(r'%s' %pattern)
    for output_list in dir_output:
        file_name_in_parsed_list = output_list['file_name']
        match_file_name = match_re.search(file_name_in_parsed_list)
        if match_file_name:
            file_to_copy = match_file_name.group()

    confirm = kwargs.get("confirm") if kwargs.get("confirm") else "y"
    skip_error = kwargs.get("skip_error") if kwargs.get("skip_error") else False
    try:
        cmd = "copy %s %s" %(source_dir + file_to_copy, destination)
        st.config(dut, cmd, type="klish", confirm=confirm, conf=False, skip_error_check=skip_error)
    except:
        st.report_fail("msg", 'Failed: copy_file_after_matching_pattern did not succeed')

