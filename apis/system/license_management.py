from spytest import st

license_not_found  = "Not found"
license_invalid    = "Invalid"
license_valid      = "Valid"
license_due_expiry = "Due expiry"
license_expired    = "Expired"

def is_license_supported(dut, is_cli=True):
    """
    This function checks if current sonic image supports license feature.
    is_cli : True if CLI, False for REST
    Author : Almah Roshni
    Usage  : license_obj.is_license_supported(vars.D1)
    """
    st.log('Entering function is_license_supported() with args %s' %(str(locals())))
    if is_cli:
        try:
            st.show(dut, "show license status", type="klish")
            return True
        except:
            return False
    else:
        err_msg = ""
        getOutput = st.open_config(dut, "/restconf/data/openconfig-license-mgmt-private:license-management/state", timeout=30)
        got = getOutput.output
        if "ietf-restconf:errors" in got:
            if got['ietf-restconf:errors']['error'][0]['error-message'].lower() ==  "entry not found":
                err_msg += "License feature not supported"
            else:
                err_msg += got['ietf-restconf:errors']['error'][0]['error-message']
        if err_msg:
            st.error(err_msg)
            return False
        return True



def license_install(dut, file_path, **kwargs):
    """
    This function installs a valid dell sonic license file.
    file_path : could be local home path, or a remote location

    Author    : Almah Roshni
    Usage     : license_obj.license_install(vars.D1, "home://file_1.xml")
    """
    st.log('Entering function license_install() with args %s' %(str(locals())))

    command = "license install %s" %(file_path)
    output = st.config(dut, command, type="klish", skip_error_check=True, conf=False)
    output = output.replace("--sonic-mgmt--# ", "")

    if len(output) == 0:
        return True
    if "Unable to download file" in output:
        st.report_fail("test_case_failure_message", "License download failed")
    elif "Invalid username/password/URL" in output:
        st.report_fail("test_case_failure_message", "Invalid license path URL")
    elif "License information mismatch" in output:
        st.error("Mismatch in license information. License file maybe incorrect/invalid, corrupted, or expired")
        return False
    else:
        err_msg = "Unknown error : "+output
        st.report_fail("test_case_failure_message", err_msg)


def verify_license_details(dut, expected_status, sold_date):
    """
    This function checks if the expected license status & sold date matches parsed output.
    expected_status : license_not_found | license_invalid | license_valid | license_due_expiry | license_expired
    sold_date       : utc sold date fetched from license file

    Sample Parsed output:
    [{'vendor_name': 'Dell EMC', 'product_name': 'S5212F-ON', 'platform_name': 'X86_64-dellemc_s5212f_c3338-r0',
    'serial_number': 'TH0K6MG9CET0007T00OK', 'service_tag': '2W6RY03', 'software': 'ENTERPRISE-SONiC-PREMIUM-10G
    -3Y', 'version': 'licensing-dell-old-work-rebase.0-dirty-20221028.050055', 'license_status': 'Valid', 'licen
    se_type': 'SUBSCRIPTION', 'license_start_date': '2022-08-31T10:41:22Z', 'license_duration': '1035 days', 'li
    cense_location': '/etc/sonic/licenses/license.xml'}]

    Author : Almah Roshni
    Usage  : license_obj.verify_license_details(vars.D1, license_valid)
    """
    st.log('Entering function verify_license_details() with args %s' %(str(locals())))

    err_msg = ""
    result = True
    license_msg = {
        license_not_found  : "License not installed. Please install a valid license",
        license_invalid    : "License not valid. Please install a valid license",
        license_expired    : "License expired. Please install a valid license"
    }

    if ((expected_status == license_not_found) or \
        (expected_status == license_invalid) or \
        (expected_status == license_expired)):
        output = st.show(dut, "show license status", type="klish", skip_tmpl=True)
        if license_msg[expected_status] not in output:
            err_msg += "License output verification failed. Expected {}.".format(license_msg[expected_status])
            result = False
    else:
        output = st.show(dut, "show license status", type="klish")
        if len(output) == 0:
            err_msg += "License details not found/invalid/expired. "
            result = False
        else:
            if (output[0]['license_status'].lower() !=  expected_status.lower()):
                err_msg += "License status verification failed. Expected: {}, Observed: {}."\
                           .format(expected_status, output[0]['license_status'])
                result = False

            if (output[0]['license_start_date'].lower() != sold_date.lower()):
                err_msg += "License start date verification failed. Expected: {}, Observed: {}."\
                           .format(sold_date, output[0]['license_start_date'])
                result = False

    st.error(err_msg) if err_msg else st.log("License details verification success")
    return result



def verify_syslog(dut, license_status, retry_count = 2, sleep_duration = 5):
    """
    This function verifies syslog messages based on license status.
    license_status : Status of installed license
                   : license_not_found | license_invalid | license_valid | license_due_expiry | license_expired
    retry_count    : Number of retries if verification fails
    sleep_duration : Time in seconds to wait for next retry

    Author         : Almah Roshni
    Usage          : license_obj.verify_syslog(vars.D1, license_expired)
    """
    st.log('Entering function verify_syslog() with args %s' %(str(locals())))
    syslog_msg = {
        license_not_found  : "License Management: Dell Enterprise SONiC License is not found. Please install a valid license.",
        license_invalid    : "License Management: Dell Enterprise SONiC License is not valid. Please install a valid license.",
        license_valid      : "License Management: Dell Enterprise SONiC License is installed successfully.",
        license_expired    : "License Management: Dell Enterprise SONiC License expired. Please renew and install the new license.",
        license_due_expiry : "License Management: Dell Enterprise SONiC License is about to expire. Please renew and install the new license."
    }

    for itr in range(retry_count):
        st.log('Iteration : {}'.format(itr+1))
        if ((license_status == license_valid) or (license_status == license_due_expiry)):
            file = "/var/log/ramfs/in-memory-syslog-info.log"
        else:
            file = "/var/log/syslog"

        command = "sudo cat " + file + " | grep -i 'License Management' | tail -l"
        output = st.show(dut, command, skip_tmpl=True)

        if syslog_msg[license_status] in output:
            st.log("Syslog verification success")
            return True
        else:
            st.wait(sleep_duration)

    st.error("Syslog verification failed")
    return False


def verify_banner(dut, license_status):
    """
    This function checks login banner for license related warnings
    license_status : Status of installed license
                   : license_not_found | license_invalid | license_valid | license_due_expiry | license_expired
    return value   : True if banner verification is success, False otherwise
    Author         : Almah Roshni
    Usage          : license_obj.verify_banner(vars.D1, license_expired)
    """
    st.log('Entering function verify_banner() with args %s' %(str(locals())))
    err_msg = ""
    banner_msg = {
        license_not_found  : "Dell SONiC License is not found",
        license_invalid    : "Dell SONiC License is invalid",
        license_expired    : "Dell SONiC License expired"
    }

    command = "cat /etc/issue | grep -i 'Dell SONiC License'"
    output = st.show(dut, command, skip_tmpl=True)
    output = output.replace("admin@sonic:~$ ", "")

    if ((license_status == license_valid) or (license_status == license_due_expiry)):
        if len(output):
           err_msg += "Banner message observed for license state {}".format(license_status)
    elif banner_msg[license_status] not in output:
        err_msg += "Appropriate banner message not found. \nExpected: {}. Observed: {}".format(banner_msg[license_status], output)

    if err_msg:
        st.error(err_msg)
        return False
    st.log("Banner verification success")
    return True


def license_install_rest(dut, file_path):
    """
    This function installs a valid dell sonic license file using REST.
    file_path    : could be local home path, or a remote location.
    return value : Error messages if any, empty string otherwise
    Author       : Almah Roshni
    Usage        : license_obj.license_install_rest(vars.D1, "home://file_1.xml")
    """
    st.log('Entering function license_install_rest() with args %s' %(str(locals())))
    err_msg = ""
    requestBody = {
        "openconfig-license-mgmt-private:input":{
            "filename": file_path
        }
    }
    postOutput = st.open_config(dut, "/restconf/operations/openconfig-license-mgmt-private:install", \
                               action='create', data=requestBody, timeout=30)
    st.log("Output: {}".format(postOutput))
    if postOutput.status == 200:
        pot = postOutput.output
        if 'openconfig-license-mgmt-private:output' in pot:
            if pot['openconfig-license-mgmt-private:output']['status'] != 0:
                err_msg += pot['openconfig-license-mgmt-private:output']['status-detail']
        else:
            err_msg += "openconfig-license-mgmt-private:output not observed in REST output."
    else:
        err_msg += "Status of REST response is not success. "
    if not err_msg:
        st.log("License installation using REST success")
    return err_msg



def verify_license_details_rest(dut, expected_status, sold_date):
    st.log('Entering function verify_license_details_rest() with args %s' %(str(locals())))
    """
    This function checks if the expected license status & sold date matches parsed output.
    expected_status : license_not_found | license_invalid | license_valid | license_due_expiry | license_expired
    sold_date       : utc sold date fetched from license file

    Sample Parsed output:
    {"url": "https://100.104.24.55/restconf/data/openconfig-license-mgmt-private:license-management/state", "operation"
    : "GET", "status": 200, "input": null, "output": {"openconfig-license-mgmt-private:state": {"license": {"license-du
    ration": "1027 days (remaining)", "license-enabled": "true", "license-location": "/etc/sonic/licenses/license.xml",
    "license-status": "Valid", "license-type": "SUBSCRIPTION", "software-type": "ENTERPRISE-SONiC-PREMIUM-10G-3Y", "sta
    rt-date": "2022-08-31T10:41:22Z"}, "platform": {"mfg-name": "Dell EMC", "platform-name": "X86_64-dellemc_s5212f_c33
    38-r0", "product-version": "S5212F-ON", "serial-number": "TH0K6MG9CET0007T00OK", "service-tag": "2W6RY03", "softwar
    e-version": "licensing-dell-old-work-rebase.0-dirty-20221106.092424"}}}}

    Author       : Almah Roshni
    Usage        : license_obj.verify_license_details_rest(vars.D1, license_valid)
    """
    err_msg = ""
    result = True
    getOutput = st.open_config(dut, "/restconf/data/openconfig-license-mgmt-private:license-management/state", timeout=30)
    st.log("Output: {}".format(getOutput))
    if getOutput.status == 200 or getOutput.status is True:
        got = getOutput.output
        if "openconfig-license-mgmt-private:state" in got:
            if got["openconfig-license-mgmt-private:state"]['license']['license-status'] != expected_status:
                err_msg += "License status verification failed. Expected: {}, Observed: {}." \
                           .format(expected_status, got["openconfig-license-mgmt-private:state"]['license']['license-status'])
                result = False
            if (expected_status != license_not_found) and (expected_status != license_invalid):
                if got["openconfig-license-mgmt-private:state"]['license']['start-date'] != sold_date:
                    err_msg += "License start date verification failed. Expected: {}, Observed: {}." \
                               .format(sold_date, got["openconfig-license-mgmt-private:state"]['license']['start-date'])
                    result = False
        else:
            err_msg += "openconfig-license-mgmt-private:state not found in REST output."
            result = False
    else:
        err_msg += "Status of REST response is not success."
        result = False
    if err_msg:
        st.error(err_msg)
    else:
        st.log("License details verification using REST success")
    return result






