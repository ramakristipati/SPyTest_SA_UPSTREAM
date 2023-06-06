import copy
import json
import pprint
from deepdiff import DeepDiff

from collections import OrderedDict
from six.moves.urllib.parse import quote  # pylint: disable=import-error

from spytest import st

from apis.system.rest import config_rest, get_rest, delete_rest
#from apis.yang.utils.common import get_audit_msg

from utilities import common as utils

def remove_yang_module_name(key, yang="openconfig-"):
    if utils.is_unicode_string(key) and key.startswith(yang):
        return key.split(":", 1)[-1]
    return key


def remove_module_names_and_sort(dst, src, yang="openconfig-"):
    key_map = dict()
    keys = list(src.keys())
    mod_keys = [remove_yang_module_name(k, yang) if utils.is_unicode_string(k) else k for k in keys]
    for ori, mod in zip(keys, mod_keys):
        key_map[mod] = ori
    mod_keys.sort()

    for key in mod_keys:
        value = src[key_map[key]]
        if isinstance(value, (OrderedDict, dict)):
            node = dst.setdefault(key, dict())
            remove_module_names_and_sort(node, value)
        elif isinstance(value, list):
            dst.setdefault(key, list())
            for item in value:
                if isinstance(item, (OrderedDict, dict)):
                    new_item = dict()
                    remove_module_names_and_sort(new_item, item)
                    dst[key].append(new_item)
                elif isinstance(item, int) or utils.is_unicode_string(item):
                    dst[key].append(remove_yang_module_name(item, yang))
                else:
                    dst[key].append(item)
        elif utils.is_unicode_string(value):
            dst[key] = remove_yang_module_name(value, yang)
        else:
            dst[key] = value
    return dst


def compare_rest_payloads(response, expected, yang="openconfig-", ignore_err=False, match_subset=True):
    if utils.is_unicode_string(response):
        response = json.loads(response)
    if utils.is_unicode_string(expected):
        expected = json.loads(expected)

    new_resp = dict()
    new_exp = dict()
    remove_module_names_and_sort(new_resp, response)
    remove_module_names_and_sort(new_exp, expected)

    # st.debug(new_resp)
    # st.debug(new_exp)
    ret = __compare_rest_payload_internal(new_resp, new_exp, list(), yang=yang, ignore_err=ignore_err,
                                          match_subset=match_subset)
    if ret:
        st.log("Comparison done. Response matches expected values")
    else:
        # st.debug("Response : {}".format(new_resp))
        # st.debug("Expected : {}".format(new_exp))
        st.error("Comparison done. Response Not matches expected values")

    return ret


def __compare_rest_payload_internal(response, expected, path, yang="openconfig-", ignore_err=False, match_subset=True):
    # st.debug("Path is {}".format(path))
    is_key_miss = 0
    if isinstance(expected, (dict, OrderedDict)):
        if not match_subset:
            if len(response) != len(expected):
                st.log("__compare_rest_payload_internal: mismatch response items length: {} and"
                       " expected response items length {}".format(len(response), len(expected)))
                st.log("Observed: {}".format(pprint.pformat(response)))
                st.log("Expected: {}".format(pprint.pformat(expected)))
                if not ignore_err:
                    st.error('Expected number of items {}. Found {}'.format(len(expected), len(response)))
                return False

        for key, value in expected.items():
            if key not in response:
                if not ignore_err:
                    st.error("Key:{}, Value:{} not present in response of path {}".format(key, expected[key], path))
                is_key_miss = 1
        if is_key_miss:
            if not ignore_err:
                # st.error('Observed - {}'.format(response))
                st.error('Expected - {}'.format(expected))
            return False

        for key, value in expected.items():
            # st.debug("Compare Key {}".format(key))

            if isinstance(value, (dict, OrderedDict)):
                # st.debug("Value is dict")
                path.append(key)
                ret = __compare_rest_payload_internal(response[key], value, path, yang=yang, ignore_err=ignore_err,
                                                      match_subset=match_subset)
                del path[-1]
                if not ret:
                    return False
            elif isinstance(value, list):
                # st.debug("Value is list")
                if not isinstance(response[key], list):
                    if not ignore_err:
                        st.error('{} value expected is list found {}'.format(key, type(response[key])))
                        # st.error('Observed - {}'.format(response))
                        st.error('Expected - {}'.format(expected))
                    return False

                resp_list = response[key]
                if not match_subset:
                    if len(value) != len(resp_list):
                        st.log("__compare_rest_payload_internal: mismatch response items length: {} and"
                               " expected response items length {}".format(len(resp_list), len(value)))
                        st.log("Observed: {}".format(pprint.pformat(resp_list)))
                        st.log("Expected: {}".format(pprint.pformat(value)))
                        if not ignore_err:
                            st.error('{} expects {} items. Found {}'.format(key, len(value), len(resp_list)))
                        return False
                else:
                    if len(value) > len(resp_list):
                        if not ignore_err:
                            st.error('{} expects {} items. Found {}'.format(key, len(value), len(resp_list)))
                            # st.error('Observed - {}'.format(response))
                            st.error('Expected - {}'.format(expected))
                        return False

                new_resp_list = copy.deepcopy(resp_list)
                for item in value:
                    match = False
                    resp_idx = -1
                    for resp_item in new_resp_list:
                        resp_idx += 1
                        path.append(key)
                        if __compare_rest_payload_internal(resp_item, item, path, yang=yang, ignore_err=ignore_err,
                                                           match_subset=match_subset):
                            # st.debug("Item found in list")
                            match = True
                            break
                        del path[-1]

                    if not match:
                        if not ignore_err:
                            st.error('{} not found in response'.format(item))
                        return False
                    else:
                        del new_resp_list[resp_idx]
            elif utils.is_unicode_string(value) and utils.is_unicode_string(response[key]):
                # st.debug("Value is string {} vs {}".format(value, response[key]))
                if remove_yang_module_name(value, yang=yang) != remove_yang_module_name(response[key], yang=yang):
                    if not ignore_err:
                        st.error('Key:{} Value:{} doesnt match {}'.format(key, value, response[key]))
                        # st.error('Observed - {}'.format(response))
                        st.error('Expected - {}'.format(expected))
                    return False
            else:
                # st.debug("Value is Other {} {} vs {}".format(type(value), value, response[key]))
                if type(response[key])(value) != response[key]:
                    if not ignore_err:
                        st.error('Key:{} Value:{} doesnt match {}'.format(key, value, response[key]))
                        # st.error('Observed - {}'.format(response))
                        st.error('Expected - {}'.format(expected))
                    return False

        # Finally return true as all elements of dict matched
        # st.debug("All matched")
        return True
    elif isinstance(response, (int, bool)) or utils.is_unicode_string(response):
        if response != type(response)(expected):
            if not ignore_err:
                st.error('{} doesnt match {}'.format(expected, response))
            return False
        else:
            return True
    else:
        st.exception('Unhandled type {}'.format(type(expected)))


def get_url_with_params(url, params):
    if params is None:
        params = dict()
    else:
        params = {k: quote(str(v), safe='') for k, v in params.items()}

    return url.format(**params)


def ret_response(response):
    try:
        st.log(json.dumps(response, indent=2))
    except Exception:
        pass
    return response['output']


def rest_post(dut, url, payload, params=None, success=True, ignore_error=False, is_rpc=False, complete_resp=False,
              **kwargs):
    url = get_url_with_params(url, params)
    full_url = '/restconf/data{}'.format(url)

    dmsg = '\nPOST::{}\n'.format(full_url)
    if isinstance(payload, (dict, list)):
        dmsg = dmsg + json.dumps(payload, indent=2)
    else:
        dmsg = dmsg + payload
        payload = json.loads(payload)

    #st.audit(get_audit_msg(dut, dmsg), split_lines=False)

    response = config_rest(dut, http_method="rest-post", rest_url=full_url, json_data=payload, params=params,
                           get_response=True, **kwargs)
    if complete_resp:
        return response
    else:
        return ret_response(response)


def rest_patch(dut, url, payload, params=None, success=True, ignore_error=False, complete_resp=False, **kwargs):
    url = get_url_with_params(url, params)
    full_url = '/restconf/data{}'.format(url)

    dmsg = '\nPATCH::{}\n'.format(full_url)
    if isinstance(payload, (dict, list)):
        dmsg = dmsg + json.dumps(payload, indent=2)
    else:
        dmsg = dmsg + payload
        payload = json.loads(payload)

    #st.audit(get_audit_msg(dut, dmsg), split_lines=False)

    response = config_rest(dut, http_method="rest-patch", rest_url=full_url, json_data=payload, params=params,
                           get_response=True, **kwargs)
    if complete_resp:
        return response
    else:
        return ret_response(response)


def rest_put(dut, url, payload, params=None, success=True, ignore_error=False, complete_resp=False, **kwargs):
    url = get_url_with_params(url, params)
    full_url = '/restconf/data{}'.format(url)

    dmsg = '\nPUT::{}\n'.format(full_url)
    if isinstance(payload, (dict, list)):
        dmsg = dmsg + json.dumps(payload, indent=2)
    else:
        dmsg = dmsg + payload
        payload = json.loads(payload)

    #st.audit(get_audit_msg(dut, dmsg), split_lines=False)

    response = config_rest(dut, http_method="rest-put", rest_url=full_url, json_data=payload, params=params,
                           get_response=True, **kwargs)
    if complete_resp:
        return response
    else:
        return ret_response(response)


def rest_delete(dut, url, params=None, success=True, ignore_error=False, complete_resp=False, **kwargs):
    url = get_url_with_params(url, params)
    full_url = '/restconf/data{}'.format(url)
    #dmsg = '\nDELETE::{}\n'.format(full_url)
    #st.audit(get_audit_msg(dut, dmsg), split_lines=False)

    response = delete_rest(dut, rest_url=full_url, params=params, get_response=True, **kwargs)
    if complete_resp:
        return response
    else:
        return ret_response(response)


def rest_get(dut, url, params=None, success=True, ignore_error=False, complete_resp=False, **kwargs):
    url = get_url_with_params(url, params)
    full_url = '/restconf/data{}'.format(url)
    #dmsg = '\nGET::{}\n'.format(full_url)
    #st.audit(get_audit_msg(dut, dmsg), split_lines=False)

    response = get_rest(dut, rest_url=full_url, params=params, get_response=True, **kwargs)
    if complete_resp:
        return response
    else:
        return ret_response(response)

class Bulk():
    """
    Class to create a YANG Patch request
    """

    def __init__(self, patch_id="", comment=None):
        """
        Returns a payload template for YANG Patch request
        """
        self.req = {
            "ietf-yang-patch:yang-patch": {
                "patch-id": patch_id,
                "edit": []
            }
        }
        if comment is not None:
            self.req["ietf-yang-patch:yang-patch"]["comment"] = comment

    def __fill_request(self, operation, target, payload={}, edit_id=""):
        edit_obj = {
            "target": str(target),
            "operation": operation
        }
        if len(edit_id) > 0:
            edit_obj["edit-id"] = edit_id
        if len(payload) > 0:
            edit_obj["value"] = payload
        self.req["ietf-yang-patch:yang-patch"]["edit"].append(edit_obj)

    def create(self, target, payload={}, edit_id=""):
        self.__fill_request("create", target, payload, edit_id)

    def replace(self, target, payload={}, edit_id=""):
        self.__fill_request("replace", target, payload, edit_id)

    def merge(self, target, payload={}, edit_id=""):
        self.__fill_request("merge", target, payload, edit_id)

    def delete(self, target, edit_id=""):
        self.__fill_request("delete", target, edit_id=edit_id)

    def remove(self, target="/", edit_id=""):
        self.__fill_request("remove", target, edit_id=edit_id)


class EditResp():
    def __init__(self, status=True, payload=[]):
        self.status = status
        self.payload = payload


def verify_yang_patch_response(resp, global_status, edit_resp_list=[], exp_status=200):
    if resp.status != exp_status:
        return False

    is_ok = False
    if 'ok' in resp.output['ietf-yang-patch:yang-patch-status']:
        is_ok = True
    if global_status != is_ok:
        st.error("Global status did not match")
        return False

    recv_resp_list = resp.output['ietf-yang-patch:yang-patch-status']['edit-status']['edit']

    if len(edit_resp_list) != len(recv_resp_list):
        st.error("mismatch in number of edit response")
        return False

    for index, zip_resp in enumerate(zip(recv_resp_list, edit_resp_list)):
        recv_resp, edit_resp = zip_resp
        is_ok = False
        if 'ok' in recv_resp:
            is_ok = True
        if edit_resp.status != is_ok:
            st.error("Error status did not match for {}th edit".format(index))
            return False
        recv_err = []
        if 'errors' in recv_resp:
            if 'error' in recv_resp["errors"]:
                recv_err = recv_resp["errors"]["error"]
        payload_diff = DeepDiff(recv_err, edit_resp.payload)
        if len(payload_diff) > 0:
            st.error("mismatch in error payload for {}th edit, {}".format(index, payload_diff))
            return False

    return True
