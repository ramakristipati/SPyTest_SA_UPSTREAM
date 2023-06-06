from spytest import st
from collections import OrderedDict
import copy


def compare_response_expected(response, expected, ignore_err=False):
    def __sort_dict_by_key(dst, src):
        key_map = dict()
        keys = list(src.keys())
        mod_keys = [k for k in keys]
        for ori, mod in zip(keys, mod_keys):
            key_map[mod] = ori
        mod_keys.sort()

        for key in mod_keys:
            value = src[key_map[key]]
            if isinstance(value, (OrderedDict, dict)):
                node = dst.setdefault(key, dict())
                __sort_dict_by_key(node, value)
            elif isinstance(value, list):
                dst.setdefault(key, list())
                for item in value:
                    if isinstance(item, (OrderedDict, dict)):
                        new_item = dict()
                        __sort_dict_by_key(new_item, item)
                        dst[key].append(new_item)
                    else:
                        dst[key].append(item)
            else:
                dst[key] = value
        return dst

    new_resp = dict()
    new_exp = dict()
    __sort_dict_by_key(new_resp, response)
    __sort_dict_by_key(new_exp, expected)

    st.debug(new_resp)
    st.debug(new_exp)
    ret = __compare_dict_internal(new_resp, new_exp, list(), ignore_err=ignore_err)
    if ret:
        st.log("Comparison done. Response matches expected values")

    return ret


def __compare_dict_internal(response, expected, path, ignore_err=False):
    if isinstance(expected, (dict, OrderedDict)):
        for key, value in expected.items():
            if key not in response:
                if not ignore_err:
                    st.error('{} not present in response'.format(key))
                return False

            if isinstance(value, (dict, OrderedDict)):
                path.append(key)
                ret = __compare_dict_internal(response[key], value, path, ignore_err=ignore_err)
                del path[-1]
                if not ret:
                    return False
            elif isinstance(value, list):
                if not isinstance(response[key], list):
                    if not ignore_err:
                        st.error('{} value expected is list found {}'.format(key, type(response[key])))
                    return False

                resp_list = response[key]
                if len(value) > len(resp_list):
                    if not ignore_err:
                        st.error('{} expects {}items. Found {}'.format(key, len(value), len(resp_list)))
                    return False

                new_resp_list = copy.deepcopy(resp_list)
                for item in value:
                    match = False
                    resp_idx = -1
                    for resp_item in new_resp_list:
                        resp_idx += 1
                        path.append(key)
                        if __compare_dict_internal(resp_item, item, path, ignore_err=True):
                            match = True
                            break
                        del path[-1]

                    if not match:
                        if not ignore_err:
                            st.error('{} not found in response'.format(item))
                        return False
                    else:
                        del new_resp_list[resp_idx]
            elif value is None:
                if response[key] is not None:
                    if not ignore_err:
                        st.error('Key:{} Value:{} doesnt match {}'.format(key, value, response[key]))
                    return False
            else:
                if type(response[key])(value) != response[key]:
                    if not ignore_err:
                        st.error('Key:{} Value:{} doesnt match {}'.format(key, value, response[key]))
                    return False
        return True
    elif isinstance(response, (str, int, bool)):
        if response != type(response)(expected):
            if not ignore_err:
                st.error('{} doesnt match {}'.format(expected, response))
            return False
        else:
            return True
    else:
        st.error('Unhandled type {}'.format(type(expected)))
