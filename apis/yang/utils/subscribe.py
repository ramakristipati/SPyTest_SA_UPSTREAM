##
# This file contains APIs and utilities to test gNMI subscriptions
# using the message classes (instead of raw path and payload json).
#

from abc import ABC, abstractmethod
from os.path import join
from pytest import fixture

from apis.yang.codegen.error_constants import OK, UNKNOWN, VALIDATION_FAILED
from apis.yang.codegen.response import Response
from apis.yang.utils import gnmi
from apis.yang.utils.common import NorthBoundApi, resolve_targets, validate_response
from spytest import st
from utilities.common import make_list2


def start_subscribe(dut, mode, path_infos, timeout=30, target=None, origin=None, updates_only=False,
                    auto_close=True, new_conn=False):
    """Creates gNMI subscription for paths. Returns a RpcContext object which can be used for
    validating the notification messages.

    Parameters:
    dut             DUT name
    mode            Subscription mode -- should be one of "on_change", "sample", "target_defined",
                    "poll" or "once". Values are case insensitive.
    path_infos      A PathInfo object or list of PathInfo objects indicating paths to subscribe to.
    timeout         Hard timeout for test case; in seconds. Used to break verification loop when
                    expected notifications are not received. It is recommended that developers pass
                    an appropriate timeout value based on the verification steps in the test case.
                    Default timeout is 30 seconds.
    target          A string value to be used as 'target' property of request path prefix.
    origin          A string value to be used as 'origin' property of request path prefix.
    updates_only    Boolean value for the 'updates_only' property in the request.
    auto_close      Indicate if the rpc should be tracked for automatic cleanup via subscribe_cleanup
                    fixture. Enabled by default.
    new_conn        True for new gNMI connection context.
    """
    conn = gnmi.get_gnmi_conn(dut, new_conn=new_conn)
    mode = mode.lower().replace("-", "_")
    paths = []
    for pi in make_list2(path_infos):
        paths.extend(pi.path_list)

    if mode == "on_change":
        rpc = conn.gnmi_subscribe_onchange(
            paths, target=target, origin=origin, timeout=timeout, updates_only=updates_only)
    elif mode == "sample":
        rpc = conn.gnmi_subscribe_sample(
            paths, target=target, origin=origin, timeout=timeout, updates_only=updates_only)
    elif mode == "target_defined":
        rpc = conn.gnmi_subscribe_target_defined(
            paths, target=target, origin=origin, timeout=timeout, updates_only=updates_only)
    elif mode == "poll":
        rpc = conn.gnmi_subscribe_poll(
            paths, target=target, origin=origin, timeout=timeout, updates_only=updates_only)
    elif mode == "once":
        rpc = conn.gnmi_subscribe_once(
            paths, target=target, origin=origin, timeout=timeout, updates_only=updates_only)
    else:
        raise ValueError("Invalid subscription mode: " + mode)

    ctx = RpcContext(rpc)
    if auto_close and ctx.ok():
        # Save in spytest cache for automatic cleanup later.
        context_cache = st.get_cache("__subscribe_context_cache")
        if context_cache:
            context_cache.append(ctx)
        else:
            st.set_cache("__subscribe_context_cache", [ctx])

    return ctx


class PathInfo:
    """PathInfo is a set of gNMI paths with its subscription options."""

    def __init__(self, msg_obj, target_attr=None, target_path=None,
                 sample_interval=None, suppress_redundant=False, heartbeat_interval=None):
        self.path_list = []
        for target in resolve_targets(msg_obj, target_attr, target_path):
            p = gnmi.GnmiSubscribeOptions(
                path=to_path(msg_obj, target.attr, target.path),
                suppress_redundant=suppress_redundant,
                sample_interval=sample_interval,
                heartbeat_interval=heartbeat_interval)
            self.path_list.append(p)


class RpcContext(Response):
    def __init__(self, rpc):
        super().__init__(ui=NorthBoundApi.GNMI)
        self.__rpc = None   # gnmi.SubscribeRpc
        self.__is_err = False  # rpc failed
        err = None
        if isinstance(rpc, gnmi.gNMIError):
            err = rpc
        elif isinstance(rpc, gnmi.SubscribeRpc):
            err = rpc.error
        else:
            raise ValueError("Invalid rpc param: {}".format(type(rpc)))
        if err:
            self._set_gnmi_error(err)
        else:
            self.status = OK
            self.__rpc = rpc

    def _set_gnmi_error(self, err):
        """Sets error status from a gNMIError object"""
        self.status = err.code
        self.message = err.details
        self.data = err
        self.__is_err = True

    def verify(self, notifications, sync=False, success=True, **kwargs):
        """Verify expected notification values are received. Blocks till expected values
        are received or the timeout (specified in the subscribe API) and returns True.
        Returns False as soon as it encounters an unexpected notification data.

        Parameters:
        notifications
                A Notification object or a list of Notification objects indicating the
                expected notification data.
        sync    Indicates whether a sync message is expected. When True, this function
                waits for a sync message after expected notification data is received.
                It is an error if sync message is received when it is not expected or
                all expected notification data are not received yet.
        """
        if self.__is_err:
            return False
        if not notifications and not sync:
            raise ValueError("Nothing to verify")

        self.status = UNKNOWN
        exp_updates = {}
        exp_deletes = []
        for n in make_list2(notifications):
            update_values, delete_paths = n.decode()
            if update_values:
                exp_updates.update(update_values)
            if delete_paths:
                exp_deletes.extend(delete_paths)

        rpc = self.__rpc
        is_ok = gnmi.verify_notifications(rpc, exp_updates, exp_deletes, sync_response=sync, **kwargs)

        if rpc.error is not None:
            is_ok = False
            self._set_gnmi_error(rpc.error)
        elif not is_ok:
            self.status = VALIDATION_FAILED
        else:
            self.status = OK
        validate_response("", "Subcribe", success, self, target_attr=None, target_path=None, **kwargs)
        return is_ok

    def poll(self, notifications, success=True, **kwargs):
        """Sends a gNMI poll message to the DUT and verifies the notifications.
        Should be used only when the subscription is created with mode="poll".
        Waits till all the expected notifications are received followed by a
        sync message; or a timeout.
        """
        if self.__is_err:
            return False
        self.__rpc.poll()
        return self.verify(notifications, sync=True, success=success, **kwargs)

    def discard_sync(self):
        """Receives and discards the sync notifications. Waits till a sync message
        is received or timeout.
        """
        if self.__is_err:
            return False
        is_ok = self.__rpc.clear_initial_sync()
        if self.__rpc.error:
            is_ok = False
            self._set_gnmi_error(self.__rpc.error)
        else:
            self.status = OK if is_ok else UNKNOWN
        return is_ok

    def close(self):
        """Close the subscribe rpc."""
        if self.__rpc:
            self.__rpc.cancel()


class Notification(ABC):
    """Abstract base class to express expected notification data"""

    @abstractmethod
    def decode(self):
        """Returns a tuple containing update values and delete paths contained in this object.
        Update values will be a dict of path to json data.
        """
        pass


class UpdateNotification(Notification):
    def __init__(self, msg_obj, target_attr=None, target_path=None, iterations=1, interval=20):
        """Expected update notification data.
        Parameters:
        msg_obj     A message class containing the expected notification data.
                    If this message class has a parent message in the class hierarchy, the parent
                    context should be filled.
        target_attr Property name indicating the subpath inside the message class.
        target_path Subpath inside the message class.
                    Only one of target_attr or target_path can be specified.
        iterations  Expected number of notification messages containing the values in data class.
        interval    Number of seconds between notifications when iterations > 1.
        """
        self.path_values = {}
        for target in resolve_targets(msg_obj, target_attr, target_path):
            p = gnmi.PathEntry(path=to_path(msg_obj, target.attr, target.path),
                               iteration=iterations, interval=interval)
            v = msg_obj.get_ietf_json(target_attr=target.attr, target_path=target.path)
            self.path_values[p] = v

    def decode(self):
        return self.path_values, None


class DeleteNotification(Notification):
    def __init__(self, msg_obj, target_attr=None, target_path=None):
        """Expecteds delete notification path.
        Parameters:
        msg_obj     A message class or string path indicating the expected delete path.
        target_attr Property name indicating the subpath inside the message class.
        target_path Subpath inside the message class.
                    Only one of target_attr or target_path can be specified.
        """
        self.path_list = []
        for target in resolve_targets(msg_obj, target_attr, target_path):
            p = to_path(msg_obj, target.attr, target.path)
            self.path_list.append(p)

    def decode(self):
        return None, self.path_list


def to_path(msg_obj, target_attr, target_path):
    if isinstance(msg_obj, str):
        if target_attr:
            raise ValueError("target_attr not expected when msg is a string")
        return join(msg_obj, target_path) if target_path else msg_obj
    return msg_obj.get_path(ui=NorthBoundApi.GNMI,
                            target_attr=target_attr, target_path=target_path)


@fixture
def subscribe_cleanup():
    yield
    context_cache = st.get_cache("__subscribe_context_cache", default=[])
    st.del_cache("__subscribe_context_cache")
    st.log("subscribe_cleanup: Found {} RpcContext objects".format(len(context_cache)))
    for ctx in context_cache:
        try:
            ctx.close()
        except:
            st.exception("Error closing the subscription")


def is_invalid_path(dut, path, exp_error='INVALID_ARGUMENT', mode='on_change', timeout=1):
    """Test subscription with invalid path"""
    from apis.yang.codegen import error_constants
    ctx = start_subscribe(dut, mode=mode, path_infos=PathInfo(path), timeout=timeout)
    ctx.verify(None, success=False, sync=True)
    if ctx.status != getattr(error_constants, exp_error):
        st.error("Error not match : Expected ({}); found {}".format(exp_error, ctx.status))
        return False
    else:
        st.log("Error matched : Expected ({}); found {}".format(exp_error, ctx.status))
        return True


def gnmi_verify_notification(obj, ctx, interval=20, iterations=2, target_attr=None, target_path=None,
                             mode='on_change', sync=False, **kwargs):

    if mode == 'sample' and not sync:
        ctx.verify(UpdateNotification(obj, target_attr=target_attr, target_path=target_path, iterations=iterations,
                                      interval=interval), **kwargs)
    elif mode == 'poll' and not sync:
        for i in range(1, iterations+1):
            st.log("Validating Poll iteration - {}".format(i))
            ctx.poll(UpdateNotification(obj, target_attr=target_attr, target_path=target_path), **kwargs)
            st.wait(interval)
    else:
        ctx.verify(UpdateNotification(obj, target_attr=target_attr, target_path=target_path), sync=sync, **kwargs)