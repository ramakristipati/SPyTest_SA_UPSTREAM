import traceback

from spytest import st
from apis.yang.utils.gnmi import GNMIConnection, log_step

def get_gnoi_conn(dut, gnoi_pb2_grpc, service, save=True, connect=True, report=True, new_conn=False):
    """
    Create and return gNOI connection object for a gRPC service.
    :param dut:
    :param save:  To save the gNOI service config to DUT
    :param connect: To will get cert, create Stub and check for gNOI status.
    :param report: If connect fail - report.
    :param new_conn: Return New gNOI conn object.
    """
    cache_key = "gnoi_" + service
    conn = None if new_conn else st.get_cache(cache_key, dut)
    if not conn:
        conn = GNOIConnection(dut, gnoi_pb2_grpc, service)
        conn.setup(save)
        if not new_conn:
            st.set_cache(cache_key, conn, dut)
    if connect and not conn.isconnected():
        if not conn.connect():
            if report:
                st.report_env_fail('msg',\
    'Failed to create the gNOI {} service connection Object.'.format(service))
            return
    return conn

#
# Note: There could have been a common base class GRPCConnection, but in the
# interests of less code changes, sub-classing GNMIConnection for now
#
class GNOIConnection(GNMIConnection):

    def __init__(self, dut, gnoi_pb2_grpc, service):
        super().__init__(dut)

        self.__gnoi_channel = None
        self.__gnoi_stub = None
        self.__gnoi_pb2_grpc = gnoi_pb2_grpc
        self.__service = service
        log_step("GNOIConnection: service {}".format(service), dut=self.dut)

    def __gnoi_create_stub(self, cert):
        log_step("GNOI create stub...", dut=self.dut)
        ip_port = "{}:{}".format(self.mgmt_addr, self.mgmt_port)
        options = (('grpc.ssl_target_name_override', self.gnmi_hostname_on_cert),)
        gnoi_pb2_grpc = self.__gnoi_pb2_grpc
        if cert:
            creds = gnoi_pb2_grpc.grpc.ssl_channel_credentials(root_certificates=cert, private_key=None,
                                                               certificate_chain=None)
            self.__gnoi_channel = gnoi_pb2_grpc.grpc.secure_channel(ip_port, creds, options)
        else:
            self.__gnoi_channel = gnoi_pb2_grpc.grpc.insecure_channel(ip_port, options)
        self.__gnoi_stub = \
            getattr(gnoi_pb2_grpc, self.__service + 'Stub')(self.__gnoi_channel)

        st.log("GNOIConnection.__gnoi_create_stub: {}".format(str(\
            self.__gnoi_stub)))

    def isconnected(self):
        return bool(self.__gnoi_stub)

    def connect(self):
        log_step("GNOI connect...", dut=self.dut)
        if self.secure:
            log_step('Getting server cert for GNOI', dut=self.dut)
            cert = self._get_server_cert()
            if cert is not None:
                self.__gnoi_create_stub(cert)
            else:
                st.error('Unable to get server Cert for GNOI, GNOI Stub is not initialized')
                return False
        else:
            self.__gnoi_create_stub(None)
        ## TBD: Is there a Ping test on a __gnoi_stub ?
        #if not self.__check_gnmi_server_status():
        #    st.error('Telemetry server is not in working state, GNOI cases may fail')
        #    return False
        return True

    def disconnect(self):
        log_step("GNOI disconnect...", dut=self.dut)
        if self.__gnoi_channel:
            self.__gnoi_channel.close()
            self.__gnoi_channel = None
            self.__gnoi_stub = None
        if not self.gnmi_cert_preserve:
            log_step('Removing GNOI cert configurations', dut=self.dut)
            self.cleanup()

    def gnoi_execute(self, rpc, request=None, encoding='JSON_IETF', timeout=30):
        """Execute a gNOI RPC request.
           Args:
               rpc: RPC name
               request: The RPC request message
               encoding: gNMI encoding value; one of JSON, BYTES, PROTO, ASCII, JSON_IETF
           Returns:
               response = The RPC response message
        """
        log_step("GNOI RPC: {}".format(rpc), dut=self.dut)
        log_step("Request : {}".format(request), dut=self.dut)
        log_step("timeout : {}".format(timeout), dut=self.dut)

        try:
            response = getattr(self.__gnoi_stub, rpc)(request,
                                                      metadata=[('username', self.mgmt_user), ('password', self.mgmt_pass)],
                                                      timeout=timeout)
            log_step("Response : {}".format(response), dut=self.dut)
            return response, 0

        except Exception as err:
            st.error("execute: {}".format(err), self.dut)
            traceback.print_exc()
            return err, -1
