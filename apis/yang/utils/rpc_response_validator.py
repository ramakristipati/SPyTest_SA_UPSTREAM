
import traceback
from enum import Enum
from abc import abstractmethod

from spytest import st

from apis.yang.utils.common import NorthBoundApi
from apis.yang.utils.rest import compare_rest_payloads
from apis.yang.codegen.response import Response
from apis.yang.codegen.error_constants import DATA_MATCH_FAILED

class EncodingType(Enum):
    """Specifies the encoding type of the response payload
    """
    JSON_IETF = 1

class RpcResponseValidator():
    """Verifies the actual response with the expected response.

       Parameters:
           dut          switch related information
           response     response of the GET request
           ui           name of the northbound interface
           encodingType encoding type of the response payload
           match_subset If True, comparison will also be successful if the subset of
                        the message data matches the switch response.
    """

    def __init__(self, dut, response, ui, encodingType, match_subset=False):
        self.dut = dut
        self.actualResp = response
        if ui not in [NorthBoundApi.REST, NorthBoundApi.GNMI]:
            raise ValueError("Unsupported UI: {}".format(ui))
        st.log("RpcResponseValidator: ui: {}; match_subset: {}; response: {}".format(ui, match_subset, response), self.dut)
        self.nbIntf = ui
        self.encodingType = encodingType
        self.match_subset = match_subset

    def verify(self, expectedResponse):
        retResp = Response(ui=self.nbIntf)
        try:
            status = False
            if self.nbIntf == NorthBoundApi.REST:
                getResp = RestRpcResponse(self.dut, self.actualResp, self.encodingType, self.match_subset)
                isSuccess = getResp.verify(expectedResponse)
                retResp.payload = None
                if getResp.statusCode != 200 and expectedResponse is None:
                    retResp.status = 200
                else:
                    retResp.status = getResp.statusCode
                    retResp.data = getResp.respPayload
                    retResp.payload = getResp.respPayload
                    if not isSuccess:
                        retResp.status = DATA_MATCH_FAILED
            elif self.nbIntf == NorthBoundApi.GNMI:
                getResp = GnoiRpcResponse(self.dut, status, self.actualResp, self.encodingType, self.match_subset)
                isSuccess = getResp.verify(expectedResponse)
                retResp.payload = None
                if getResp.status != 200 and expectedResponse is None:
                    retResp.status = 200
                else:
                    retResp.status = getResp.status
                    retResp.data = getResp.response
                    retResp.payload = getResp.getPayload()
                    if not isSuccess:
                        retResp.status = DATA_MATCH_FAILED
            return retResp
        except Exception as e:
            st.error("RpcResponseValidator: verify: Exception: {}".format(e), self.dut)
            traceback.print_exc()
            return retResp


class ResponseComparator:
    """Abstract base class to represent the different derived class comparator
       based on the type of the response
    """

    @abstractmethod
    def compare(self, actual, expected):
        pass


class RestIetfJsonComparator(ResponseComparator):
    """REST GET response comparator to compare the actual and expected IETF JSON response payload
    """

    def __init__(self, dut, match_subset=False):
        self.dut = dut
        self.match_subset = match_subset

    def compare(self, actual, expected):
        st.log("RestIetfJsonComparator: compare: actual json payload: {}".format(actual), self.dut)
        st.log("RestIetfJsonComparator: compare: expected json payload: {}".format(expected), self.dut)
        if actual is None:
            return False
        return compare_rest_payloads(actual, expected, match_subset=self.match_subset)


class RestErrorObject:
    """To represent the error object in the REST GET error response

       Parameters:
           error_message  error message of the response
           error_type     type of the error
           error_tag      error tag of the response
    """

    def __init__(self, error_message, error_type, error_tag):
        self.error_message = error_message
        self.error_type = error_type
        self.error_tag = error_tag

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "error_message: % s; error_type: % s; error_tag: % s" % (self.error_message, self.error_type, self.error_tag)

    def compare(self, expErrObj):
        if len(expErrObj.error_message) > 0 and self.error_message != expErrObj.error_message:
            return False
        if len(expErrObj.error_type) > 0 and self.error_type != expErrObj.error_type:
            return False
        if len(expErrObj.error_tag) > 0 and self.error_tag != expErrObj.error_tag:
            return False
        return True


class RestErrorResponse:
    """To represent the REST error response object.

       Parameters:
           status_code    status code of the error response
           error_message  error message of the response
           error_type     type of the error
           error_tag      error tag of the response
    """

    def __init__(self, dut, status_code, error_message="", error_type="", error_tag=""):
        self.dut = dut
        self.status_code = status_code
        self.errors = []
        if len(error_message) > 0 or len(error_type) > 0 or len(error_tag) > 0:
            self.errors.append(RestErrorObject(error_message, error_type, error_tag))

    def addErrorInfo(self, error_message, error_type="", error_tag=""):
        self.errors.append(RestErrorObject(str(error_message), str(error_type), str(error_tag)))

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        str = "status_code : % s; " % (self.status_code)
        for err in self.errors:
            str = str + err.__str__() + "\n"
        return str

    def compare(self, expErrObj):
        st.log("RestErrorResponse: compare: actual error object: {}".format(self), self.dut)
        st.log("RestIetfJsonComparator: compare: expected error object: {}".format(expErrObj), self.dut)
        if self.status_code != expErrObj.status_code:
            return False
        if len(expErrObj.errors) > 0:
            if len(self.errors) != len(expErrObj.errors):
                return False
            for idx in range(len(self.errors)):
                if self.errors[idx].compare(expErrObj.errors[idx]) is False:
                    return False
        return True

    @staticmethod
    def buildErrorResponseObject(dut, errorResp, encodingType=EncodingType.JSON_IETF):
        if encodingType == EncodingType.JSON_IETF:
            errRespObj = RestErrorResponse(dut, errorResp["status"])
            for _, errJsonList in errorResp["output"]["ietf-restconf:errors"].items():
                for errJson in errJsonList:
                    errRespObj.addErrorInfo(errJson["error-message"], errJson["error-type"], errJson["error-tag"])
                    return errRespObj
        else:
            st.error("buildErrorResponseObject: Invalid response payload encoding: {}".format(encodingType), dut)
            return None


class RestRpcResponse:
    """To represent the REST GET response object.

       Parameters:
           resp          actual response of the REST GET command
           encodingType  encoding type of the response payload
    """

    def __init__(self, dut, resp, encodingType=EncodingType.JSON_IETF, match_subset=False):
        self.dut = dut
        self.resp = resp
        self.encodingType = encodingType
        self.statusCode = None
        self.respPayload = None
        self.parseResponse()
        self.setComparator(match_subset)

    def setComparator(self, match_subset=False):
        if self.encodingType == EncodingType.JSON_IETF:
            self.comparator = RestIetfJsonComparator(self.dut, match_subset)
        else:
            st.error("RestRpcResponse: setComparator:  Invalid encoding type: {}".format(self.encodingType), self.dut)
            raise Exception("Error: Invalid encoding type: " + str(self.encodingType))

    def verifyPayload(self, expectedResp):
        if self.encodingType != EncodingType.JSON_IETF:
            st.error("RestRpcResponse: verifyPayload: Invalid response payload encoding: {}".format(self.encodingType), self.dut)
            return False
        return self.comparator.compare(self.respPayload, expectedResp)

    def verifyErrorResponse(self, expectedErrResp):
        actualErrResp = RestErrorResponse.buildErrorResponseObject(self.dut, self.resp, self.encodingType)
        return actualErrResp.compare(expectedErrResp)

    def parseResponse(self):
        if self.encodingType == EncodingType.JSON_IETF:
            if "status" in self.resp:
                self.statusCode = self.resp["status"]
            if "output" in self.resp:
                self.respPayload = self.resp["output"]

    def verify(self, expectedResp=None):
        try:
            if isinstance(expectedResp, RestErrorResponse):
                return self.verifyErrorResponse(expectedResp)
            elif isinstance(expectedResp, dict):
                if self.statusCode == 200:
                    return self.verifyPayload(expectedResp)
                else:
                    st.error("RestRpcResponse: verify: Invalid get response status code: {}".format(self.statusCode), self.dut)
                    return False
            else:
                st.error("RestRpcResponse: verify: Invalid expected response object: {}".format(type(expectedResp)), self.dut)
                return False
        except Exception as e:
            st.error("RestRpcResponse: verify: Exception: {}".format(e), self.dut)
            traceback.print_exc()
            return False


class GNOIErrorResponse():
    """To represent the GNMI Error response object.

       Parameters:
           status_code    status code of the error response
           error_message  error message of the response
    """

    def __init__(self, status_code, error_message=""):
        self.status_code = status_code
        self.error_message = error_message

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "status_code: % s; error_message: % s" % (self.status_code, self.error_message)


class GnoiRpcResponseComparator(ResponseComparator):
    """GNMI GET response comparator to compare the actual and expected response
    """

    def __init__(self, dut, match_subset=False):
        self.dut = dut
        self.match_subset = match_subset

    def compare(self, actual, expected):
        st.log("GnoiRpcResponseComparator: compare: actual json payload: {}".format(actual), self.dut)
        st.log("GnoiRpcResponseComparator: compare: expected json payload: {}".format(expected), self.dut)
        if actual is None:
            return False
        return compare_rest_payloads(actual, expected, match_subset=self.match_subset)


class GnoiRpcResponse:
    """To represent the GNMI GET response details

       Parameters:
           status       status code of the GNMI GET response
           response     response payload of the GNMI GET request
           encodingType encoding type of the GNMI GET response payload
    """

    def __init__(self, dut, status, response, encodingType=EncodingType.JSON_IETF, match_subset=False):
        self.dut = dut
        self.status = status
        self.response = response
        self.encodingType = encodingType
        self.setComparator(match_subset)

    def setComparator(self, match_subset=False):
        if self.encodingType == EncodingType.JSON_IETF:
            self.comparator = GnoiRpcResponseComparator(self.dut, match_subset)
        else:
            st.error("GnoiRpcResponse: setComparator:  Invalid encoding type: {}".format(self.encodingType), self.dut)
            raise Exception("Error: Invalid encoding type: " + str(self.encodingType))

    def getPayload(self):
        if self.encodingType == EncodingType.JSON_IETF:
            payload = self.response['output']
            st.log("GnoiRpcResponse: actual response payload: {}".format(payload), self.dut)
            return payload
        else:
            return None

    def verifyErrorResponse(self, expectedErrResp):
        st.log("GnoiRpcResponse: verifyErrorResponse: actual error: {}".format(self.response), self.dut)
        st.log("GnoiRpcResponse: verifyErrorResponse: expected error: {}".format(expectedErrResp), self.dut)
        return self.response.verify(expectedErrResp.status_code, expectedErrResp.error_message)

    def verify(self, expectedResp=None):
        try:
            if isinstance(expectedResp, GNOIErrorResponse):
                return self.verifyErrorResponse(expectedResp)
            elif isinstance(expectedResp, dict):
                if self.status != 0:
                    return False
                return self.verifyPayload(expectedResp)
            else:
                st.error("GnoiRpcResponse: verify:  Invalid expected response: {}".format(type(expectedResp)), self.dut)
                return False
        except Exception as e:
            st.error("GnoiRpcResponse: verify:  Exception: {}".format(e), self.dut)
            traceback.print_exc()
            return False

    def verifyPayload(self, expectedResp):
        if self.encodingType != EncodingType.JSON_IETF:
            st.error("GnoiRpcResponse: verifyPayload: Invalid response payload encoding: {}".format(self.encodingType), self.dut)
            return False
        return self.comparator.compare(self.getPayload(), expectedResp)
