package detector

import (
	"net/http"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/consumer"
	"github.com/free5gc/scp/logger"
)

const (
	ERR_MANDATORY_ABSENT = "Mandatory type is absent"
	ERR_MISS_CONDITION   = "Miss condition"
	ERR_VALUE_INCORRECT  = "Unexpected value is received"
)

func HandleAuth5gAkaComfirmRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// source: [AMF]
	// destination: [AUSF] http://127.0.0.9:8000
	logger.DetectorLog.Infof("Auth5gAkaComfirmRequest")
	updateConfirmationData := request.Body.(models.ConfirmationData)
	ConfirmationDataResponseID := request.Params["authCtxId"]

	// NOTE: The request from AMF is guaranteed to be correct
	logger.DetectorLog.Infof("request from [AMF] %+v", request)
	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Info(targetNfUri)
	response, problemDetails, err := consumer.SendAuth5gAkaConfirmRequest(targetNfUri, ConfirmationDataResponseID, &updateConfirmationData)

	// TODO: Check IEs in response body is correct
	logger.DetectorLog.Infof("response from [AUSF] %+v", response)
	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleUeAuthPostRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// source: [AMF]
	// destination: [AUSF] http://127.0.0.9:8000
	logger.DetectorLog.Infof("HandleUeAuthPostRequest")
	updateAuthenticationInfo := request.Body.(models.AuthenticationInfo)
	CurrentAuthProcedure.AuthInfo = updateAuthenticationInfo
	logger.DetectorLog.Infof("!! %+v", updateAuthenticationInfo)

	// NOTE: The request from AMF is guaranteed to be correct
	logger.DetectorLog.Infof("request from [AMF] %+v", request)

	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Infof("target NF Uri %+v", targetNfUri)

	response, respHeader, problemDetails, err := consumer.SendUeAuthPostRequest(targetNfUri, &updateAuthenticationInfo)
	// TODO: Check IEs in response body is correct
	logger.DetectorLog.Infof("response from [AUSF]: %+v", response)
	logger.DetectorLog.Infof("!!%+v", response.Var5gAuthData)
	logger.DetectorLog.Infof("respHeader from [AUSF]: %+v", respHeader)
	logger.DetectorLog.Infof("problemDetails from [AUSF]: %+v", problemDetails)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusCreated, respHeader, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleGenerateAuthDataRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// source: [AUSF]
	// destination: [UDM] http://127.0.0.3:8000
	logger.DetectorLog.Infoln("Handle GenerateAuthDataRequest")

	authInfoRequest := request.Body.(models.AuthenticationInfoRequest)
	supiOrSuci := request.Params["supiOrSuci"]

	// TODO: Check IEs in request body is correct
	logger.DetectorLog.Infof("request from [AUSF]: %+v", request)

	logger.DetectorLog.Infof("1 %+v", authInfoRequest)
	if authInfoRequest.ServingNetworkName == "" {
		logger.DetectorLog.Errorf("AuthenticationInfoRequest.ServingNetworkName: %s", ERR_MANDATORY_ABSENT)
		authInfoRequest.ServingNetworkName = CurrentAuthProcedure.AuthInfo.ServingNetworkName
	}
	// &{AuthType:5G_AKA SupportedFeatures: AuthenticationVector:0xc000391300 Supi:imsi-208930000000003}
	// &{AuthType:5G_AKA SupportedFeatures: AuthenticationVector:0xc0000a4880 Supi:imsi-208930000000003}
	// &{AuthType:5G_AKA SupportedFeatures: AuthenticationVector:0xc0002c4d80 Supi:imsi-208930000000003}
	logger.DetectorLog.Infof("2 %+v", authInfoRequest)
	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Infof("target NF Uri %+v", targetNfUri)

	response, problemDetails, err := consumer.SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &authInfoRequest)
	logger.DetectorLog.Infof("response from [UDM]: %+v", response)
	logger.DetectorLog.Infof("authen vector: %+v", response.AuthenticationVector)
	CurrentAuthProcedure.AuthVector = *response.AuthenticationVector
	logger.DetectorLog.Infof("XRES* %+v", CurrentAuthProcedure.AuthVector.XresStar)
	CurrentAuthProcedure.hxresStar = retrieveHxresStar([]byte(CurrentAuthProcedure.AuthVector.XresStar))
	logger.DetectorLog.Infof("hxressStar %+v", string(CurrentAuthProcedure.hxresStar))
	xres, sqnXorAk, ck, ik, autn := retrieveBasicDeriveFactor(&CurrentAuthProcedure.AuthSubsData, response.AuthenticationVector.Rand)
	_, _, _, _, _ = xres, sqnXorAk, ck, ik, autn

	logger.DetectorLog.Infof("problemDetails from [UDM]: %+v", problemDetails)
	// TODO: Check IEs in response body is correct

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleQueryAuthSubsData(request *http_wrapper.Request) *http_wrapper.Response {
	// source: [UDM]
	// destination: [UDR] http://127.0.0.4:8000
	logger.DetectorLog.Infof("Handle QueryAuthSubsData")

	ueId := request.Params["ueId"]
	logger.DetectorLog.Infof("ueId request %+v", request)
	// TODO: Send request to correct NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Infof("target NF Uri %+v", targetNfUri)

	response, problemDetails, err := consumer.SendAuthSubsDataGet(targetNfUri, ueId)
	logger.DetectorLog.Infof("response from [UDR]: %+v", response)
	// NOTE: The response from UDR is guaranteed to be correct
	CurrentAuthProcedure.AuthSubsData = *response

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}
