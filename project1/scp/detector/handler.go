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

	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Info(targetNfUri)
	response, problemDetails, err := consumer.SendAuth5gAkaConfirmRequest(targetNfUri, ConfirmationDataResponseID, &updateConfirmationData)

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

func HandleUeAuthPostRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// source: [AMF]
	// destination: [AUSF] http://127.0.0.9:8000
	logger.DetectorLog.Infof("HandleUeAuthPostRequest")
	updateAuthenticationInfo := request.Body.(models.AuthenticationInfo)

	// NOTE: The request from AMF is guaranteed to be correct
	logger.DetectorLog.Infof("AMF data")
	logger.DetectorLog.Info(request)
	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Info(targetNfUri)
	response, respHeader, problemDetails, err := consumer.SendUeAuthPostRequest(targetNfUri, &updateAuthenticationInfo)

	// TODO: Check IEs in response body is correct
	logger.DetectorLog.Infof("[AUSF] response")
	logger.DetectorLog.Info(response)
	logger.DetectorLog.Infof("[AUSF] respHeader")
	logger.DetectorLog.Info(respHeader)
	logger.DetectorLog.Infof("[AUSF] problemDetails")
	logger.DetectorLog.Info(problemDetails)
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
	logger.DetectorLog.Infof("AUSF data")
	logger.DetectorLog.Info(request)
	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Info(targetNfUri)
	response, problemDetails, err := consumer.SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &authInfoRequest)
	xres, sqnXorAk, ck, ik, autn := retrieveBasicDeriveFactor(&CurrentAuthProcedure.AuthSubsData, response.AuthenticationVector.Rand)
	_, _, _, _, _ = xres, sqnXorAk, ck, ik, autn
	logger.DetectorLog.Infof("[UDM] response")
	logger.DetectorLog.Info(response)
	logger.DetectorLog.Infof("[UDM] problemDetails")
	logger.DetectorLog.Info(problemDetails)
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

	// TODO: Send request to correct NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Info(targetNfUri)
	response, problemDetails, err := consumer.SendAuthSubsDataGet(targetNfUri, ueId)
	logger.DetectorLog.Infof("[UDR]")
	logger.DetectorLog.Info(*response)
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
