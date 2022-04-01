package detector

import (
	"encoding/hex"
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
	logger.DetectorLog.Infof("[Before] response from [AUSF] %+v", response)

	// check Kseaf
	logger.DetectorLog.Infof("check Kseaf")
	logger.DetectorLog.Infof("Kseaf in response %+v", response.Kseaf)
	logger.DetectorLog.Infof("Kseaf expected %+v", hex.EncodeToString(CurrentAuthProcedure.kseaf))
	logger.DetectorLog.Info(response.Kseaf == hex.EncodeToString(CurrentAuthProcedure.kseaf))
	if response.Kseaf == "" {
		logger.DetectorLog.Errorf("ConfirmationResponse.Kseaf: %+v", ERR_MISS_CONDITION)
	} else if response.Kseaf != hex.EncodeToString(CurrentAuthProcedure.kseaf) {
		logger.DetectorLog.Errorf("ConfirmationResponse.Kseaf: %+v", ERR_VALUE_INCORRECT)
	}
	response.Kseaf = hex.EncodeToString(CurrentAuthProcedure.kseaf)

	// check supi
	logger.DetectorLog.Infof("check supi")
	supi, _ := extractSupi(ConfirmationDataResponseID)
	logger.DetectorLog.Infof("Supi in response %+v", response.Supi)
	logger.DetectorLog.Infof("Supi expected %+v", supi)
	logger.DetectorLog.Info(response.Supi == supi)
	if response.Supi == "" {
		logger.DetectorLog.Errorf("ConfirmationResponse.Supi: %+v", ERR_MISS_CONDITION)
	} else if response.Supi != supi {
		logger.DetectorLog.Errorf("ConfirmationResponse.Supi: %+v", ERR_VALUE_INCORRECT)
	}
	response.Supi = supi

	logger.DetectorLog.Infof("[After] response from [AUSF] %+v", response)

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

	// NOTE: The request from AMF is guaranteed to be correct
	logger.DetectorLog.Infof("request from [AMF] %+v", request)

	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Infof("target NF Uri %+v", targetNfUri)

	response, respHeader, problemDetails, err := consumer.SendUeAuthPostRequest(targetNfUri, &updateAuthenticationInfo)
	// TODO: Check IEs in response body is correct
	logger.DetectorLog.Infof("[Before] response from [AUSF]: %+v", response)

	// check Hxress*
	logger.DetectorLog.Infof("check Hxress*")
	logger.DetectorLog.Infof("Hxress* in response %+v", response.Var5gAuthData.(map[string]interface{})["hxresStar"])
	logger.DetectorLog.Infof("Hxress* expected %+v", hex.EncodeToString(CurrentAuthProcedure.hxresStar))
	logger.DetectorLog.Info(response.Var5gAuthData.(map[string]interface{})["hxresStar"] == hex.EncodeToString(CurrentAuthProcedure.hxresStar))
	if response.Var5gAuthData.(map[string]interface{})["hxresStar"] == "" {
		logger.DetectorLog.Errorf("UeAuthenticationCtx.Av5gAka.HxressStar: %+v", ERR_MANDATORY_ABSENT)
	} else if response.Var5gAuthData.(map[string]interface{})["hxresStar"] != hex.EncodeToString(CurrentAuthProcedure.hxresStar) {
		logger.DetectorLog.Errorf("UeAuthenticationCtx.Av5gAka.HxressStar: %+v", ERR_VALUE_INCORRECT)
	}
	response.Var5gAuthData.(map[string]interface{})["hxresStar"] = hex.EncodeToString(CurrentAuthProcedure.hxresStar)

	//check autn
	logger.DetectorLog.Infof("check Autn")
	logger.DetectorLog.Infof("autn in response %+v", response.Var5gAuthData.(map[string]interface{})["autn"])
	logger.DetectorLog.Infof("autn expected %+v", CurrentAuthProcedure.ausf_autn)
	logger.DetectorLog.Info(response.Var5gAuthData.(map[string]interface{})["autn"] == CurrentAuthProcedure.ausf_autn)
	if response.Var5gAuthData.(map[string]interface{})["autn"] == "" {
		logger.DetectorLog.Errorf("UeAuthenticationCtx.Av5gAka.Autn: %+v", ERR_MANDATORY_ABSENT)
	} else if response.Var5gAuthData.(map[string]interface{})["autn"] != CurrentAuthProcedure.ausf_autn {
		logger.DetectorLog.Errorf("UeAuthenticationCtx.Av5gAka.Autn: %+v", ERR_VALUE_INCORRECT)
	}
	response.Var5gAuthData.(map[string]interface{})["autn"] = CurrentAuthProcedure.ausf_autn

	//check rand
	logger.DetectorLog.Infof("check Rand")
	logger.DetectorLog.Infof("rand in response %+v", response.Var5gAuthData.(map[string]interface{})["rand"])
	logger.DetectorLog.Infof("rand expected %+v", CurrentAuthProcedure.ausf_rand)
	logger.DetectorLog.Info(response.Var5gAuthData.(map[string]interface{})["rand"] == CurrentAuthProcedure.ausf_rand)
	if response.Var5gAuthData.(map[string]interface{})["rand"] == "" {
		logger.DetectorLog.Errorf("UeAuthenticationCtx.Av5gAka.Rand: %+v", ERR_MANDATORY_ABSENT)
	} else if response.Var5gAuthData.(map[string]interface{})["rand"] != CurrentAuthProcedure.ausf_rand {
		logger.DetectorLog.Errorf("UeAuthenticationCtx.Av5gAka.Rand: %+v", ERR_VALUE_INCORRECT)
	}
	response.Var5gAuthData.(map[string]interface{})["rand"] = CurrentAuthProcedure.ausf_rand

	logger.DetectorLog.Infof("[After] response from [AUSF]: %+v", response)

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

	logger.DetectorLog.Infof("[Before] %+v", authInfoRequest)
	if authInfoRequest.ServingNetworkName == "" {
		logger.DetectorLog.Errorf("AuthenticationInfoRequest.ServingNetworkName: %s", ERR_MANDATORY_ABSENT)
		authInfoRequest.ServingNetworkName = CurrentAuthProcedure.AuthInfo.ServingNetworkName
	}
	logger.DetectorLog.Infof("[After] %+v", authInfoRequest)

	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0]
	logger.DetectorLog.Infof("target NF Uri %+v", targetNfUri)

	response, problemDetails, err := consumer.SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &authInfoRequest)

	logger.DetectorLog.Infof("response from [UDM]: %+v", response)
	logger.DetectorLog.Infof("[Before] authen vector: %+v", response.AuthenticationVector)
	// CurrentAuthProcedure.AuthVector = *response.AuthenticationVector

	xres, sqnXorAk, ck, ik, autn := retrieveBasicDeriveFactor(&CurrentAuthProcedure.AuthSubsData, response.AuthenticationVector.Rand)
	// _, _, _, _, _ = xres, sqnXorAk, ck, ik, autn
	// TODO: Check IEs in response body is correct

	// generate key
	logger.DetectorLog.Infof("generate key from ck & ik")
	logger.DetectorLog.Infof("ck: %+v, ik: %+v", ck, ik)
	key := append(ck, ik...)
	logger.DetectorLog.Infof("key: %+v", key)

	// check xres
	logger.DetectorLog.Infof("check xres")
	xres_s := hex.EncodeToString(xres)
	logger.DetectorLog.Infof("XRES 1 %+v", xres_s)
	logger.DetectorLog.Infof("XRES 2 %+v", response.AuthenticationVector.Xres)
	logger.DetectorLog.Info(xres_s == response.AuthenticationVector.Xres)
	// if response.AuthenticationVector.Xres == "" {
	// 	logger.DetectorLog.Errorf("AuthenticationInfoResult.Xres: %+v", ERR_MANDATORY_ABSENT)
	// } else if response.AuthenticationVector.Xres != xres_s {
	// 	logger.DetectorLog.Errorf("AuthenticationInfoResult.Xres: %+v", ERR_VALUE_INCORRECT)
	// }
	response.AuthenticationVector.Xres = xres_s
	// check authn and save
	logger.DetectorLog.Infof("check authn")
	autn_s := hex.EncodeToString(autn)
	logger.DetectorLog.Infof("AUTN 1 %+v", autn_s)
	logger.DetectorLog.Infof("AUTN 2 %+v", response.AuthenticationVector.Autn)
	logger.DetectorLog.Info(autn_s == response.AuthenticationVector.Autn)
	if response.AuthenticationVector.Autn == "" {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.Autn: %+v", ERR_MANDATORY_ABSENT)
	} else if response.AuthenticationVector.Autn != autn_s {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.Autn: %+v", ERR_VALUE_INCORRECT)
	}
	response.AuthenticationVector.Autn = autn_s
	CurrentAuthProcedure.ausf_autn = autn_s

	// save rand
	CurrentAuthProcedure.ausf_rand = response.AuthenticationVector.Rand

	// calculate xres* and check
	logger.DetectorLog.Infof("calculate xres* and check")
	rand_b, _ := hex.DecodeString(response.AuthenticationVector.Rand)
	xressStar := retrieveXresStar(key, "6B", []byte(authInfoRequest.ServingNetworkName), rand_b, xres)
	xressStar_s := hex.EncodeToString(xressStar)
	logger.DetectorLog.Infof("XRES* 1 %+v", xressStar_s)
	logger.DetectorLog.Infof("XRES* 2 %+v", response.AuthenticationVector.XresStar)
	logger.DetectorLog.Info(xressStar_s == response.AuthenticationVector.XresStar)
	if response.AuthenticationVector.XresStar == "" {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.XRES*: %+v", ERR_MANDATORY_ABSENT)
	} else if response.AuthenticationVector.XresStar != xressStar_s {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.XRES*: %+v", ERR_VALUE_INCORRECT)
	}
	response.AuthenticationVector.XresStar = xressStar_s

	// calculate Kausf and check
	logger.DetectorLog.Infof("calculate Kausf and check")
	kausf := retrieve5GAkaKausf(key, "6A", []byte(authInfoRequest.ServingNetworkName), sqnXorAk)
	kausf_s := hex.EncodeToString(kausf)
	logger.DetectorLog.Infof("Kausf 1 %+v", kausf_s)
	logger.DetectorLog.Infof("Kausf 2 %+v", response.AuthenticationVector.Kausf)
	logger.DetectorLog.Info(kausf_s == response.AuthenticationVector.Kausf)
	if response.AuthenticationVector.Kausf == "" {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.Kausf: %+v", ERR_MANDATORY_ABSENT)
	} else if response.AuthenticationVector.Kausf != kausf_s {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.Kausf: %+v", ERR_VALUE_INCORRECT)
	}
	response.AuthenticationVector.Kausf = kausf_s
	// calculate hxressStar and save
	logger.DetectorLog.Infof("calculate hxressStar and save")
	s := append(rand_b, xressStar...)
	CurrentAuthProcedure.hxresStar = retrieveHxresStar(s)

	// calculate Kseaf and save
	logger.DetectorLog.Infof("calculate Kseaf and save")
	CurrentAuthProcedure.kseaf = retrieveKseaf(kausf, "6C", []byte(authInfoRequest.ServingNetworkName))

	logger.DetectorLog.Infof("[After] authen vector: %+v", response.AuthenticationVector)

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
