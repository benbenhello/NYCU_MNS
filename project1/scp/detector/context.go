package detector

import (
	"github.com/free5gc/openapi/models"
)

var CurrentAuthProcedure AuthProcedureInfo

// Define every thing you want in this struct,
// so that you can use them in different message handler
type AuthProcedureInfo struct {
	AuthSubsData models.AuthenticationSubscription
	AuthInfo     models.AuthenticationInfo
	AuthVector   models.AuthenticationVector
	hxresStar    []byte
	kseaf        []byte
	ausf_autn    string
	ausf_rand    string
}
