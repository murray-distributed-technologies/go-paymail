package server

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	apirouter "github.com/mrz1836/go-api-router"
	"github.com/tonicpow/go-paymail"
)

// getAuthenticationEndpoint will return the authentication URL for the corresponding paymail address
//
// Specs: http://bsvalias.org/03-public-key-infrastructure.html
func (c *Configuration) getAuthenticationEndpoint(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	// Get the params & paymail address submitted via URL request
	params := apirouter.GetParams(req)
	incomingPaymail := params.GetString("paymailAddress")

	// Parse, sanitize and basic validation
	alias, domain, address := paymail.SanitizePaymail(incomingPaymail)
	if len(address) == 0 {
		ErrorResponse(w, req, ErrorInvalidParameter, "invalid paymail: "+incomingPaymail, http.StatusBadRequest)
		return
	} else if !c.IsAllowedDomain(domain) {
		ErrorResponse(w, req, ErrorUnknownDomain, "domain unknown: "+domain, http.StatusBadRequest)
		return
	}

	// Create the metadata struct
	md := CreateMetadata(req, alias, domain, "")

	// Get from the data layer
	authInfo, err := c.actions.GetAuthenticationURL(req.Context(), alias, domain, md)
	if err != nil {
		ErrorResponse(w, req, ErrorGettingAuthenticationUrl, err.Error(), http.StatusExpectationFailed)
		return
	} else if authInfo == nil {
		ErrorResponse(w, req, ErrorPaymailNotFound, "paymail not found", http.StatusNotFound)
		return
	}

	// Return the response
	apirouter.ReturnResponse(w, req, http.StatusOK, &paymail.AuthenticationPayload{
		BsvAlias:          c.BSVAliasVersion,
		Handle:            address,
		AuthenticationURL: authInfo.AuthenticationURL,
	})
}
