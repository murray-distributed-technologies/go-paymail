package paymail

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

/*
Default Response:
{
  "bsvalias": "1.0",
  "handle": "<alias>@<domain>.<tld>",
  "authenticationURL": "..."
}
*/

// AuthenticationResponse is the result returned
type AuthenticationResponse struct {
	StandardResponse
	AuthenticationPayload
}

// AuthenticationPayload is the payload from the response
type AuthenticationPayload struct {
	BsvAlias          string `json:"bsvalias"`          // Version of Paymail
	Handle            string `json:"handle"`            // The <alias>@<domain>.<tld>
	AuthenticationURL string `json:"authenticationURL"` // The URL for the authentication endpoint
}

// GetAuthenticationURL will return a valid authentication endpoint url for a given alias@domain.tld
//
func (c *Client) GetAuthenticationURL(authURL, alias, domain string) (response *AuthenticationResponse, err error) {

	// Require a valid url
	if len(authURL) == 0 || !strings.Contains(authURL, "https://") {
		err = fmt.Errorf("invalid url: %s", authURL)
		return
	}

	// Basic requirements for the request
	if len(alias) == 0 {
		err = fmt.Errorf("missing alias")
		return
	} else if len(domain) == 0 {
		err = fmt.Errorf("missing domain")
		return
	}

	// Set the base url and path, assuming the url is from the prior GetCapabilities() request
	// https://<host-discovery-target>/{alias}@{domain.tld}/id
	reqURL := replaceAliasDomain(authURL, alias, domain)

	// Fire the GET request
	var resp StandardResponse
	if resp, err = c.getRequest(reqURL); err != nil {
		return
	}

	// Start the response
	response = &AuthenticationResponse{StandardResponse: resp}

	// Test the status code (200 or 304 is valid)
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotModified {
		serverError := &ServerError{}
		if err = json.Unmarshal(resp.Body, serverError); err != nil {
			return
		}
		err = fmt.Errorf("bad response from paymail provider: code %d, message: %s", response.StatusCode, serverError.Message)
		return
	}

	// Decode the body of the response
	if err = json.Unmarshal(resp.Body, &response); err != nil {
		return
	}

	// Invalid version detected
	if len(response.BsvAlias) == 0 {
		err = fmt.Errorf("missing bsvalias version")
		return
	}

	// Check basic requirements (handle should match our alias@domain.tld)
	if response.Handle != alias+"@"+domain {
		err = fmt.Errorf("auth response handle %s does not match paymail address: %s", response.Handle, alias+"@"+domain)
		return
	}

	// TODO: Check Authentication URL
	return
}
