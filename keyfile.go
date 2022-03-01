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
  "keyfile": "..."
}
*/

// PKIResponse is the result returned
type KeyfileResponse struct {
	StandardResponse
	KeyfilePayload
}

// PKIPayload is the payload from the response
type KeyfilePayload struct {
	BsvAlias string `json:"bsvalias"` // Version of Paymail
	Handle   string `json:"handle"`   // The <alias>@<domain>.<tld>
	Keyfile  string `json:"keyfile"`  // The encrypted keyfile
}

// GetKeyfile will return a valid Keyfile response for a given alias@domain.tld
//
// Specs: https://github.com/openspv/openspv/blob/master/openspv-js/openspv-keyfile/src/index.mjs
func (c *Client) GetKeyfile(keyfileURL, alias, domain string) (response *KeyfileResponse, err error) {

	// Require a valid url
	if len(keyfileURL) == 0 || !strings.Contains(keyfileURL, "https://") {
		err = fmt.Errorf("invalid url: %s", keyfileURL)
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
	reqURL := replaceAliasDomain(keyfileURL, alias, domain)

	// Fire the GET request
	var resp StandardResponse
	if resp, err = c.getRequest(reqURL); err != nil {
		return
	}

	// Start the response
	response = &KeyfileResponse{StandardResponse: resp}

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
		err = fmt.Errorf("keyfile response handle %s does not match paymail address: %s", response.Handle, alias+"@"+domain)
		return
	}

	// Check the Keyfile encoding (?)
	//if len(response.PubKey) == 0 {
	//	err = fmt.Errorf("pki response is missing a PubKey value")
	//} else if len(response.PubKey) != PubKeyLength {
	//	err = fmt.Errorf("returned pubkey is not the required length of %d, got: %d", PubKeyLength, len(response.PubKey))
	//}

	return
}
