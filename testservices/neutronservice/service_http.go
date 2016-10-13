// Neutron double testing service - HTTP API implementation

package neutronservice

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"
	"strings"

	//"gopkg.in/goose.v1/errors"
	"gopkg.in/goose.v1/neutron"
	"gopkg.in/goose.v1/testservices"
	"gopkg.in/goose.v1/testservices/identityservice"
)

const authToken = "X-Auth-Token"

// errorResponse defines a single HTTP error response.
type errorResponse struct {
	code        int
	body        string
	contentType string
	errorText   string
	headers     map[string]string
	neutron     *Neutron
}

// verbatim real Neutron responses (as errors).
var (
	errUnauthorized = &errorResponse{
		http.StatusUnauthorized,
		`401 Unauthorized

This server could not verify that you are authorized to access the ` +
			`document you requested. Either you supplied the wrong ` +
			`credentials (e.g., bad password), or your browser does ` +
			`not understand how to supply the credentials required.

 Authentication required
`,
		"text/plain; charset=UTF-8",
		"unauthorized request",
		nil,
		nil,
	}
	errForbidden = &errorResponse{
		http.StatusForbidden,
		`{"forbidden": {"message": "Policy doesn't allow compute_extension:` +
			`flavormanage to be performed.", "code": 403}}`,
		"application/json; charset=UTF-8",
		"forbidden flavors request",
		nil,
		nil,
	}
	errBadRequest = &errorResponse{
		http.StatusBadRequest,
		`{"badRequest": {"message": "Malformed request url", "code": 400}}`,
		"application/json; charset=UTF-8",
		"bad request base path or URL",
		nil,
		nil,
	}
	errBadRequest2 = &errorResponse{
		http.StatusBadRequest,
		`{"badRequest": {"message": "The server could not comply with the ` +
			`request since it is either malformed or otherwise incorrect.", "code": 400}}`,
		"application/json; charset=UTF-8",
		"bad request URL",
		nil,
		nil,
	}
	errBadRequest3 = &errorResponse{
		http.StatusBadRequest,
		`{"badRequest": {"message": "Malformed request body", "code": 400}}`,
		"application/json; charset=UTF-8",
		"bad request body",
		nil,
		nil,
	}
	errBadRequestDuplicateValue = &errorResponse{
		http.StatusBadRequest,
		`{"badRequest": {"message": "entity already exists", "code": 400}}`,
		"application/json; charset=UTF-8",
		"duplicate value",
		nil,
		nil,
	}
	errNotFound = &errorResponse{
		http.StatusNotFound,
		`404 Not Found

The resource could not be found.


`,
		"text/plain; charset=UTF-8",
		"resource not found",
		nil,
		nil,
	}
	errNotFoundJSON = &errorResponse{
		http.StatusNotFound,
		`{"itemNotFound": {"message": "The resource could not be found.", "code": 404}}`,
		"application/json; charset=UTF-8",
		"resource not found",
		nil,
		nil,
	}
	errNotFoundJSONSG = &errorResponse{
		http.StatusNotFound,
		`{"itemNotFound": {"message": "Security group $ID$ not found.", "code": 404}}`,
		"application/json; charset=UTF-8",
		"",
		nil,
		nil,
	}
	errNotFoundJSONSGR = &errorResponse{
		http.StatusNotFound,
		`{"itemNotFound": {"message": "Rule ($ID$) not found.", "code": 404}}`,
		"application/json; charset=UTF-8",
		"security rule not found",
		nil,
		nil,
	}
	errMultipleChoices = &errorResponse{
		http.StatusMultipleChoices,
		`{"choices": [{"status": "CURRENT", "media-types": [{"base": ` +
			`"application/xml", "type": "application/vnd.openstack.compute+` +
			`xml;version=2"}, {"base": "application/json", "type": "application/` +
			`vnd.openstack.compute+json;version=2"}], "id": "v2.0", "links": ` +
			`[{"href": "$ENDPOINT$$URL$", "rel": "self"}]}]}`,
		"application/json",
		"multiple URL redirection choices",
		nil,
		nil,
	}
	errNoVersion = &errorResponse{
		http.StatusOK,
		`{"versions": [{"status": "CURRENT", "id": "v2.0", "links": [{"href": "$ENDPOINT$/v2.0", "rel": "self"}]}]}`,
		"application/json",
		"no version specified in URL",
		nil,
		nil,
	}
	errVersionsLinks = &errorResponse{
		http.StatusOK,
		`{"version": {"status": "CURRENT", "updated": "2011-01-21T11` +
			`:33:21Z", "media-types": [{"base": "application/xml", "type": ` +
			`"application/vnd.openstack.compute+xml;version=2"}, {"base": ` +
			`"application/json", "type": "application/vnd.openstack.compute` +
			`+json;version=2"}], "id": "v2.0", "links": [{"href": "$ENDPOINT$"` +
			`, "rel": "self"}, {"href": "http://docs.openstack.org/api/openstack` +
			`-compute/1.1/os-compute-devguide-1.1.pdf", "type": "application/pdf` +
			`", "rel": "describedby"}, {"href": "http://docs.openstack.org/api/` +
			`openstack-compute/1.1/wadl/os-compute-1.1.wadl", "type": ` +
			`"application/vnd.sun.wadl+xml", "rel": "describedby"}]}}`,
		"application/json",
		"version missing from URL",
		nil,
		nil,
	}
	errNotImplemented = &errorResponse{
		http.StatusNotImplemented,
		"501 Not Implemented",
		"text/plain; charset=UTF-8",
		"not implemented",
		nil,
		nil,
	}
	errNoGroupId = &errorResponse{
		errorText: "no security group id given",
	}
	errRateLimitExceeded = &errorResponse{
		http.StatusRequestEntityTooLarge,
		"",
		"text/plain; charset=UTF-8",
		"too many requests",
		// RFC says that Retry-After should be an int, but we don't want to wait an entire second during the test suite.
		map[string]string{"Retry-After": "0.001"},
		nil,
	}
	errNoMoreFloatingIPs = &errorResponse{
		http.StatusNotFound,
		"Zero floating ips available.",
		"text/plain; charset=UTF-8",
		"zero floating ips available",
		nil,
		nil,
	}
	errIPLimitExceeded = &errorResponse{
		http.StatusRequestEntityTooLarge,
		"Maximum number of floating ips exceeded.",
		"text/plain; charset=UTF-8",
		"maximum number of floating ips exceeded",
		nil,
		nil,
	}
)

func (e *errorResponse) Error() string {
	return e.errorText
}

// requestBody returns the body for the error response, replacing
// $ENDPOINT$, $URL$, $ID$, and $ERROR$ in e.body with the values from
// the request.
func (e *errorResponse) requestBody(r *http.Request) []byte {
	url := strings.TrimLeft(r.URL.Path, "/")
	body := e.body
	if body != "" {
		if e.neutron != nil {
			body = strings.Replace(body, "$ENDPOINT$", e.neutron.endpointURL("/"), -1)
		}
		body = strings.Replace(body, "$URL$", url, -1)
		body = strings.Replace(body, "$ERROR$", e.Error(), -1)
		if slash := strings.LastIndex(url, "/"); slash != -1 {
			body = strings.Replace(body, "$ID$", url[slash+1:], -1)
		}
	}
	return []byte(body)
}

func (e *errorResponse) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e.contentType != "" {
		w.Header().Set("Content-Type", e.contentType)
	}
	body := e.requestBody(r)
	if e.headers != nil {
		for h, v := range e.headers {
			w.Header().Set(h, v)
		}
	}
	// workaround for https://code.google.com/p/go/issues/detail?id=4454
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if e.code != 0 {
		w.WriteHeader(e.code)
	}
	if len(body) > 0 {
		w.Write(body)
	}
}

type neutronHandler struct {
	n      *Neutron
	method func(n *Neutron, w http.ResponseWriter, r *http.Request) error
}

func userInfo(i identityservice.IdentityService, r *http.Request) (*identityservice.UserInfo, error) {
	return i.FindUser(r.Header.Get(authToken))
}

func (h *neutronHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	//fmt.Printf("\nServeHTTP(): request = %q\n\n", r)
	// handle invalid X-Auth-Token header
	_, err := userInfo(h.n.IdentityService, r)
	if err != nil {
		errUnauthorized.ServeHTTP(w, r)
		return
	}
	// handle trailing slash in the path
	if strings.HasSuffix(path, "/") && path != "/" {
		errNotFound.ServeHTTP(w, r)
		return
	}
	err = h.method(h.n, w, r)
	if err == nil {
		return
	}
	var resp http.Handler

	if err == testservices.RateLimitExceededError {
		resp = errRateLimitExceeded
	} else if err == testservices.NoMoreFloatingIPs {
		resp = errNoMoreFloatingIPs
	} else if err == testservices.IPLimitExceeded {
		resp = errIPLimitExceeded
	} else {
		resp, _ = err.(http.Handler)
		if resp == nil {
			code, encodedErr := errorJSONEncode(err)
			resp = &errorResponse{
				code,
				encodedErr,
				"application/json",
				err.Error(),
				nil,
				h.n,
			}
		}
	}
	resp.ServeHTTP(w, r)
}

func writeResponse(w http.ResponseWriter, code int, body []byte) {
	// workaround for https://code.google.com/p/go/issues/detail?id=4454
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	w.Write(body)
}

// sendJSON sends the specified response serialized as JSON.
func sendJSON(code int, resp interface{}, w http.ResponseWriter, r *http.Request) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	writeResponse(w, code, data)
	return nil
}

func (n *Neutron) handler(method func(n *Neutron, w http.ResponseWriter, r *http.Request) error) http.Handler {
	return &neutronHandler{n, method}
}

func (n *Neutron) handleRoot(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path == "/" {
		return errNoVersion
	}
	fmt.Printf("handleRoot(): returning errMultipleChoices\n")
	return errMultipleChoices
}

func (n *Neutron) HandleRoot(w http.ResponseWriter, r *http.Request) {
	n.handler((*Neutron).handleRoot).ServeHTTP(w, r)
}

// newUUID generates a random UUID conforming to RFC 4122.
func newUUID() (string, error) {
	uuid := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, uuid); err != nil {
		return "", err
	}
	uuid[8] = uuid[8]&^0xc0 | 0x80 // variant bits; see section 4.1.1.
	uuid[6] = uuid[6]&^0xf0 | 0x40 // version 4; see section 4.1.3.
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// processGroupId returns the group id from the given request.
// If there was no group id specified in the path, it returns errNoGroupId
func (n *Neutron) processGroupId(w http.ResponseWriter, r *http.Request) (*neutron.SecurityGroupV2, error) {
	groupId := path.Base(r.URL.Path)
	apiFunc := path.Base(neutron.ApiSecurityGroupsV2)
	//fmt.Printf("processGroupId(): %s maybe equal %s\n", groupId, apiFunc)
	if groupId != apiFunc {
		group, err := n.securityGroup(groupId)
		if err != nil {
			return nil, errNotFoundJSONSG
		}
		return group, nil
	}
	return nil, errNoGroupId
}

// handleSecurityGroups handles the /v2.0/security-groups HTTP API.
func (n *Neutron) handleSecurityGroups(w http.ResponseWriter, r *http.Request) error {
	//fmt.Printf("handleSecurityGroups(): r.Method = %s\n", r.Method)
	//fmt.Printf("handleSecurityGroups(): r.URL = %s\n", r.URL)
	switch r.Method {
	case "GET":
		group, err := n.processGroupId(w, r)
		//fmt.Printf("handleSecurityGroups(GET): %s; %s\n", err, group)
		if err == errNoGroupId {
			groups := n.allSecurityGroups()
			if len(groups) == 0 {
				groups = []neutron.SecurityGroupV2{}
			}
			resp := struct {
				Groups []neutron.SecurityGroupV2 `json:"security_groups"`
			}{groups}
			return sendJSON(http.StatusOK, resp, w, r)
		}
		if err != nil {
			return err
		}
		resp := struct {
			Group neutron.SecurityGroupV2 `json:"security_group"`
		}{*group}
		return sendJSON(http.StatusOK, resp, w, r)
	case "POST":
		_, err := n.processGroupId(w, r)
		if err != errNoGroupId {
			return errNotFound
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			return errBadRequest2
		}
		var req struct {
			Group struct {
				Name        string
				Description string
			} `json:"security_group"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		} else {
			_, err := n.securityGroupByName(req.Group.Name)
			if err == nil {
				return errBadRequestDuplicateValue
			}
			n.nextGroupId++
			nextId := strconv.Itoa(n.nextGroupId)
			err = n.addSecurityGroup(neutron.SecurityGroupV2{
				Id:          nextId,
				Name:        req.Group.Name,
				Description: req.Group.Description,
				TenantId:    n.TenantId,
			})
			if err != nil {
				return err
			}
			group, err := n.securityGroup(nextId)
			if err != nil {
				return err
			}
			var resp struct {
				Group neutron.SecurityGroupV2 `json:"security_group"`
			}
			resp.Group = *group
			return sendJSON(http.StatusCreated, resp, w, r)
		}
	case "PUT":
		group, err := n.processGroupId(w, r)
		if err == errNoGroupId {
			return errNotFound
		}

		var req struct {
			Group struct {
				Name        string
				Description string
			} `json:"security_group"`
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			return errBadRequest2
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}

		err = n.updateSecurityGroup(neutron.SecurityGroupV2{
			Id:          group.Id,
			Name:        req.Group.Name,
			Description: req.Group.Description,
			TenantId:    group.TenantId,
		})
		if err != nil {
			return err
		}
		group, err = n.securityGroup(group.Id)
		if err != nil {
			return err
		}
		var resp struct {
			Group neutron.SecurityGroupV2 `json:"security_group"`
		}
		resp.Group = *group
		return sendJSON(http.StatusOK, resp, w, r)

	case "DELETE":
		if group, err := n.processGroupId(w, r); group != nil {
			if err := n.removeSecurityGroup(group.Id); err != nil {
				return err
			}
			writeResponse(w, http.StatusNoContent, nil)
			return nil
		} else if err == errNoGroupId {
			return errNotFound
		} else {
			return err
		}
	}
	return fmt.Errorf("unknown request method %q for %s", r.Method, r.URL.Path)
}

// handleSecurityGroupRules handles the /v2.0/security-group-rules HTTP API.
func (n *Neutron) handleSecurityGroupRules(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		return errNotFoundJSON
		/*
			group, err := n.processGroupId(w, r)
			if err == errNoGroupId {
				groups := n.allSecurityGroups()
				if len(groups) == 0 {
					groups = []neutron.SecurityGroupV2{}
				}
				resp := struct {
					Groups []neutron.SecurityGroupV2 `json:"security_groups"`
				}{groups}
				return sendJSON(http.StatusOK, resp, w, r)
			}
			if err != nil {
				return err
			}
			resp := struct {
				Group neutron.SecurityGroupV2 `json:"security_group"`
			}{*group}
			return sendJSON(http.StatusOK, resp, w, r)
		*/
	case "POST":
		ruleId := path.Base(r.URL.Path)
		apiFunc := path.Base(neutron.ApiSecurityGroupRulesV2)
		if ruleId != apiFunc {
			return errNotFound
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			return errBadRequest2
		}
		var req struct {
			Rule neutron.RuleInfoV2 `json:"security_group_rule"`
		}
		if err = json.Unmarshal(body, &req); err != nil {
			return err
		}
		inrule := req.Rule
		group, err := n.securityGroup(inrule.ParentGroupId)
		if err != nil {
			return err // TODO: should be a 4XX error with details
		}
		for _, r := range group.Rules {
			// TODO: this logic is actually wrong, not what neutron does at all
			// why are we reimplementing half of neutron/api/openstack in go again?
			if r.IPProtocol != nil && *r.IPProtocol == inrule.IPProtocol &&
				r.PortRangeMax != nil && *r.PortRangeMax == inrule.PortRangeMax &&
				r.PortRangeMin != nil && *r.PortRangeMin == inrule.PortRangeMin {
				// TODO: Use a proper helper and sane error type
				return &errorResponse{
					http.StatusBadRequest,
					fmt.Sprintf(`{"badRequest": {"message": "This rule already exists in group %s", "code": 400}}`, group.Id),
					"application/json; charset=UTF-8",
					"rule already exists",
					nil,
					nil,
				}
			}
		}
		n.nextRuleId++
		nextId := strconv.Itoa(n.nextRuleId)
		err = n.addSecurityGroupRule(nextId, req.Rule)
		if err != nil {
			return err
		}
		rule, err := n.securityGroupRule(nextId)
		if err != nil {
			return err
		}
		var resp struct {
			Rule neutron.SecurityGroupRuleV2 `json:"security_group_rule"`
		}
		resp.Rule = *rule
		return sendJSON(http.StatusCreated, resp, w, r)
	case "PUT":
		if ruleId := path.Base(r.URL.Path); ruleId != neutron.ApiSecurityGroupRulesV2 {
			return errNotFoundJSON
		}
		return errNotFound
	case "DELETE":
		ruleId := path.Base(r.URL.Path)
		apiFunc := path.Base(neutron.ApiSecurityGroupRulesV2)
		if ruleId != apiFunc {
			if _, err := n.securityGroupRule(ruleId); err != nil {
				return errNotFoundJSONSGR
			}
			if err := n.removeSecurityGroupRule(ruleId); err != nil {
				return err
			}
			writeResponse(w, http.StatusNoContent, nil)
			return nil
		}
		return errNotFound
	}
	return fmt.Errorf("unknown request method %q for %s", r.Method, r.URL.Path)
}

// handleFloatingIPs handles the v2/floatingips HTTP API.
func (n *Neutron) handleFloatingIPs(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		ipId := path.Base(r.URL.Path)
		apiFunc := path.Base(neutron.ApiFloatingIPsV2)
		if ipId != apiFunc {
			fip, err := n.floatingIP(ipId)
			if err != nil {
				return errNotFoundJSON
			}
			resp := struct {
				IP neutron.FloatingIPV2 `json:"floating_ip"`
			}{*fip}
			return sendJSON(http.StatusOK, resp, w, r)
		}
		fips := n.allFloatingIPs()
		if len(fips) == 0 {
			fips = []neutron.FloatingIPV2{}
		}
		resp := struct {
			IPs []neutron.FloatingIPV2 `json:"floating_ips"`
		}{fips}
		return sendJSON(http.StatusOK, resp, w, r)
	case "POST":
		ipId := path.Base(r.URL.Path)
		apiFunc := path.Base(neutron.ApiFloatingIPsV2)
		if ipId != apiFunc {
			return errNotFound
		}
		n.nextIPId++
		addr := fmt.Sprintf("10.0.0.%d", n.nextIPId)
		nextId := strconv.Itoa(n.nextIPId)
		fip := neutron.FloatingIPV2{Id: nextId, IP: addr, FloatingNetworkId: "neutron"}
		err := n.addFloatingIP(fip)
		if err != nil {
			return err
		}
		resp := struct {
			IP neutron.FloatingIPV2 `json:"floating_ip"`
		}{fip}
		return sendJSON(http.StatusCreated, resp, w, r)
	case "PUT":
		if ipId := path.Base(r.URL.Path); ipId != neutron.ApiFloatingIPsV2 {
			return errNotFoundJSON
		}
		return errNotFound
	case "DELETE":
		ipId := path.Base(r.URL.Path)
		apiFunc := path.Base(neutron.ApiFloatingIPsV2)
		if ipId != apiFunc {
			if err := n.removeFloatingIP(ipId); err == nil {
				writeResponse(w, http.StatusNoContent, nil)
				return nil
			}
			return errNotFoundJSON
		}
		return errNotFound
	}
	return fmt.Errorf("unknown request method %q for %s", r.Method, r.URL.Path)
}

// handleNetworks handles the v2/networks HTTP API.
func (n *Neutron) handleNetworks(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		networkId := path.Base(r.URL.Path)
		apiFunc := path.Base(neutron.ApiNetworksV2)
		if networkId != apiFunc {
			network, err := n.network(networkId)
			if err != nil {
				return errNotFoundJSON
			}
			resp := struct {
				Network neutron.NetworkV2 `json:"network"`
			}{*network}
		fmt.Printf("handleNetworks(): %q\n", resp)
			return sendJSON(http.StatusOK, resp, w, r)
		}
		nets := n.allNetworks()
		if len(nets) == 0 {
			nets = []neutron.NetworkV2{}
		}
		resp := struct {
			Network []neutron.NetworkV2 `json:"networks"`
		}{nets}
		fmt.Printf("handleNetworks(): %q\n", resp)
		return sendJSON(http.StatusOK, resp, w, r)
	default:
		return errNotFound
	}
	return fmt.Errorf("unknown request method %q for %s", r.Method, r.URL.Path)
}

// handleNetworks handles the v2/subnets HTTP API.
func (n *Neutron) handleSubnets(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		subnetId := path.Base(r.URL.Path)
		apiFunc := path.Base(neutron.ApiSubnetsV2)
		if subnetId != apiFunc {
			subnet, err := n.subnet(subnetId)
			if err != nil {
				return errNotFoundJSON
			}
			resp := struct {
				Subnet neutron.SubnetV2 `json:"subnet"`
			}{*subnet}
		fmt.Printf("handleSubnets(): %q\n", resp)
			return sendJSON(http.StatusOK, resp, w, r)
		}
		subnets := n.allSubnets()
		if len(subnets) == 0 {
			subnets = []neutron.SubnetV2{}
		}
		resp := struct {
			Subnets []neutron.SubnetV2 `json:"subnets"`
		}{subnets}
		fmt.Printf("handleSubnets(): %q\n", resp)
		return sendJSON(http.StatusOK, resp, w, r)
	default:
		return errNotFound
	}
	return fmt.Errorf("unknown request method %q for %s", r.Method, r.URL.Path)
}

// SetupHTTP attaches all the needed handlers to provide the HTTP API.
func (n *Neutron) SetupHTTP(mux *http.ServeMux) {
	// /$v/security-groups/ matches /v2.0/security-groups/{security-group-id}
	// /$v/security-groups matches /v2.0/security-groups
	mux.Handle("/v2.0/security-groups/", n.handler((*Neutron).handleSecurityGroups))
	mux.Handle("/v2.0/security-group-rules/", n.handler((*Neutron).handleSecurityGroupRules))
	mux.Handle("/v2.0/floatingips/", n.handler((*Neutron).handleFloatingIPs))
	mux.Handle("/v2.0/networks/", n.handler((*Neutron).handleNetworks))
/*
	handlers := map[string]http.Handler{
		// "/":			n.handler((*Neutron).handleApiVersions,
		// "/v2.0":			n.handler((*Neutron).handleApiVersions,
		// "/v2.0/":	errBadRequest,
		//"/v2.0/security-groups":       n.handler((*Neutron).handleSecurityGroups),
		"/v2.0/security-groups/":      n.handler((*Neutron).handleSecurityGroups),
		//"/v2.0/security-group-rules":  n.handler((*Neutron).handleSecurityGroupRules),
		"/v2.0/security-group-rules/": n.handler((*Neutron).handleSecurityGroupRules),
		//"/v2.0/floatingips":           n.handler((*Neutron).handleFloatingIPs),
		"/v2.0/floatingips/":          n.handler((*Neutron).handleFloatingIPs),
		//"/v2.0/networks":              n.handler((*Neutron).handleNetworks),
		"/v2.0/networks/":             n.handler((*Neutron).handleNetworks),
		//"/v2.0/subnets":               n.handler((*Neutron).handleSubnets),
		"/v2.0/subnets/":              n.handler((*Neutron).handleSubnets),
	}
	for path, h := range handlers {
		//path = strings.Replace(path, "$v", n.VersionPath, 1)
		fmt.Printf("SetupHTTP(): mux.Handle(%s, %s)\n", path, h)
		mux.Handle(path, h)
	}
*/
}
