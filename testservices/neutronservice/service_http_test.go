// Neutron double testing service - HTTP API tests

package neutronservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	gc "gopkg.in/check.v1"

	"gopkg.in/goose.v1/neutron"
	"gopkg.in/goose.v1/testing/httpsuite"
	"gopkg.in/goose.v1/testservices/identityservice"
)

type NeutronHTTPSuite struct {
	httpsuite.HTTPSuite
	service *Neutron
	token   string
}

var _ = gc.Suite(&NeutronHTTPSuite{})

type NeutronHTTPSSuite struct {
	httpsuite.HTTPSuite
	service *Neutron
	token   string
}

var _ = gc.Suite(&NeutronHTTPSSuite{HTTPSuite: httpsuite.HTTPSuite{UseTLS: true}})

func (s *NeutronHTTPSuite) SetUpSuite(c *gc.C) {
	s.HTTPSuite.SetUpSuite(c)
	identityDouble := identityservice.NewUserPass()
	userInfo := identityDouble.AddUser("fred", "secret", "tenant")
	s.token = userInfo.Token
	s.service = New(s.Server.URL, versionPath, userInfo.TenantId, region, identityDouble, nil)
}

func (s *NeutronHTTPSuite) TearDownSuite(c *gc.C) {
	s.HTTPSuite.TearDownSuite(c)
}

func (s *NeutronHTTPSuite) SetUpTest(c *gc.C) {
	s.HTTPSuite.SetUpTest(c)
	s.service.SetupHTTP(s.Mux)
	// this is otherwise handled not directly by neutron test service
	// but by openstack that tries for / before.
	s.Mux.Handle("/", s.service.handler((*Neutron).handleRoot))
}

func (s *NeutronHTTPSuite) TearDownTest(c *gc.C) {
	s.HTTPSuite.TearDownTest(c)
}

// assertJSON asserts the passed http.Response's body can be
// unmarshalled into the given expected object, populating it with the
// successfully parsed data.
func assertJSON(c *gc.C, resp *http.Response, expected interface{}) {
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	c.Assert(err, gc.IsNil)
	err = json.Unmarshal(body, &expected)
	c.Assert(err, gc.IsNil)
}

// assertBody asserts the passed http.Response's body matches the
// expected response, replacing any variables in the expected body.
func assertBody(c *gc.C, resp *http.Response, expected *errorResponse) {
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	c.Assert(err, gc.IsNil)
	expBody := expected.requestBody(resp.Request)
	// cast to string for easier asserts debugging
	c.Assert(string(body), gc.Equals, string(expBody))
}

// sendRequest constructs an HTTP request from the parameters and
// sends it, returning the response or an error.
func (s *NeutronHTTPSuite) sendRequest(method, url string, body []byte, headers http.Header) (*http.Response, error) {
	if !strings.HasPrefix(url, "http") {
		url = "http://" + s.service.Hostname + strings.TrimLeft(url, "/")
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for header, values := range headers {
		for _, value := range values {
			req.Header.Add(header, value)
		}
	}
	// workaround for https://code.google.com/p/go/issues/detail?id=4454
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return http.DefaultClient.Do(req)
}

// authRequest is a shortcut for sending requests with pre-set token
// header and correct version prefix and tenant ID in the URL.
func (s *NeutronHTTPSuite) authRequest(method, path string, body []byte, headers http.Header) (*http.Response, error) {
	if headers == nil {
		headers = make(http.Header)
	}
	headers.Set(authToken, s.token)
	url := s.service.endpointURL(path)
	//url := s.service.endpointURL(false, path)
	//fmt.Printf("authRequest(): url after= %s\n", url)
	return s.sendRequest(method, url, body, headers)
}

// jsonRequest serializes the passed body object to JSON and sends a
// the request with authRequest().
func (s *NeutronHTTPSuite) jsonRequest(method, path string, body interface{}, headers http.Header) (*http.Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return s.authRequest(method, path, jsonBody, headers)
}

// setHeader creates http.Header map, sets the given header, and
// returns the map.
func setHeader(header, value string) http.Header {
	h := make(http.Header)
	h.Set(header, value)
	return h
}

// SimpleTest defines a simple request without a body and expected response.
type SimpleTest struct {
	unauth  bool
	method  string
	url     string
	headers http.Header
	expect  *errorResponse
}

func (s *NeutronHTTPSuite) simpleTests() []SimpleTest {
	var simpleTests = []SimpleTest{
		{
			unauth:  true,
			method:  "GET",
			url:     "/any",
			headers: make(http.Header),
			expect:  errUnauthorized,
		},
		{
			unauth:  true,
			method:  "POST",
			url:     "/any",
			headers: setHeader(authToken, "phony"),
			expect:  errUnauthorized,
		},
		{
			unauth:  true,
			method:  "GET",
			url:     "/any",
			headers: setHeader(authToken, s.token),
			expect:  errMultipleChoices,
		},
		{
			unauth:  true,
			method:  "POST",
			url:     "/any/unknown/one",
			headers: setHeader(authToken, s.token),
			expect:  errMultipleChoices,
		},
/*
		{
			method: "POST",
			url:    "/any/unknown/one",
			expect: errNotFound,
		},
*/
		{
			unauth:  true,
			method:  "GET",
			url:     versionPath + "/phony_token",
			headers: setHeader(authToken, s.token),
			expect:  errBadRequest,
		},
		{
			method: "GET",
			url:    neutron.ApiSecurityGroupsV2 + "/42",
			expect: errNotFoundJSONSG,
		},
		{
			method: "POST",
			url:    neutron.ApiSecurityGroupsV2,
			expect: errBadRequest2,
		},
/*
		{
			method: "POST",
			url:    neutron.ApiSecurityGroupsV2 + "/invalid",
			expect: errNotFound,
		},
*/
		{
			method: "PUT",
			url:    neutron.ApiSecurityGroupsV2,
			expect: errNotFound,
		},
/*
		{
			method: "PUT",
			url:    neutron.ApiSecurityGroupsV2 + "/invalid",
			expect: errNotFoundJSONSG,
		},
*/
		{
			method: "DELETE",
			url:    neutron.ApiSecurityGroupsV2,
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    neutron.ApiSecurityGroupsV2 + "/42",
			expect: errNotFoundJSONSG,
		},
		{
			method: "GET",
			url:    neutron.ApiSecurityGroupRulesV2,
			expect: errNotFoundJSON,
		},
		{
			method: "GET",
			url:    neutron.ApiSecurityGroupRulesV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "GET",
			url:    neutron.ApiSecurityGroupRulesV2 + "/42",
			expect: errNotFoundJSON,
		},
		{
			method: "POST",
			url:    neutron.ApiSecurityGroupRulesV2,
			expect: errBadRequest2,
		},
		{
			method: "POST",
			url:    neutron.ApiSecurityGroupRulesV2 + "/invalid",
			expect: errNotFound,
		},
/*
		{
			method: "PUT",
			url:    neutron.ApiSecurityGroupRulesV2,
			expect: errNotFound,
		},
*/
		{
			method: "PUT",
			url:    neutron.ApiSecurityGroupRulesV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "DELETE",
			url:    neutron.ApiSecurityGroupRulesV2,
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    neutron.ApiSecurityGroupRulesV2 + "/42",
			expect: errNotFoundJSONSGR,
		},
		{
			method: "GET",
			url:    neutron.ApiFloatingIPsV2 + "/42",
			expect: errNotFoundJSON,
		},
		{
			method: "POST",
			url:    neutron.ApiFloatingIPsV2 + "/invalid",
			expect: errNotFound,
		},
/*
		{
			method: "PUT",
			url:    neutron.ApiFloatingIPsV2,
			expect: errNotFound,
		},
*/
		{
			method: "PUT",
			url:    neutron.ApiFloatingIPsV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "DELETE",
			url:    neutron.ApiFloatingIPsV2,
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    neutron.ApiFloatingIPsV2 + "/invalid",
			expect: errNotFoundJSON,
		},
/*
		{
			method: "GET",
			url:    neutron.ApiNetworksV2 + "/42",
			expect: errNotFoundJSON,
		},
		{
			method: "POST",
			url:    neutron.ApiNetworksV2 + "/invalid",
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    neutron.ApiNetworksV2,
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    neutron.ApiNetworksV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "DELETE",
			url:    neutron.ApiNetworksV2,
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    neutron.ApiNetworksV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "GET",
			url:    neutron.ApiSubnetsV2 + "/42",
			expect: errNotFoundJSON,
		},
		{
			method: "POST",
			url:    neutron.ApiSubnetsV2 + "/invalid",
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    neutron.ApiSubnetsV2,
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    neutron.ApiSubnetsV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "DELETE",
			url:    neutron.ApiSubnetsV2,
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    neutron.ApiSubnetsV2 + "/invalid",
			expect: errNotFoundJSON,
		},
*/
	}
	return simpleTests
}

func (s *NeutronHTTPSuite) TestSimpleRequestTests(c *gc.C) {
	simpleTests := s.simpleTests()
	for i, t := range simpleTests {
		c.Logf("#%d. %s %s -> %d", i, t.method, t.url, t.expect.code)
		if t.headers == nil {
			t.headers = make(http.Header)
			t.headers.Set(authToken, s.token)
		}
		var (
			resp *http.Response
			err  error
		)
		if t.unauth {
			resp, err = s.sendRequest(t.method, t.url, nil, t.headers)
		} else {
			resp, err = s.authRequest(t.method, t.url, nil, t.headers)
		}
		c.Assert(err, gc.IsNil)
		c.Assert(resp.StatusCode, gc.Equals, t.expect.code)
		assertBody(c, resp, t.expect)
	}
	fmt.Printf("total: %d\n", len(simpleTests))
}

func (s *NeutronHTTPSuite) TestNewUUID(c *gc.C) {
	uuid, err := newUUID()
	c.Assert(err, gc.IsNil)
	var p1, p2, p3, p4, p5 string
	num, err := fmt.Sscanf(uuid, "%8x-%4x-%4x-%4x-%12x", &p1, &p2, &p3, &p4, &p5)
	c.Assert(err, gc.IsNil)
	c.Assert(num, gc.Equals, 5)
	uuid2, err := newUUID()
	c.Assert(err, gc.IsNil)
	c.Assert(uuid2, gc.Not(gc.Equals), uuid)
}

func (s *NeutronHTTPSuite) TestGetSecurityGroups(c *gc.C) {
	// There is always a default security group.
	groups := s.service.allSecurityGroups()
	c.Assert(groups, gc.HasLen, 1)
	var expected struct {
		Groups []neutron.SecurityGroupV2 `json:"security_groups"`
	}
	resp, err := s.authRequest("GET", neutron.ApiSecurityGroupsV2, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Groups, gc.HasLen, 1)
	groups = []neutron.SecurityGroupV2{
		{
			Id:       "1",
			Name:     "group 1",
			TenantId: s.service.TenantId,
			Rules:    []neutron.SecurityGroupRuleV2{},
		},
		{
			Id:       "2",
			Name:     "group 2",
			TenantId: s.service.TenantId,
			Rules:    []neutron.SecurityGroupRuleV2{},
		},
	}
	for _, group := range groups {
		err := s.service.addSecurityGroup(group)
		c.Assert(err, gc.IsNil)
		defer s.service.removeSecurityGroup(group.Id)
	}
	resp, err = s.authRequest("GET", neutron.ApiSecurityGroupsV2, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Groups, gc.HasLen, len(groups)+1)
	checkGroupsInList(c, groups, expected.Groups)
	var expectedGroup struct {
		Group neutron.SecurityGroupV2 `json:"security_group"`
	}
	url := fmt.Sprintf("%s/%s", neutron.ApiSecurityGroupsV2, "1")
	resp, err = s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expectedGroup)
	c.Assert(expectedGroup.Group, gc.DeepEquals, groups[0])
}

func (s *NeutronHTTPSuite) TestAddSecurityGroup(c *gc.C) {
	//fmt.Printf("TestAddSecurityGroup(): called\n")
	group := neutron.SecurityGroupV2{
		Id:          "1",
		Name:        "group 1",
		Description: "desc",
		TenantId:    s.service.TenantId,
		Rules:       []neutron.SecurityGroupRuleV2{},
	}
	_, err := s.service.securityGroup(group.Id)
	c.Assert(err, gc.NotNil)
	var req struct {
		Group struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"security_group"`
	}
	req.Group.Name = group.Name
	req.Group.Description = group.Description
	var expected struct {
		Group neutron.SecurityGroupV2 `json:"security_group"`
	}
	resp, err := s.jsonRequest("POST", neutron.ApiSecurityGroupsV2, req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusCreated)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Group, gc.DeepEquals, group)
	err = s.service.removeSecurityGroup(group.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NeutronHTTPSuite) TestDeleteSecurityGroup(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1", Name: "group 1"}
	_, err := s.service.securityGroup(group.Id)
	c.Assert(err, gc.NotNil)
	err = s.service.addSecurityGroup(group)
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup(group.Id)
	url := fmt.Sprintf("%s/%s", neutron.ApiSecurityGroupsV2, "1")
	resp, err := s.authRequest("DELETE", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusNoContent)
	_, err = s.service.securityGroup(group.Id)
	c.Assert(err, gc.NotNil)
}

func (s *NeutronHTTPSuite) TestAddSecurityGroupRule(c *gc.C) {
	group1 := neutron.SecurityGroupV2{Id: "1", Name: "src"}
	group2 := neutron.SecurityGroupV2{Id: "2", Name: "tgt"}
	err := s.service.addSecurityGroup(group1)
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup(group1.Id)
	err = s.service.addSecurityGroup(group2)
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup(group2.Id)
	riIngress := neutron.RuleInfoV2{
		ParentGroupId: "1",
		Direction:     "ingress",
		PortRangeMax:  22,
		PortRangeMin:  22,
		IPProtocol:    "tcp",
	}
	riEgress := neutron.RuleInfoV2{
		ParentGroupId: group2.Id,
		Direction:     "egress",
		PortRangeMax:  22,
		PortRangeMin:  22,
		IPProtocol:    "tcp",
	}
	rule1 := neutron.SecurityGroupRuleV2{
		Id:            "1",
		ParentGroupId: group1.Id,
		Direction:     riIngress.Direction,
		PortRangeMax:  &riIngress.PortRangeMax,
		PortRangeMin:  &riIngress.PortRangeMin,
		IPProtocol:    &riIngress.IPProtocol,
	}
	rule2 := neutron.SecurityGroupRuleV2{
		Id:            "2",
		ParentGroupId: group2.Id,
		Direction:     riEgress.Direction,
		PortRangeMax:  &riEgress.PortRangeMax,
		PortRangeMin:  &riEgress.PortRangeMin,
		IPProtocol:    &riEgress.IPProtocol,
	}
	ok := s.service.hasSecurityGroupRule(group1.Id, rule1.Id)
	c.Assert(ok, gc.Equals, false)
	ok = s.service.hasSecurityGroupRule(group2.Id, rule2.Id)
	c.Assert(ok, gc.Equals, false)
	var req struct {
		Rule neutron.RuleInfoV2 `json:"security_group_rule"`
	}
	req.Rule = riIngress
	var expected struct {
		Rule neutron.SecurityGroupRuleV2 `json:"security_group_rule"`
	}
	resp, err := s.jsonRequest("POST", neutron.ApiSecurityGroupRulesV2, req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusCreated)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Rule.Id, gc.Equals, rule1.Id)
	c.Assert(expected.Rule.ParentGroupId, gc.Equals, rule1.ParentGroupId)
	c.Assert(*expected.Rule.PortRangeMax, gc.Equals, *rule1.PortRangeMax)
	c.Assert(*expected.Rule.PortRangeMin, gc.Equals, *rule1.PortRangeMin)
	c.Assert(*expected.Rule.IPProtocol, gc.Equals, *rule1.IPProtocol)
	c.Assert(expected.Rule.Direction, gc.Equals, rule1.Direction)
	defer s.service.removeSecurityGroupRule(rule1.Id)
	req.Rule = riEgress
	resp, err = s.jsonRequest("POST", neutron.ApiSecurityGroupRulesV2, req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusCreated)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Rule.Id, gc.Equals, rule2.Id)
	c.Assert(expected.Rule.ParentGroupId, gc.Equals, rule2.ParentGroupId)
	err = s.service.removeSecurityGroupRule(rule2.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NeutronHTTPSuite) TestDeleteSecurityGroupRule(c *gc.C) {
	group1 := neutron.SecurityGroupV2{Id: "1", Name: "src"}
	group2 := neutron.SecurityGroupV2{Id: "2", Name: "tgt"}
	err := s.service.addSecurityGroup(group1)
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup(group1.Id)
	err = s.service.addSecurityGroup(group2)
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup(group2.Id)
	riGroup := neutron.RuleInfoV2{
		ParentGroupId: group2.Id,
		Direction:     "egress",
	}
	rule := neutron.SecurityGroupRuleV2{
		Id:            "1",
		ParentGroupId: group2.Id,
		Direction:     "egress",
	}
	err = s.service.addSecurityGroupRule(rule.Id, riGroup)
	c.Assert(err, gc.IsNil)
	url := fmt.Sprintf("%s/%s", neutron.ApiSecurityGroupRulesV2, "1")
	resp, err := s.authRequest("DELETE", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusNoContent)
	ok := s.service.hasSecurityGroupRule(group2.Id, rule.Id)
	c.Assert(ok, gc.Equals, false)
}

func (s *NeutronHTTPSuite) TestPostFloatingIPV2(c *gc.C) {
	fip := neutron.FloatingIPV2{Id: "1", IP: "10.0.0.1", FloatingNetworkId: "neutron"}
	c.Assert(s.service.allFloatingIPs(), gc.HasLen, 0)
	var expected struct {
		IP neutron.FloatingIPV2 `json:"floating_ip"`
	}
	resp, err := s.authRequest("POST", neutron.ApiFloatingIPsV2, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusCreated)
	assertJSON(c, resp, &expected)
	c.Assert(expected.IP, gc.DeepEquals, fip)
	err = s.service.removeFloatingIP(fip.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NeutronHTTPSuite) TestGetFloatingIPs(c *gc.C) {
	c.Assert(s.service.allFloatingIPs(), gc.HasLen, 0)
	var expected struct {
		IPs []neutron.FloatingIPV2 `json:"floating_ips"`
	}
	resp, err := s.authRequest("GET", neutron.ApiFloatingIPsV2, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.IPs, gc.HasLen, 0)
	fips := []neutron.FloatingIPV2{
		{Id: "1", IP: "1.2.3.4"},
		{Id: "2", IP: "4.3.2.1"},
	}
	for _, fip := range fips {
		err := s.service.addFloatingIP(fip)
		defer s.service.removeFloatingIP(fip.Id)
		c.Assert(err, gc.IsNil)
	}
	resp, err = s.authRequest("GET", neutron.ApiFloatingIPsV2, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	if expected.IPs[0].Id != fips[0].Id {
		expected.IPs[0], expected.IPs[1] = expected.IPs[1], expected.IPs[0]
	}
	c.Assert(expected.IPs, gc.DeepEquals, fips)
	var expectedIP struct {
		IP neutron.FloatingIPV2 `json:"floating_ip"`
	}
	url := fmt.Sprintf("%s/%s", neutron.ApiFloatingIPsV2, "1")
	resp, err = s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expectedIP)
	c.Assert(expectedIP.IP, gc.DeepEquals, fips[0])
}

func (s *NeutronHTTPSuite) TestDeleteFloatingIP(c *gc.C) {
	fip := neutron.FloatingIPV2{Id: "1", IP: "10.0.0.1"}
	err := s.service.addFloatingIP(fip)
	c.Assert(err, gc.IsNil)
	defer s.service.removeFloatingIP(fip.Id)
	url := fmt.Sprintf("%s/%s", neutron.ApiFloatingIPsV2, "1")
	resp, err := s.authRequest("DELETE", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusNoContent)
	_, err = s.service.floatingIP(fip.Id)
	c.Assert(err, gc.NotNil)
}

func (s *NeutronHTTPSSuite) SetUpSuite(c *gc.C) {
	s.HTTPSuite.SetUpSuite(c)
	identityDouble := identityservice.NewUserPass()
	userInfo := identityDouble.AddUser("fred", "secret", "tenant")
	s.token = userInfo.Token
	c.Assert(s.Server.URL[:8], gc.Equals, "https://")
	s.service = New(s.Server.URL, versionPath, userInfo.TenantId, region, identityDouble, nil)
}

func (s *NeutronHTTPSSuite) TearDownSuite(c *gc.C) {
	s.HTTPSuite.TearDownSuite(c)
}

func (s *NeutronHTTPSSuite) SetUpTest(c *gc.C) {
	s.HTTPSuite.SetUpTest(c)
	s.service.SetupHTTP(s.Mux)
}

func (s *NeutronHTTPSSuite) TearDownTest(c *gc.C) {
	s.HTTPSuite.TearDownTest(c)
}

func (s *NeutronHTTPSSuite) TestHasHTTPSServiceURL(c *gc.C) {
	endpoints := s.service.Endpoints()
	c.Assert(endpoints[0].PublicURL[:8], gc.Equals, "https://")
}
