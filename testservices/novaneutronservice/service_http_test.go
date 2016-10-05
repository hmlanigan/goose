// Nova double testing service - HTTP API tests

package novaneutronservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"

	gc "gopkg.in/check.v1"

	"gopkg.in/goose.v1/neutron"
	"gopkg.in/goose.v1/nova"
	"gopkg.in/goose.v1/testing/httpsuite"
	"gopkg.in/goose.v1/testservices/hook"
	"gopkg.in/goose.v1/testservices/identityservice"
)

type NovaNeutronHTTPSuite struct {
	httpsuite.HTTPSuite
	service *NovaNeutron
	token   string
}

var _ = gc.Suite(&NovaNeutronHTTPSuite{})

type NovaNeutronHTTPSSuite struct {
	httpsuite.HTTPSuite
	service *NovaNeutron
	token   string
}

var _ = gc.Suite(&NovaNeutronHTTPSSuite{HTTPSuite: httpsuite.HTTPSuite{UseTLS: true}})

func (s *NovaNeutronHTTPSuite) SetUpSuite(c *gc.C) {
	fmt.Printf("NovaNeutronHTTPSSuite.SetUpSuite() called\n")
	s.HTTPSuite.SetUpSuite(c)
	identityDouble := identityservice.NewUserPass()
	userInfo := identityDouble.AddUser("fred", "secret", "tenant")
	s.token = userInfo.Token
	s.service = New(s.Server.URL, versionPath, userInfo.TenantId, region, identityDouble, nil)
}

func (s *NovaNeutronHTTPSuite) TearDownSuite(c *gc.C) {
	s.HTTPSuite.TearDownSuite(c)
}

func (s *NovaNeutronHTTPSuite) SetUpTest(c *gc.C) {
	s.HTTPSuite.SetUpTest(c)
	s.service.SetupHTTP(s.Mux)
	// this is otherwise handled not directly by nova test service
	// but by openstack that tries for / before.
	s.Mux.Handle("/", s.service.handler((*NovaNeutron).handleRoot))
}

func (s *NovaNeutronHTTPSuite) TearDownTest(c *gc.C) {
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
func (s *NovaNeutronHTTPSuite) sendRequest(method, url string, body []byte, headers http.Header) (*http.Response, error) {
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
func (s *NovaNeutronHTTPSuite) authRequest(method, path string, body []byte, headers http.Header) (*http.Response, error) {
	if headers == nil {
		headers = make(http.Header)
	}
	headers.Set(authToken, s.token)
	url := s.service.endpointURL(true, path)
	return s.sendRequest(method, url, body, headers)
}

// jsonRequest serializes the passed body object to JSON and sends a
// the request with authRequest().
func (s *NovaNeutronHTTPSuite) jsonRequest(method, path string, body interface{}, headers http.Header) (*http.Response, error) {
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

func (s *NovaNeutronHTTPSuite) simpleTests() []SimpleTest {
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
		{
			method: "POST",
			url:    "/any/unknown/one",
			expect: errNotFound,
		},
		{
			unauth:  true,
			method:  "GET",
			url:     versionPath + "/phony_token",
			headers: setHeader(authToken, s.token),
			expect:  errBadRequest,
		},
		{
			method: "GET",
			url:    "/flavors/",
			expect: errNotFound,
		},
		{
			method: "GET",
			url:    "/flavors/invalid",
			expect: errNotFound,
		},
		{
			method: "POST",
			url:    "/flavors",
			expect: errBadRequest2,
		},
		{
			method: "POST",
			url:    "/flavors/invalid",
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    "/flavors",
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    "/flavors/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "DELETE",
			url:    "/flavors",
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    "/flavors/invalid",
			expect: errForbidden,
		},
		{
			method: "GET",
			url:    "/flavors/detail/invalid",
			expect: errNotFound,
		},
		{
			method: "POST",
			url:    "/flavors/detail",
			expect: errNotFound,
		},
		{
			method: "POST",
			url:    "/flavors/detail/invalid",
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    "/flavors/detail",
			expect: errNotFoundJSON,
		},
		{
			method: "PUT",
			url:    "/flavors/detail/invalid",
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    "/flavors/detail",
			expect: errForbidden,
		},
		{
			method: "DELETE",
			url:    "/flavors/detail/invalid",
			expect: errNotFound,
		},
		{
			method: "GET",
			url:    "/servers/invalid",
			expect: &errorResponse{code: 404, body: "{\"itemNotFound\":{\"message\":\"No such server \\\"invalid\\\"\", \"code\":404}}"},
		},
		{
			method: "POST",
			url:    "/servers",
			expect: errBadRequest2,
		},
		{
			method: "POST",
			url:    "/servers/invalid",
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    "/servers",
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    "/servers/invalid",
			expect: errBadRequest2,
		},
		{
			method: "DELETE",
			url:    "/servers",
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    "/servers/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "GET",
			url:    "/servers/detail/invalid",
			expect: errNotFound,
		},
		{
			method: "POST",
			url:    "/servers/detail",
			expect: errNotFound,
		},
		{
			method: "POST",
			url:    "/servers/detail/invalid",
			expect: errNotFound,
		},
		{
			method: "PUT",
			url:    "/servers/detail",
			expect: errBadRequest2,
		},
		{
			method: "PUT",
			url:    "/servers/detail/invalid",
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    "/servers/detail",
			expect: errNotFoundJSON,
		},
		{
			method: "DELETE",
			url:    "/servers/detail/invalid",
			expect: errNotFound,
		},
		/*
			{
				method: "GET",
				url:    "/os-security-groups/42",
				expect: errNotFoundJSONSG,
			},
			{
				method: "POST",
				url:    "/os-security-groups",
				expect: errBadRequest2,
			},
			{
				method: "POST",
				url:    "/os-security-groups/invalid",
				expect: errNotFound,
			},
			{
				method: "PUT",
				url:    "/os-security-groups",
				expect: errNotFound,
			},
			{
				method: "PUT",
				url:    "/os-security-groups/invalid",
				expect: errNotFoundJSONSG,
			},
			{
				method: "DELETE",
				url:    "/os-security-groups",
				expect: errNotFound,
			},
			{
				method: "DELETE",
				url:    "/os-security-groups/42",
				expect: errNotFoundJSONSG,
			},
			{
				method: "GET",
				url:    "/os-security-group-rules",
				expect: errNotFoundJSON,
			},
			{
				method: "GET",
				url:    "/os-security-group-rules/invalid",
				expect: errNotFoundJSON,
			},
			{
				method: "GET",
				url:    "/os-security-group-rules/42",
				expect: errNotFoundJSON,
			},
			{
				method: "POST",
				url:    "/os-security-group-rules",
				expect: errBadRequest2,
			},
			{
				method: "POST",
				url:    "/os-security-group-rules/invalid",
				expect: errNotFound,
			},
			{
				method: "PUT",
				url:    "/os-security-group-rules",
				expect: errNotFound,
			},
			{
				method: "PUT",
				url:    "/os-security-group-rules/invalid",
				expect: errNotFoundJSON,
			},
			{
				method: "DELETE",
				url:    "/os-security-group-rules",
				expect: errNotFound,
			},
			{
				method: "DELETE",
				url:    "/os-security-group-rules/42",
				expect: errNotFoundJSONSGR,
			},
			{
				method: "GET",
				url:    "/os-floating-ips/42",
				expect: errNotFoundJSON,
			},
			{
				method: "POST",
				url:    "/os-floating-ips/invalid",
				expect: errNotFound,
			},
			{
				method: "PUT",
				url:    "/os-floating-ips",
				expect: errNotFound,
			},
			{
				method: "PUT",
				url:    "/os-floating-ips/invalid",
				expect: errNotFoundJSON,
			},
			{
				method: "DELETE",
				url:    "/os-floating-ips",
				expect: errNotFound,
			},
			{
				method: "DELETE",
				url:    "/os-floating-ips/invalid",
				expect: errNotFoundJSON,
			},
			{
				method: "GET",
				url:    "v2.0" + neutron.ApiSecurityGroupsV2 + "/42",
				expect: errNotFoundJSONSG,
			},
			{
				method: "POST",
				url:    "v2.0" + neutron.ApiSecurityGroupsV2,
				expect: errBadRequest2,
			},
				{
					method: "POST",
					url:    "v2.0"+neutron.ApiSecurityGroupsV2 + "/invalid",
					expect: errNotFound,
				},
		*/
		{
			method: "PUT",
			url:    "v2.0" + neutron.ApiSecurityGroupsV2,
			expect: errNotFound,
		},
		/*
			{
				method: "PUT",
				url:    "v2.0"+neutron.ApiSecurityGroupsV2 + "/invalid",
				expect: errNotFoundJSONSG,
			},
		*/
		{
			method: "DELETE",
			url:    "v2.0" + neutron.ApiSecurityGroupsV2,
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    "v2.0" + neutron.ApiSecurityGroupsV2 + "/42",
			expect: errNotFoundJSONSG,
		},
		{
			method: "GET",
			url:    "v2.0" + neutron.ApiSecurityGroupRulesV2,
			expect: errNotFoundJSON,
		},
		{
			method: "GET",
			url:    "v2.0" + neutron.ApiSecurityGroupRulesV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "GET",
			url:    "v2.0" + neutron.ApiSecurityGroupRulesV2 + "/42",
			expect: errNotFoundJSON,
		},
		{
			method: "POST",
			url:    "v2.0" + neutron.ApiSecurityGroupRulesV2,
			expect: errBadRequest2,
		},
		{
			method: "POST",
			url:    "v2.0" + neutron.ApiSecurityGroupRulesV2 + "/invalid",
			expect: errNotFound,
		},
		/*
			{
				method: "PUT",
				url:    "v2.0"+neutron.ApiSecurityGroupRulesV2,
				expect: errNotFound,
			},
		*/
		{
			method: "PUT",
			url:    "v2.0" + neutron.ApiSecurityGroupRulesV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "DELETE",
			url:    "v2.0" + neutron.ApiSecurityGroupRulesV2,
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    "v2.0" + neutron.ApiSecurityGroupRulesV2 + "/42",
			expect: errNotFoundJSONSGR,
		},
		{
			method: "GET",
			url:    "v2.0" + neutron.ApiFloatingIPsV2 + "/42",
			expect: errNotFoundJSON,
		},
		{
			method: "POST",
			url:    "v2.0" + neutron.ApiFloatingIPsV2 + "/invalid",
			expect: errNotFound,
		},
		/*
			{
				method: "PUT",
				url:    "v2.0"+neutron.ApiFloatingIPsV2,
				expect: errNotFound,
			},
		*/
		{
			method: "PUT",
			url:    "v2.0" + neutron.ApiFloatingIPsV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		{
			method: "DELETE",
			url:    "v2.0" + neutron.ApiFloatingIPsV2,
			expect: errNotFound,
		},
		{
			method: "DELETE",
			url:    "v2.0" + neutron.ApiFloatingIPsV2 + "/invalid",
			expect: errNotFoundJSON,
		},
		/*
			{
				method: "GET",
				url:    "v2.0"+neutron.ApiNetworksV2 + "/42",
				expect: errNotFoundJSON,
			},
			{
				method: "POST",
				url:    "v2.0"+neutron.ApiNetworksV2 + "/invalid",
				expect: errNotFound,
			},
			{
				method: "PUT",
				url:    "v2.0"+neutron.ApiNetworksV2,
				expect: errNotFound,
			},
			{
				method: "PUT",
				url:    "v2.0"+neutron.ApiNetworksV2 + "/invalid",
				expect: errNotFound,
			},
			{
				method: "DELETE",
				url:    "v2.0"+neutron.ApiNetworksV2,
				expect: errNotFound,
			},
			{
				method: "DELETE",
				url:    "v2.0"+neutron.ApiNetworksV2 + "/invalid",
				expect: errNotFound,
			},
			{
				method: "GET",
				url:    "v2.0"+neutron.ApiSubnetsV2 + "/42",
				expect: errNotFoundJSON,
			},
			{
				method: "POST",
				url:    "v2.0"+neutron.ApiSubnetsV2 + "/invalid",
				expect: errNotFoundJSON,
			},
			{
				method: "PUT",
				url:    "v2.0"+neutron.ApiSubnetsV2,
				expect: errNotFound,
			},
			{
				method: "PUT",
				url:    "v2.0"+neutron.ApiSubnetsV2 + "/invalid",
				expect: errNotFound,
			},
			{
				method: "DELETE",
				url:    "v2.0"+neutron.ApiSubnetsV2,
				expect: errNotFound,
			},
			{
				method: "DELETE",
				url:    "v2.0"+neutron.ApiSubnetsV2 + "/invalid",
				expect: errNotFound,
			},
		*/
	}
	return simpleTests
}

func (s *NovaNeutronHTTPSuite) TestSimpleRequestTests(c *gc.C) {
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

func (s *NovaNeutronHTTPSuite) TestGetFlavors(c *gc.C) {
	// The test service has 3 default flavours.
	var expected struct {
		Flavors []nova.Entity
	}
	resp, err := s.authRequest("GET", "/flavors", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Flavors, gc.HasLen, 3)
	entities := s.service.allFlavorsAsEntities()
	c.Assert(entities, gc.HasLen, 3)
	sort.Sort(nova.EntitySortBy{Attr: "Id", Entities: expected.Flavors})
	sort.Sort(nova.EntitySortBy{Attr: "Id", Entities: entities})
	c.Assert(expected.Flavors, gc.DeepEquals, entities)
	var expectedFlavor struct {
		Flavor nova.FlavorDetail
	}
	resp, err = s.authRequest("GET", "/flavors/1", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expectedFlavor)
	c.Assert(expectedFlavor.Flavor.Name, gc.Equals, "m1.tiny")
}

func (s *NovaNeutronHTTPSuite) TestGetFlavorsDetail(c *gc.C) {
	// The test service has 3 default flavours.
	flavors := s.service.allFlavors()
	c.Assert(flavors, gc.HasLen, 3)
	var expected struct {
		Flavors []nova.FlavorDetail
	}
	resp, err := s.authRequest("GET", "/flavors/detail", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Flavors, gc.HasLen, 3)
	sort.Sort(nova.FlavorDetailSortBy{Attr: "Id", FlavorDetails: expected.Flavors})
	sort.Sort(nova.FlavorDetailSortBy{Attr: "Id", FlavorDetails: flavors})
	c.Assert(expected.Flavors, gc.DeepEquals, flavors)
	resp, err = s.authRequest("GET", "/flavors/detail/1", nil, nil)
	c.Assert(err, gc.IsNil)
	assertBody(c, resp, errNotFound)
}

func (s *NovaNeutronHTTPSuite) TestGetServers(c *gc.C) {
	entities, err := s.service.allServersAsEntities(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(entities, gc.HasLen, 0)
	var expected struct {
		Servers []nova.Entity
	}
	resp, err := s.authRequest("GET", "/servers", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Servers, gc.HasLen, 0)
	servers := []nova.ServerDetail{
		{Id: "sr1", Name: "server 1"},
		{Id: "sr2", Name: "server 2"},
	}
	for i, server := range servers {
		s.service.buildServerLinks(&server)
		servers[i] = server
		err := s.service.addServer(server)
		c.Assert(err, gc.IsNil)
		defer s.service.removeServer(server.Id)
	}
	entities, err = s.service.allServersAsEntities(nil)
	c.Assert(err, gc.IsNil)
	resp, err = s.authRequest("GET", "/servers", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Servers, gc.HasLen, 2)
	if expected.Servers[0].Id != entities[0].Id {
		expected.Servers[0], expected.Servers[1] = expected.Servers[1], expected.Servers[0]
	}
	c.Assert(expected.Servers, gc.DeepEquals, entities)
	var expectedServer struct {
		Server nova.ServerDetail
	}
	resp, err = s.authRequest("GET", "/servers/sr1", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expectedServer)
	c.Assert(expectedServer.Server, gc.DeepEquals, servers[0])
}

func (s *NovaNeutronHTTPSuite) TestGetServersWithFilters(c *gc.C) {
	entities, err := s.service.allServersAsEntities(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(entities, gc.HasLen, 0)
	var expected struct {
		Servers []nova.Entity
	}
	url := "/servers?status=RESCUE&status=BUILD&name=srv2&name=srv1"
	resp, err := s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Servers, gc.HasLen, 0)
	servers := []nova.ServerDetail{
		{Id: "sr1", Name: "srv1", Status: nova.StatusBuild},
		{Id: "sr2", Name: "srv2", Status: nova.StatusRescue},
		{Id: "sr3", Name: "srv3", Status: nova.StatusActive},
	}
	for i, server := range servers {
		s.service.buildServerLinks(&server)
		servers[i] = server
		err := s.service.addServer(server)
		c.Assert(err, gc.IsNil)
		defer s.service.removeServer(server.Id)
	}
	resp, err = s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Servers, gc.HasLen, 1)
	c.Assert(expected.Servers[0].Id, gc.Equals, servers[0].Id)
	c.Assert(expected.Servers[0].Name, gc.Equals, servers[0].Name)
}

func (s *NovaNeutronHTTPSuite) TestGetServersWithBadFilter(c *gc.C) {
	url := "/servers?name=(server"
	resp, err := s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusInternalServerError)
	type novaError struct {
		Code    int
		Message string
	}
	var expected struct {
		novaError `json:"computeFault"`
	}
	assertJSON(c, resp, &expected)
	c.Check(expected.Code, gc.Equals, 500)
	c.Check(expected.Message, gc.Matches, `error parsing.*\(server.*`)
}

func (s *NovaNeutronHTTPSuite) TestGetServersPatchMatch(c *gc.C) {
	cleanup := s.service.RegisterControlPoint(
		"matchServers",
		func(sc hook.ServiceControl, args ...interface{}) error {
			return fmt.Errorf("Unexpected error")
		},
	)
	defer cleanup()
	resp, err := s.authRequest("GET", "/servers", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusInternalServerError)
	type novaError struct {
		Code    int
		Message string
	}
	var expected struct {
		novaError `json:"computeFault"`
	}
	assertJSON(c, resp, &expected)
	c.Check(expected.Code, gc.Equals, 500)
	c.Check(expected.Message, gc.Equals, "Unexpected error")
}

func (s *NovaNeutronHTTPSuite) TestNewUUID(c *gc.C) {
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

func (s *NovaNeutronHTTPSuite) assertAddresses(c *gc.C, serverId string) {
	server, err := s.service.server(serverId)
	c.Assert(err, gc.IsNil)
	c.Assert(server.Addresses, gc.HasLen, 2)
	c.Assert(server.Addresses["public"], gc.HasLen, 2)
	c.Assert(server.Addresses["private"], gc.HasLen, 2)
	for network, addresses := range server.Addresses {
		for _, addr := range addresses {
			if addr.Version == 4 && network == "public" {
				c.Assert(addr.Address, gc.Matches, `127\.10\.0\.\d{1,3}`)
			} else if addr.Version == 4 && network == "private" {
				c.Assert(addr.Address, gc.Matches, `127\.0\.0\.\d{1,3}`)
			}
		}

	}
}

func (s *NovaNeutronHTTPSuite) TestRunServer(c *gc.C) {
	entities, err := s.service.allServersAsEntities(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(entities, gc.HasLen, 0)
	var req struct {
		Server struct {
			FlavorRef      string              `json:"flavorRef"`
			ImageRef       string              `json:"imageRef"`
			Name           string              `json:"name"`
			SecurityGroups []map[string]string `json:"security_groups"`
		} `json:"server"`
	}
	resp, err := s.jsonRequest("POST", "/servers", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusBadRequest)
	assertBody(c, resp, errBadRequestSrvName)
	req.Server.Name = "srv1"
	resp, err = s.jsonRequest("POST", "/servers", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusBadRequest)
	assertBody(c, resp, errBadRequestSrvImage)
	req.Server.ImageRef = "image"
	resp, err = s.jsonRequest("POST", "/servers", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusBadRequest)
	assertBody(c, resp, errBadRequestSrvFlavor)
	req.Server.FlavorRef = "flavor"
	var expected struct {
		Server struct {
			SecurityGroups []map[string]string `json:"security_groups"`
			Id             string
			Links          []nova.Link
			AdminPass      string
		}
	}
	resp, err = s.jsonRequest("POST", "/servers", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusAccepted)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Server.SecurityGroups, gc.HasLen, 1)
	c.Assert(expected.Server.SecurityGroups[0]["name"], gc.Equals, "default")
	c.Assert(expected.Server.Id, gc.Not(gc.Equals), "")
	c.Assert(expected.Server.Links, gc.HasLen, 2)
	c.Assert(expected.Server.AdminPass, gc.Not(gc.Equals), "")
	s.assertAddresses(c, expected.Server.Id)
	srv, err := s.service.server(expected.Server.Id)
	c.Assert(err, gc.IsNil)
	c.Assert(srv.Links, gc.DeepEquals, expected.Server.Links)
	s.service.removeServer(srv.Id)
	req.Server.Name = "test2"
	req.Server.SecurityGroups = []map[string]string{
		{"name": "default"},
		{"name": "group1"},
		{"name": "group2"},
	}
	err = s.service.addSecurityGroup(neutron.SecurityGroupV2{Id: "1", Name: "group1"})
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup("1")
	err = s.service.addSecurityGroup(neutron.SecurityGroupV2{Id: "2", Name: "group2"})
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup("2")
	resp, err = s.jsonRequest("POST", "/servers", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusAccepted)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Server.SecurityGroups, gc.DeepEquals, req.Server.SecurityGroups)
	srv, err = s.service.server(expected.Server.Id)
	c.Assert(err, gc.IsNil)
	ok := s.service.hasServerSecurityGroup(srv.Id, "1")
	c.Assert(ok, gc.Equals, true)
	ok = s.service.hasServerSecurityGroup(srv.Id, "2")
	c.Assert(ok, gc.Equals, true)
	ok = s.service.hasServerSecurityGroup(srv.Id, "999")
	c.Assert(ok, gc.Equals, true)
	s.service.removeServerSecurityGroup(srv.Id, "1")
	s.service.removeServerSecurityGroup(srv.Id, "2")
	s.service.removeServerSecurityGroup(srv.Id, "999")
	s.service.removeServer(srv.Id)
}

func (s *NovaNeutronHTTPSuite) TestDeleteServer(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	_, err := s.service.server(server.Id)
	c.Assert(err, gc.NotNil)
	err = s.service.addServer(server)
	c.Assert(err, gc.IsNil)
	defer s.service.removeServer(server.Id)
	resp, err := s.authRequest("DELETE", "/servers/sr1", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusNoContent)
	_, err = s.service.server(server.Id)
	c.Assert(err, gc.NotNil)
}

func (s *NovaNeutronHTTPSuite) TestGetServersDetail(c *gc.C) {
	servers, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(servers, gc.HasLen, 0)
	var expected struct {
		Servers []nova.ServerDetail `json:"servers"`
	}
	resp, err := s.authRequest("GET", "/servers/detail", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Servers, gc.HasLen, 0)
	servers = []nova.ServerDetail{
		{Id: "sr1", Name: "server 1"},
		{Id: "sr2", Name: "server 2"},
	}
	for i, server := range servers {
		s.service.buildServerLinks(&server)
		servers[i] = server
		err := s.service.addServer(server)
		c.Assert(err, gc.IsNil)
		defer s.service.removeServer(server.Id)
	}
	resp, err = s.authRequest("GET", "/servers/detail", nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Servers, gc.HasLen, 2)
	if expected.Servers[0].Id != servers[0].Id {
		expected.Servers[0], expected.Servers[1] = expected.Servers[1], expected.Servers[0]
	}
	c.Assert(expected.Servers, gc.DeepEquals, servers)
	resp, err = s.authRequest("GET", "/servers/detail/sr1", nil, nil)
	c.Assert(err, gc.IsNil)
	assertBody(c, resp, errNotFound)
}

func (s *NovaNeutronHTTPSuite) TestGetServersDetailWithFilters(c *gc.C) {
	servers, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(servers, gc.HasLen, 0)
	var expected struct {
		Servers []nova.ServerDetail `json:"servers"`
	}
	url := "/servers/detail?status=RESCUE&status=BUILD&name=srv2&name=srv1"
	resp, err := s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Servers, gc.HasLen, 0)
	servers = []nova.ServerDetail{
		{Id: "sr1", Name: "srv1", Status: nova.StatusBuild},
		{Id: "sr2", Name: "srv2", Status: nova.StatusRescue},
		{Id: "sr3", Name: "srv3", Status: nova.StatusActive},
	}
	for i, server := range servers {
		s.service.buildServerLinks(&server)
		servers[i] = server
		err := s.service.addServer(server)
		c.Assert(err, gc.IsNil)
		defer s.service.removeServer(server.Id)
	}
	resp, err = s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Servers, gc.HasLen, 1)
	c.Assert(expected.Servers[0], gc.DeepEquals, servers[0])
}

func (s *NovaNeutronHTTPSuite) TestAddServerSecurityGroup(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1", Name: "group"}
	err := s.service.addSecurityGroup(group)
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup(group.Id)
	server := nova.ServerDetail{Id: "sr1"}
	err = s.service.addServer(server)
	c.Assert(err, gc.IsNil)
	defer s.service.removeServer(server.Id)
	ok := s.service.hasServerSecurityGroup(server.Id, group.Id)
	c.Assert(ok, gc.Equals, false)
	var req struct {
		Group struct {
			Name string `json:"name"`
		} `json:"addSecurityGroup"`
	}
	req.Group.Name = group.Name
	resp, err := s.jsonRequest("POST", "/servers/"+server.Id+"/action", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusAccepted)
	ok = s.service.hasServerSecurityGroup(server.Id, group.Id)
	c.Assert(ok, gc.Equals, true)
	err = s.service.removeServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronHTTPSuite) TestGetServerSecurityGroups(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	groups := []neutron.SecurityGroupV2{
		{
			Id:       "1",
			Name:     "group1",
			TenantId: s.service.TenantId,
			Rules:    []neutron.SecurityGroupRuleV2{},
		},
		{
			Id:       "2",
			Name:     "group2",
			TenantId: s.service.TenantId,
			Rules:    []neutron.SecurityGroupRuleV2{},
		},
	}
	srvGroups := s.service.allServerSecurityGroups(server.Id)
	c.Assert(srvGroups, gc.HasLen, 0)
	err := s.service.addServer(server)
	c.Assert(err, gc.IsNil)
	defer s.service.removeServer(server.Id)
	for _, group := range groups {
		err = s.service.addSecurityGroup(group)
		c.Assert(err, gc.IsNil)
		defer s.service.removeSecurityGroup(group.Id)
		err = s.service.addServerSecurityGroup(server.Id, group.Id)
		c.Assert(err, gc.IsNil)
		defer s.service.removeServerSecurityGroup(server.Id, group.Id)
	}
	srvGroups = s.service.allServerSecurityGroups(server.Id)
	/*
		var expected struct {
			Groups []neutron.SecurityGroupV2 `json:"security_groups"`
		}
		resp, err := s.authRequest("GET", "v2.0"+neutron.ApiSecurityGroupsV2, nil, nil)
		c.Assert(err, gc.IsNil)
		assertJSON(c, resp, &expected)
	*/
	c.Assert(srvGroups, gc.DeepEquals, groups)
}

func (s *NovaNeutronHTTPSuite) TestDeleteServerSecurityGroup(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1", Name: "group"}
	err := s.service.addSecurityGroup(group)
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup(group.Id)
	server := nova.ServerDetail{Id: "sr1"}
	err = s.service.addServer(server)
	c.Assert(err, gc.IsNil)
	defer s.service.removeServer(server.Id)
	ok := s.service.hasServerSecurityGroup(server.Id, group.Id)
	c.Assert(ok, gc.Equals, false)
	err = s.service.addServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
	var req struct {
		Group struct {
			Name string `json:"name"`
		} `json:"removeSecurityGroup"`
	}
	req.Group.Name = group.Name
	resp, err := s.jsonRequest("POST", "/servers/"+server.Id+"/action", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusAccepted)
	ok = s.service.hasServerSecurityGroup(server.Id, group.Id)
	c.Assert(ok, gc.Equals, false)
}

func (s *NovaNeutronHTTPSuite) TestAddServerFloatingIP(c *gc.C) {
	fip := neutron.FloatingIPV2{Id: "1", IP: "1.2.3.4"}
	server := nova.ServerDetail{Id: "sr1"}
	err := s.service.addFloatingIP(fip)
	c.Assert(err, gc.IsNil)
	defer s.service.removeFloatingIP(fip.Id)
	err = s.service.addServer(server)
	c.Assert(err, gc.IsNil)
	defer s.service.removeServer(server.Id)
	c.Assert(s.service.hasServerFloatingIP(server.Id, fip.IP), gc.Equals, false)
	var req struct {
		AddFloatingIP struct {
			Address string `json:"address"`
		} `json:"addFloatingIp"`
	}
	req.AddFloatingIP.Address = fip.IP
	resp, err := s.jsonRequest("POST", "/servers/"+server.Id+"/action", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusAccepted)
	c.Assert(s.service.hasServerFloatingIP(server.Id, fip.IP), gc.Equals, true)
	err = s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronHTTPSuite) TestRemoveServerFloatingIP(c *gc.C) {
	fip := neutron.FloatingIPV2{Id: "1", IP: "1.2.3.4"}
	server := nova.ServerDetail{Id: "sr1"}
	err := s.service.addFloatingIP(fip)
	c.Assert(err, gc.IsNil)
	defer s.service.removeFloatingIP(fip.Id)
	err = s.service.addServer(server)
	c.Assert(err, gc.IsNil)
	defer s.service.removeServer(server.Id)
	err = s.service.addServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
	defer s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(s.service.hasServerFloatingIP(server.Id, fip.IP), gc.Equals, true)
	var req struct {
		RemoveFloatingIP struct {
			Address string `json:"address"`
		} `json:"removeFloatingIp"`
	}
	req.RemoveFloatingIP.Address = fip.IP
	resp, err := s.jsonRequest("POST", "/servers/"+server.Id+"/action", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusAccepted)
	c.Assert(s.service.hasServerFloatingIP(server.Id, fip.IP), gc.Equals, false)
}

func (s *NovaNeutronHTTPSuite) TestListAvailabilityZones(c *gc.C) {
	resp, err := s.jsonRequest("GET", "/os-availability-zone", nil, nil)
	c.Assert(err, gc.IsNil)
	assertBody(c, resp, errNotFoundJSON)

	zones := []nova.AvailabilityZone{
		{Name: "az1"},
		{
			Name: "az2", State: nova.AvailabilityZoneState{Available: true},
		},
	}
	s.service.SetAvailabilityZones(zones...)
	resp, err = s.jsonRequest("GET", "/os-availability-zone", nil, nil)
	c.Assert(err, gc.IsNil)
	var expected struct {
		Zones []nova.AvailabilityZone `json:"availabilityZoneInfo"`
	}
	assertJSON(c, resp, &expected)
	c.Assert(expected.Zones, gc.DeepEquals, zones)
}

func (s *NovaNeutronHTTPSuite) TestGetSecurityGroups(c *gc.C) {
	// There is always a default security group.
	groups := s.service.allSecurityGroups()
	c.Assert(groups, gc.HasLen, 1)
	var expected struct {
		Groups []neutron.SecurityGroupV2 `json:"security_groups"`
	}
	resp, err := s.authRequest("GET", "v2.0"+neutron.ApiSecurityGroupsV2, nil, nil)
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
	resp, err = s.authRequest("GET", "v2.0"+neutron.ApiSecurityGroupsV2, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Groups, gc.HasLen, len(groups)+1)
	checkGroupsInList(c, groups, expected.Groups)
	var expectedGroup struct {
		Group neutron.SecurityGroupV2 `json:"security_group"`
	}
	url := fmt.Sprintf("%s/%s", "v2.0"+neutron.ApiSecurityGroupsV2, "1")
	resp, err = s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expectedGroup)
	c.Assert(expectedGroup.Group, gc.DeepEquals, groups[0])
}

func (s *NovaNeutronHTTPSuite) TestAddSecurityGroup(c *gc.C) {
	fmt.Printf("TestAddSecurityGroup(): called, %q\n", s.service)
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
	resp, err := s.jsonRequest("POST", "v2.0"+neutron.ApiSecurityGroupsV2, req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusCreated)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Group, gc.DeepEquals, group)
	err = s.service.removeSecurityGroup(group.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronHTTPSuite) TestDeleteSecurityGroup(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1", Name: "group 1"}
	_, err := s.service.securityGroup(group.Id)
	c.Assert(err, gc.NotNil)
	err = s.service.addSecurityGroup(group)
	c.Assert(err, gc.IsNil)
	defer s.service.removeSecurityGroup(group.Id)
	url := fmt.Sprintf("%s/%s", "v2.0"+neutron.ApiSecurityGroupsV2, "1")
	resp, err := s.authRequest("DELETE", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusNoContent)
	_, err = s.service.securityGroup(group.Id)
	c.Assert(err, gc.NotNil)
}

func (s *NovaNeutronHTTPSuite) TestAddSecurityGroupRule(c *gc.C) {
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
	resp, err := s.jsonRequest("POST", "v2.0"+neutron.ApiSecurityGroupRulesV2, req, nil)
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
	resp, err = s.jsonRequest("POST", "v2.0"+neutron.ApiSecurityGroupRulesV2, req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusCreated)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Rule.Id, gc.Equals, rule2.Id)
	c.Assert(expected.Rule.ParentGroupId, gc.Equals, rule2.ParentGroupId)
	err = s.service.removeSecurityGroupRule(rule2.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronHTTPSuite) TestDeleteSecurityGroupRule(c *gc.C) {
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
	url := fmt.Sprintf("%s/%s", "v2.0"+neutron.ApiSecurityGroupRulesV2, "1")
	resp, err := s.authRequest("DELETE", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusNoContent)
	ok := s.service.hasSecurityGroupRule(group2.Id, rule.Id)
	c.Assert(ok, gc.Equals, false)
}

func (s *NovaNeutronHTTPSuite) TestPostFloatingIPV2(c *gc.C) {
	fip := neutron.FloatingIPV2{Id: "1", IP: "10.0.0.1", FloatingNetworkId: "neutron"}
	c.Assert(s.service.allFloatingIPs(), gc.HasLen, 0)
	var expected struct {
		IP neutron.FloatingIPV2 `json:"floating_ip"`
	}
	resp, err := s.authRequest("POST", "v2.0"+neutron.ApiFloatingIPsV2, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusCreated)
	assertJSON(c, resp, &expected)
	c.Assert(expected.IP, gc.DeepEquals, fip)
	err = s.service.removeFloatingIP(fip.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronHTTPSuite) TestGetFloatingIPs(c *gc.C) {
	c.Assert(s.service.allFloatingIPs(), gc.HasLen, 0)
	var expected struct {
		IPs []neutron.FloatingIPV2 `json:"floating_ips"`
	}
	resp, err := s.authRequest("GET", "v2.0"+neutron.ApiFloatingIPsV2, nil, nil)
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
	resp, err = s.authRequest("GET", "v2.0"+neutron.ApiFloatingIPsV2, nil, nil)
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
	url := fmt.Sprintf("%s/%s", "v2.0"+neutron.ApiFloatingIPsV2, "1")
	resp, err = s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expectedIP)
	c.Assert(expectedIP.IP, gc.DeepEquals, fips[0])
}

func (s *NovaNeutronHTTPSuite) TestDeleteFloatingIP(c *gc.C) {
	fip := neutron.FloatingIPV2{Id: "1", IP: "10.0.0.1"}
	err := s.service.addFloatingIP(fip)
	c.Assert(err, gc.IsNil)
	defer s.service.removeFloatingIP(fip.Id)
	url := fmt.Sprintf("%s/%s", "v2.0"+neutron.ApiFloatingIPsV2, "1")
	resp, err := s.authRequest("DELETE", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusNoContent)
	_, err = s.service.floatingIP(fip.Id)
	c.Assert(err, gc.NotNil)
}

func (s *NovaNeutronHTTPSuite) TestGetNetworks(c *gc.C) {
	// There are always 2 networks
	networks := s.service.allNetworks()
	c.Assert(networks, gc.HasLen, 2)
	var expected struct {
		Networks []neutron.NetworkV2 `json:"networks"`
	}
	resp, err := s.authRequest("GET", "v2.0"+neutron.ApiNetworksV2, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Networks, gc.HasLen, len(networks))
	//fmt.Printf("TestGetNetworks(): expected.Networks = %q\n", expected.Networks)
	var expectedNetwork struct {
		Network neutron.NetworkV2 `json:"network"`
	}
	url := fmt.Sprintf("%s/%s", "v2.0"+neutron.ApiNetworksV2, networks[0].Id)
	resp, err = s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expectedNetwork)
	//fmt.Printf("TestGetNetworks(): expectedNetwork.Network = %q\n", expectedNetwork.Network)
	//fmt.Printf("TestGetNetworks(): networks = %q\n", networks)
	c.Assert(expectedNetwork.Network, gc.DeepEquals, networks[0])
}

func (s *NovaNeutronHTTPSuite) TestGetSubnets(c *gc.C) {
	// There are always 2 subnets
	subnets := s.service.allSubnets()
	c.Assert(subnets, gc.HasLen, 2)
	var expected struct {
		Subnets []neutron.SubnetV2 `json:"subnets"`
	}
	resp, err := s.authRequest("GET", "v2.0"+neutron.ApiSubnetsV2, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expected)
	c.Assert(expected.Subnets, gc.HasLen, 2)
	var expectedSubnet struct {
		Subnet neutron.SubnetV2 `json:"subnet"`
	}
	url := fmt.Sprintf("%s/%s", "v2.0"+neutron.ApiSubnetsV2, subnets[0].Id)
	resp, err = s.authRequest("GET", url, nil, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	assertJSON(c, resp, &expectedSubnet)
	c.Assert(expectedSubnet.Subnet, gc.DeepEquals, subnets[0])
}

func (s *NovaNeutronHTTPSSuite) SetUpSuite(c *gc.C) {
	s.HTTPSuite.SetUpSuite(c)
	identityDouble := identityservice.NewUserPass()
	userInfo := identityDouble.AddUser("fred", "secret", "tenant")
	s.token = userInfo.Token
	c.Assert(s.Server.URL[:8], gc.Equals, "https://")
	s.service = New(s.Server.URL, versionPath, userInfo.TenantId, region, identityDouble, nil)
}

func (s *NovaNeutronHTTPSSuite) TearDownSuite(c *gc.C) {
	s.HTTPSuite.TearDownSuite(c)
}

func (s *NovaNeutronHTTPSSuite) SetUpTest(c *gc.C) {
	s.HTTPSuite.SetUpTest(c)
	s.service.SetupHTTP(s.Mux)
}

func (s *NovaNeutronHTTPSSuite) TearDownTest(c *gc.C) {
	s.HTTPSuite.TearDownTest(c)
}

func (s *NovaNeutronHTTPSSuite) TestHasHTTPSServiceURL(c *gc.C) {
	endpoints := s.service.Endpoints()
	c.Assert(endpoints[0].PublicURL[:8], gc.Equals, "https://")
}

func (s *NovaNeutronHTTPSuite) TestSetServerMetadata(c *gc.C) {
	const serverId = "sr1"

	err := s.service.addServer(nova.ServerDetail{Id: serverId})
	c.Assert(err, gc.IsNil)
	defer s.service.removeServer(serverId)
	var req struct {
		Metadata map[string]string `json:"metadata"`
	}
	req.Metadata = map[string]string{
		"k1": "v1",
		"k2": "v2",
	}
	resp, err := s.jsonRequest("POST", "/servers/"+serverId+"/metadata", req, nil)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)

	server, err := s.service.server(serverId)
	c.Assert(err, gc.IsNil)
	c.Assert(server.Metadata, gc.DeepEquals, req.Metadata)
}
