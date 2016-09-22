package neutron_test

import (
	"log"
	"net/http"
	"net/http/httptest"

	gc "gopkg.in/check.v1"

	"gopkg.in/goose.v1/client"
	"gopkg.in/goose.v1/identity"
	"gopkg.in/goose.v1/testservices"
	"gopkg.in/goose.v1/testservices/hook"
	"gopkg.in/goose.v1/neutron"
	"gopkg.in/goose.v1/testservices/openstackservice"
)

func registerLocalTests() {
        // noop, called by local test suite.
}

// localLiveSuite runs tests from LiveTests using a fake
// neutron server that runs within the test process itself.
type localLiveSuite struct {
	LiveTests
	//useNumericIds bool
	// The following attributes are for using testing doubles.
	Server                *httptest.Server
	Mux                   *http.ServeMux
	oldHandler            http.Handler
	openstack             *openstackservice.Openstack
	retryErrorCount       int  // The current retry error count.
	retryErrorCountToSend int  // The number of retry errors to send.
	noMoreIPs             bool // If true, addFloatingIP will return ErrNoMoreFloatingIPs
	ipLimitExceeded       bool // If true, addFloatingIP will return ErrIPLimitExceeded
	badTokens             int  // If > 0, authHook will set an invalid token in the AccessResponse data.
}

func (s *localLiveSuite) SetUpSuite(c *gc.C) {
	c.Logf("Using identity and neutron service test doubles")

	// Set up the HTTP server.
	s.Server = httptest.NewServer(nil)
	s.oldHandler = s.Server.Config.Handler
	s.Mux = http.NewServeMux()
	s.Server.Config.Handler = s.Mux

	// Set up an Openstack service.
	s.cred = &identity.Credentials{
		URL:        s.Server.URL,
		User:       "fred",
		Secrets:    "secret",
		Region:     "some region",
		TenantName: "tenant",
	}
	s.openstack = openstackservice.New(s.cred, identity.AuthUserPass)
	s.openstack.SetupHTTP(s.Mux)

	s.LiveTests.SetUpSuite(c)
}

func (s *localLiveSuite) TearDownSuite(c *gc.C) {
	s.LiveTests.TearDownSuite(c)
	s.Mux = nil
	s.Server.Config.Handler = s.oldHandler
	s.Server.Close()
}

func (s *localLiveSuite) SetUpTest(c *gc.C) {
	s.retryErrorCount = 0
	s.LiveTests.SetUpTest(c)
}

func (s *localLiveSuite) TearDownTest(c *gc.C) {
	s.LiveTests.TearDownTest(c)
}

// Additional tests to be run against the service double only go here.

func (s *localLiveSuite) retryLimitHook(sc hook.ServiceControl) hook.ControlProcessor {
	return func(sc hook.ServiceControl, args ...interface{}) error {
		sendError := s.retryErrorCount < s.retryErrorCountToSend
		if sendError {
			s.retryErrorCount++
			return testservices.RateLimitExceededError
		}
		return nil
	}
}

func (s *localLiveSuite) setupClient(c *gc.C, logger *log.Logger) *neutron.Client {
	client := client.NewClient(s.cred, identity.AuthUserPass, logger)
	return neutron.New(client)
}

func (s *localLiveSuite) addFloatingIPHook(sc hook.ServiceControl) hook.ControlProcessor {
	return func(sc hook.ServiceControl, args ...interface{}) error {
		if s.noMoreIPs {
			return testservices.NoMoreFloatingIPs
		} else if s.ipLimitExceeded {
			return testservices.IPLimitExceeded
		}
		return nil
	}
}

/*
func (s *localLiveSuite) TestAddFloatingIPErrors(c *gc.C) {
	neutronClient := s.setupClient(c, nil)
	fips, err := neutronClient.ListFloatingIPsV2()
	c.Assert(err, gc.IsNil)
	c.Assert(fips, gc.HasLen, 0)
	//cleanup := s.openstack.Neutron.RegisterControlPoint("addFloatingIP", s.addFloatingIPHook(s.openstack.Neutron))
	//defer cleanup()
	s.noMoreIPs = true
	fip, err := neutronClient.AllocateFloatingIPV2()
	c.Assert(err, gc.ErrorMatches, "(.|\n)*Zero floating ips available.*")
	c.Assert(fip, gc.IsNil)
	s.noMoreIPs = false
	s.ipLimitExceeded = true
	fip, err = neutronClient.AllocateFloatingIPV2()
	c.Assert(err, gc.ErrorMatches, "(.|\n)*Maximum number of floating ips exceeded.*")
	c.Assert(fip, gc.IsNil)
	s.ipLimitExceeded = false
	fip, err = neutronClient.AllocateFloatingIPV2()
	c.Assert(err, gc.IsNil)
	c.Assert(fip.IP, gc.Not(gc.Equals), "")
}
*/