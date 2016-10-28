package neutron_test

import (
	"fmt"
	"log"

	gc "gopkg.in/check.v1"

	"gopkg.in/goose.v1/client"
	"gopkg.in/goose.v1/identity"
	"gopkg.in/goose.v1/neutron"
	"gopkg.in/goose.v1/testservices"
	"gopkg.in/goose.v1/testservices/hook"
	"gopkg.in/goose.v1/testservices/openstackservice"
)

func registerLocalTests() {
	gc.Suite(&localLiveSuite{})
}

// localLiveSuite runs tests from LiveTests using a fake
// neutron server that runs within the test process itself.
type localLiveSuite struct {
	LiveTests
	openstack             *openstackservice.Openstack
	retryErrorCount       int  // The current retry error count.
	retryErrorCountToSend int  // The number of retry errors to send.
	noMoreIPs             bool // If true, addFloatingIP will return ErrNoMoreFloatingIPs
	ipLimitExceeded       bool // If true, addFloatingIP will return ErrIPLimitExceeded
}

func (s *localLiveSuite) SetUpSuite(c *gc.C) {
	c.Logf("Using identity and neutron service test doubles")

	// Set up an Openstack service.
	s.cred = &identity.Credentials{
		User:       "fred",
		Secrets:    "secret",
		Region:     "some region",
		TenantName: "tenant",
	}
	var logMsg []string
	s.openstack, logMsg = openstackservice.New(s.cred, identity.AuthUserPass, false)
	for _, msg := range logMsg {
		c.Logf(msg)
		fmt.Printf("SetUpSuite(): %s\n", msg)
	}
	s.openstack.UseNeutronNetworking()

	s.openstack.SetupHTTP(nil)
	s.LiveTests.SetUpSuite(c)
}

func (s *localLiveSuite) TearDownSuite(c *gc.C) {
	s.LiveTests.TearDownSuite(c)
	s.openstack.Stop()
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
