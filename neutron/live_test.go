package neutron_test

import (
	//"fmt"
	gc "gopkg.in/check.v1"

	"gopkg.in/goose.v1/client"
	"gopkg.in/goose.v1/identity"
	"gopkg.in/goose.v1/neutron"
)

const (
	// A made up name we use for the test server instance.
	testImageName = "neutron_test_server"
)

func registerOpenStackTests(cred *identity.Credentials) {
	gc.Suite(&LiveTests{
		cred: cred,
	})
}

type LiveTests struct {
	cred     *identity.Credentials
	client   client.AuthenticatingClient
	neutron  *neutron.Client
	userId   string
	tenantId string
}

func (s *LiveTests) SetUpSuite(c *gc.C) {
	s.client = client.NewClient(s.cred, identity.AuthUserPass, nil)
	s.neutron = neutron.New(s.client)
}

func (s *LiveTests) TearDownSuite(c *gc.C) {
	// noop, called by local test suite.
}

func (s *LiveTests) SetUpTest(c *gc.C) {
	// noop, called by local test suite.
}

func (s *LiveTests) TearDownTest(c *gc.C) {
	// noop, called by local test suite.
}

func (s *LiveTests) TestFloatingIPsV2(c *gc.C) {
	networks, err := s.neutron.ListNetworksV2()
	c.Assert(err, gc.IsNil)
	var netId string
	for _, net := range networks {
		if net.External == true {
			netId = net.Id
			break
		}
	}
	if netId == "" {
		c.Errorf("no valid network to create floating IP")
	}
	c.Assert(netId, gc.Not(gc.Equals), "")
	ip, err := s.neutron.AllocateFloatingIPV2(netId)
	c.Assert(err, gc.IsNil)
	c.Assert(ip, gc.Not(gc.IsNil))
	c.Check(ip.IP, gc.Not(gc.Equals), "")
	c.Check(ip.FixedIP, gc.Equals, "")
	c.Check(ip.Id, gc.Not(gc.Equals), "")
	c.Check(ip.FloatingNetworkId, gc.Not(gc.Equals), "")
	ips, err := s.neutron.ListFloatingIPsV2()
	c.Assert(err, gc.IsNil)
	if len(ips) < 1 {
		c.Errorf("no floating IPs found (expected at least 1)")
	} else {
		found := false
		for _, i := range ips {
			c.Check(i.IP, gc.Not(gc.Equals), "")
			if i.Id == ip.Id {
				c.Check(i.IP, gc.Equals, ip.IP)
				c.Check(i.FloatingNetworkId, gc.Equals, ip.FloatingNetworkId)
				found = true
			}
		}
		if !found {
			c.Errorf("expected to find added floating IP: %#v", ip)
		}
		fip, err := s.neutron.GetFloatingIPV2(ip.Id)
		c.Assert(err, gc.IsNil)
		c.Check(fip.Id, gc.Equals, ip.Id)
		c.Check(fip.IP, gc.Equals, ip.IP)
		c.Check(fip.FloatingNetworkId, gc.Equals, ip.FloatingNetworkId)
	}
	err = s.neutron.DeleteFloatingIPV2(ip.Id)
	c.Assert(err, gc.IsNil)
	_, err = s.neutron.GetFloatingIPV2(ip.Id)
	c.Assert(err, gc.Not(gc.IsNil))
}

func (s *LiveTests) TestListNetworksV2(c *gc.C) {
	networks, err := s.neutron.ListNetworksV2()
	c.Assert(err, gc.IsNil)
	for _, network := range networks {
		c.Check(network.Id, gc.Not(gc.Equals), "")
		c.Check(network.Name, gc.Not(gc.Equals), "")
	}
	firstNetwork := networks[0]
	foundNetwork, err := s.neutron.GetNetworkV2(firstNetwork.Id)
	c.Assert(err, gc.IsNil)
	c.Check(foundNetwork.Id, gc.Equals, firstNetwork.Id)
	c.Check(foundNetwork.Name, gc.Equals, firstNetwork.Name)
}

func (s *LiveTests) TestSubnetsV2(c *gc.C) {
	subnets, err := s.neutron.ListSubnetsV2()
	c.Assert(err, gc.IsNil)
	for _, subnet := range subnets {
		c.Check(subnet.Id, gc.Not(gc.Equals), "")
		c.Check(subnet.NetworkId, gc.Not(gc.Equals), "")
		c.Check(subnet.Name, gc.Not(gc.Equals), "")
		c.Assert(subnet.Cidr, gc.Matches, `\d{1,3}(\.+\d{1,3}){3}\/\d+`)
	}
	firstSubnet := subnets[0]
	foundSubnet, err := s.neutron.GetSubnetV2(firstSubnet.Id)
	c.Assert(err, gc.IsNil)
	c.Check(foundSubnet.Id, gc.Equals, firstSubnet.Id)
	c.Check(foundSubnet.NetworkId, gc.Equals, firstSubnet.NetworkId)
	c.Check(foundSubnet.Name, gc.Equals, firstSubnet.Name)
	c.Assert(foundSubnet.Cidr, gc.Matches, `\d{1,3}(\.+\d{1,3}){3}\/\d+`)
}

func (s *LiveTests) TestSecurityGroupsV2(c *gc.C) {
	newSecGrp, err := s.neutron.CreateSecurityGroupV2("SecurityGroupTest", "Testing create security group")
	c.Assert(err, gc.IsNil)
	c.Assert(newSecGrp, gc.Not(gc.IsNil))
	secGrps, err := s.neutron.ListSecurityGroupsV2()
	c.Assert(err, gc.IsNil)
	c.Assert(secGrps, gc.Not(gc.HasLen), 0)
	var found bool
	for _, secGrp := range secGrps {
		c.Check(secGrp.Id, gc.Not(gc.Equals), "")
		c.Check(secGrp.Name, gc.Not(gc.Equals), "")
		c.Check(secGrp.Description, gc.Not(gc.Equals), "")
		c.Check(secGrp.TenantId, gc.Not(gc.Equals), "")
		if secGrp.Id == newSecGrp.Id {
			found = true
		}
	}
	if !found {
		c.Errorf("expected to find added security group %s", newSecGrp)
	}
	updatedSecGroup, err := s.neutron.UpdateSecurityGroupV2(newSecGrp.Id, "NameChanged", "")
	foundSecGrps, err := s.neutron.SecurityGroupByNameV2(updatedSecGroup.Name)
	c.Assert(err, gc.IsNil)
	c.Assert(foundSecGrps, gc.Not(gc.HasLen), 0)
	found = false
	for _, secGrp := range foundSecGrps {
		if secGrp.Id == updatedSecGroup.Id {
			found = true
			break
		}
	}
	if !found {
		c.Errorf("expected to find added security group %s, when requested by name", updatedSecGroup.Name)
	}
	_, err = s.neutron.SecurityGroupByNameV2(newSecGrp.Name)
	c.Assert(err, gc.IsNil)
	err = s.neutron.DeleteSecurityGroupV2(updatedSecGroup.Id)
	c.Assert(err, gc.IsNil)
}

func (s *LiveTests) TestSecurityGroupsRulesV2(c *gc.C) {
	newSecGrp, err := s.neutron.CreateSecurityGroupV2("SecurityGroupTestRules", "Testing create security group")
	c.Assert(err, gc.IsNil)
	defer s.neutron.DeleteSecurityGroupV2(newSecGrp.Id)
	rule := neutron.RuleInfoV2{
		ParentGroupId:  newSecGrp.Id,
		RemoteIPPrefix: "0.0.0.0/0",
		IPProtocol:     "icmp",
		Direction:      "ingress",
		EthernetType:   "IPv4",
	}
	newSecGrpRule, err := s.neutron.CreateSecurityGroupRuleV2(rule)
	c.Assert(err, gc.IsNil)
	c.Assert(newSecGrp.Id, gc.Equals, newSecGrpRule.ParentGroupId)
	c.Assert(*newSecGrpRule.IPProtocol, gc.Equals, rule.IPProtocol)
	c.Assert(newSecGrpRule.Direction, gc.Equals, rule.Direction)

	secGrps, err := s.neutron.SecurityGroupByNameV2(newSecGrp.Name)
	c.Assert(err, gc.IsNil)
	c.Assert(secGrps, gc.Not(gc.HasLen), 0)
	var found bool
	for _, secGrp := range secGrps {
		if secGrp.Id == newSecGrp.Id {
			for _, secGrpRule := range secGrp.Rules {
				if newSecGrpRule.Id == secGrpRule.Id {
					found = true
				}
			}
		}
	}
	if !found {
		c.Errorf("expected to find added security group rule %s", newSecGrpRule.Id)
	}
}
