// Nova double testing service - internal direct API tests

package neutronservice

import (
	"fmt"

	gc "gopkg.in/check.v1"

	"gopkg.in/goose.v1/neutron"
	//"gopkg.in/goose.v1/nova"
	//"gopkg.in/goose.v1/testservices/hook"
)

type NeutronSuite struct {
	service *Neutron
}

const (
	versionPath = "v2.0"
	hostname    = "http://example.com"
	region      = "region"
)

var _ = gc.Suite(&NeutronSuite{})

func (s *NeutronSuite) SetUpSuite(c *gc.C) {
	s.service = New(hostname, versionPath, "tenant", region, nil, nil)
}

func (s *NeutronSuite) ensureNoGroup(c *gc.C, group neutron.SecurityGroupV2) {
	_, err := s.service.securityGroup(group.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: Security Group %s does not exist", group.Id))
}

func (s *NeutronSuite) ensureNoRule(c *gc.C, rule neutron.SecurityGroupRuleV2) {
	_, err := s.service.securityGroupRule(rule.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: No such security group rule %s", rule.Id))
}

func (s *NeutronSuite) ensureNoIP(c *gc.C, ip neutron.FloatingIPV2) {
	_, err := s.service.floatingIP(ip.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: No such floating IP %q", ip.Id))
}

func (s *NeutronSuite) createGroup(c *gc.C, group neutron.SecurityGroupV2) {
	s.ensureNoGroup(c, group)
	err := s.service.addSecurityGroup(group)
	c.Assert(err, gc.IsNil)
}

func (s *NeutronSuite) createIP(c *gc.C, ip neutron.FloatingIPV2) {
	s.ensureNoIP(c, ip)
	err := s.service.addFloatingIP(ip)
	c.Assert(err, gc.IsNil)
}

func (s *NeutronSuite) deleteGroup(c *gc.C, group neutron.SecurityGroupV2) {
	err := s.service.removeSecurityGroup(group.Id)
	c.Assert(err, gc.IsNil)
	s.ensureNoGroup(c, group)
}

func (s *NeutronSuite) deleteRule(c *gc.C, rule neutron.SecurityGroupRuleV2) {
	err := s.service.removeSecurityGroupRule(rule.Id)
	c.Assert(err, gc.IsNil)
	s.ensureNoRule(c, rule)
}

func (s *NeutronSuite) deleteIP(c *gc.C, ip neutron.FloatingIPV2) {
	err := s.service.removeFloatingIP(ip.Id)
	c.Assert(err, gc.IsNil)
	s.ensureNoIP(c, ip)
}

func (s *NeutronSuite) TestAddRemoveSecurityGroup(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createGroup(c, group)
	s.deleteGroup(c, group)
}

func (s *NeutronSuite) TestRemoveSecurityGroupTwiceFails(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1", Name: "test"}
	s.createGroup(c, group)
	s.deleteGroup(c, group)
	err := s.service.removeSecurityGroup(group.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: Security Group 1 does not exist")
}

func (s *NeutronSuite) TestAllSecurityGroups(c *gc.C) {
	groups := s.service.allSecurityGroups()
	// There is always a default security group.
	c.Assert(groups, gc.HasLen, 1)
	groups = []neutron.SecurityGroupV2{
		{
			Id:       "1",
			Name:     "one",
			TenantId: s.service.TenantId,
			Rules:    []neutron.SecurityGroupRuleV2{},
		},
		{
			Id:       "2",
			Name:     "two",
			TenantId: s.service.TenantId,
			Rules:    []neutron.SecurityGroupRuleV2{},
		},
	}
	s.createGroup(c, groups[0])
	defer s.deleteGroup(c, groups[0])
	s.createGroup(c, groups[1])
	defer s.deleteGroup(c, groups[1])
	gr := s.service.allSecurityGroups()
	c.Assert(gr, gc.HasLen, len(groups)+1)
	checkGroupsInList(c, groups, gr)
}

func (s *NeutronSuite) TestGetSecurityGroup(c *gc.C) {
	group := neutron.SecurityGroupV2{
		Id:          "42",
		TenantId:    s.service.TenantId,
		Name:        "group",
		Description: "desc",
		Rules:       []neutron.SecurityGroupRuleV2{},
	}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	gr, _ := s.service.securityGroup(group.Id)
	c.Assert(*gr, gc.DeepEquals, group)
}

func (s *NeutronSuite) TestGetSecurityGroupByName(c *gc.C) {
	group := neutron.SecurityGroupV2{
		Id:       "1",
		Name:     "test",
		TenantId: s.service.TenantId,
		Rules:    []neutron.SecurityGroupRuleV2{},
	}
	s.ensureNoGroup(c, group)
	gr, err := s.service.securityGroupByName(group.Name)
	c.Assert(err, gc.ErrorMatches, `itemNotFound: Security Group test does not exist`)
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	gr, err = s.service.securityGroupByName(group.Name)
	c.Assert(err, gc.IsNil)
	c.Assert(*gr, gc.DeepEquals, group)
}

func (s *NeutronSuite) TestAddHasRemoveSecurityGroupRule(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	ri := neutron.RuleInfoV2{ParentGroupId: group.Id, Direction: "egress"}
	//ri := neutron.RuleInfoV2{ParentGroupId: group.Id, GroupId: &group.Id}
	rule := neutron.SecurityGroupRuleV2{Id: "10", ParentGroupId: group.Id}
	s.ensureNoGroup(c, group)
	s.ensureNoRule(c, rule)
	ok := s.service.hasSecurityGroupRule(group.Id, rule.Id)
	c.Assert(ok, gc.Equals, false)
	s.createGroup(c, group)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)
	ok = s.service.hasSecurityGroupRule(group.Id, rule.Id)
	c.Assert(ok, gc.Equals, true)
	s.deleteGroup(c, group)
	ok = s.service.hasSecurityGroupRule("-1", rule.Id)
	c.Assert(ok, gc.Equals, true)
	ok = s.service.hasSecurityGroupRule(group.Id, rule.Id)
	c.Assert(ok, gc.Equals, false)
	s.deleteRule(c, rule)
	ok = s.service.hasSecurityGroupRule("-1", rule.Id)
	c.Assert(ok, gc.Equals, false)
}

func (s *NeutronSuite) TestAddGetIngressSecurityGroupRule(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ri := neutron.RuleInfoV2{
		Direction:     "ingress",
		PortRangeMax:  1234,
		PortRangeMin:  4321,
		IPProtocol:    "tcp",
		ParentGroupId: group.Id,
	}
	rule := neutron.SecurityGroupRuleV2{
		Id:            "10",
		Direction:     "ingress",
		ParentGroupId: group.Id,
		PortRangeMax:  &ri.PortRangeMax,
		PortRangeMin:  &ri.PortRangeMin,
		IPProtocol:    &ri.IPProtocol,
	}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)
	defer s.deleteRule(c, rule)
	ru, err := s.service.securityGroupRule(rule.Id)
	c.Assert(err, gc.IsNil)
	c.Assert(ru.Id, gc.Equals, rule.Id)
	c.Assert(ru.Direction, gc.Equals, rule.Direction)
	c.Assert(ru.ParentGroupId, gc.Equals, rule.ParentGroupId)
	c.Assert(*ru.PortRangeMax, gc.Equals, *rule.PortRangeMax)
	c.Assert(*ru.PortRangeMin, gc.Equals, *rule.PortRangeMin)
	c.Assert(*ru.IPProtocol, gc.Equals, *rule.IPProtocol)
}

func (s *NeutronSuite) TestAddGetGroupSecurityGroupRule(c *gc.C) {
	srcGroup := neutron.SecurityGroupV2{Id: "1", Name: "source", TenantId: s.service.TenantId}
	tgtGroup := neutron.SecurityGroupV2{Id: "2", Name: "target"}
	s.createGroup(c, srcGroup)
	defer s.deleteGroup(c, srcGroup)
	s.createGroup(c, tgtGroup)
	defer s.deleteGroup(c, tgtGroup)
	ri := neutron.RuleInfoV2{
		Direction:     "ingress",
		PortRangeMax:  1234,
		PortRangeMin:  4321,
		IPProtocol:    "tcp",
		ParentGroupId: tgtGroup.Id,
	}
	rule := neutron.SecurityGroupRuleV2{
		Id:            "10",
		Direction:     "ingress",
		ParentGroupId: tgtGroup.Id,
		PortRangeMax:  &ri.PortRangeMax,
		PortRangeMin:  &ri.PortRangeMin,
		IPProtocol:    &ri.IPProtocol,
	}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)
	defer s.deleteRule(c, rule)
	ru, err := s.service.securityGroupRule(rule.Id)
	c.Assert(err, gc.IsNil)
	c.Assert(ru.Id, gc.Equals, rule.Id)
	c.Assert(ru.ParentGroupId, gc.Equals, rule.ParentGroupId)
	c.Assert(*ru.PortRangeMax, gc.Equals, *rule.PortRangeMax)
	c.Assert(*ru.PortRangeMin, gc.Equals, *rule.PortRangeMin)
	c.Assert(*ru.IPProtocol, gc.Equals, *rule.IPProtocol)
	c.Assert(ru.Direction, gc.Equals, rule.Direction)
}

/* Valid Test?
func (s *NeutronSuite) TestAddSecurityGroupRuleTwiceFails(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ri := neutron.RuleInfoV2{ParentGroupId: group.Id, Direction: "egress"}
	rule := neutron.SecurityGroupRuleV2{Id: "10"}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)
	defer s.deleteRule(c, rule)
	err = s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.ErrorMatches, "conflictingRequest: A security group rule with id 10 already exists")
}

func (s *NeutronSuite) TestAddSecurityGroupRuleToParentTwiceFails(c *gc.C) {
	group := neutron.SecurityGroupV2{
		Id: "1",
		Name: "TestAddSecurityGroupRuleToParentTwiceFails"
	}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ri := neutron.RuleInfoV2{ParentGroupId: group.Id}
	rule := neutron.SecurityGroupRuleV2{Id: "10"}
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)

	err = s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.ErrorMatches, "conflictingRequest: Cannot add twice rule 10 to security group 1")
}
*/

func (s *NeutronSuite) TestAddSecurityGroupRuleWithInvalidParentFails(c *gc.C) {
	invalidGroup := neutron.SecurityGroupV2{Id: "1"}
	s.ensureNoGroup(c, invalidGroup)
	ri := neutron.RuleInfoV2{ParentGroupId: invalidGroup.Id, Direction: "egress"}
	rule := neutron.SecurityGroupRuleV2{Id: "10", Direction: "egress"}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: Security Group 1 does not exist")
}

func (s *NeutronSuite) TestAddGroupSecurityGroupRuleWithInvalidSourceFails(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	invalidDirection := "42"
	ri := neutron.RuleInfoV2{
		ParentGroupId: group.Id,
		Direction:     invalidDirection,
	}
	rule := neutron.SecurityGroupRuleV2{Id: "10"}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.ErrorMatches, "conflictingRequest: Unknown security group direction 42")
}

func (s *NeutronSuite) TestAddSecurityGroupRuleUpdatesParent(c *gc.C) {
	group := neutron.SecurityGroupV2{
		Id:       "1",
		Name:     "test",
		TenantId: s.service.TenantId,
	}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ri := neutron.RuleInfoV2{ParentGroupId: group.Id, Direction: "egress"}
	rule := neutron.SecurityGroupRuleV2{
		Id:            "10",
		ParentGroupId: group.Id,
		Direction:     "egress",
		TenantId:      s.service.TenantId,
	}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)
	defer s.deleteRule(c, rule)
	group.Rules = []neutron.SecurityGroupRuleV2{rule}
	gr, err := s.service.securityGroup(group.Id)
	c.Assert(err, gc.IsNil)
	c.Assert(*gr, gc.DeepEquals, group)
}

func (s *NeutronSuite) TestAddSecurityGroupRuleKeepsNegativePort(c *gc.C) {
	group := neutron.SecurityGroupV2{
		Id:       "1",
		Name:     "test",
		TenantId: s.service.TenantId,
	}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ri := neutron.RuleInfoV2{
		IPProtocol:    "icmp",
		PortRangeMax:  -1,
		PortRangeMin:  -1,
		ParentGroupId: group.Id,
		Direction:     "ingress",
	}
	rule := neutron.SecurityGroupRuleV2{
		Id:            "10",
		ParentGroupId: group.Id,
		PortRangeMax:  &ri.PortRangeMax,
		PortRangeMin:  &ri.PortRangeMin,
		IPProtocol:    &ri.IPProtocol,
		Direction:     "ingress",
		TenantId:      s.service.TenantId,
	}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)
	defer s.deleteRule(c, rule)
	returnedGroup, err := s.service.securityGroup(group.Id)
	c.Assert(err, gc.IsNil)
	c.Assert(returnedGroup.Rules, gc.DeepEquals, []neutron.SecurityGroupRuleV2{rule})
}

/*
func (s *NeutronSuite) TestRemoveSecurityGroupRuleTwiceFails(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ri := neutron.RuleInfoV2{ParentGroupId: group.Id, Direction:}
	//ri := neutron.RuleInfoV2{ParentGroupId: group.Id, GroupId: &group.Id}
	rule := neutron.SecurityGroupRuleV2{Id: "10"}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)
	s.deleteRule(c, rule)
	err = s.service.removeSecurityGroupRule(rule.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such security group rule 10")
}
*/

func (s *NeutronSuite) TestAddHasRemoveFloatingIP(c *gc.C) {
	ip := neutron.FloatingIPV2{Id: "1", IP: "1.2.3.4"}
	s.ensureNoIP(c, ip)
	ok := s.service.hasFloatingIP(ip.IP)
	c.Assert(ok, gc.Equals, false)
	s.createIP(c, ip)
	ok = s.service.hasFloatingIP("invalid IP")
	c.Assert(ok, gc.Equals, false)
	ok = s.service.hasFloatingIP(ip.IP)
	c.Assert(ok, gc.Equals, true)
	s.deleteIP(c, ip)
	ok = s.service.hasFloatingIP(ip.IP)
	c.Assert(ok, gc.Equals, false)
}

func (s *NeutronSuite) TestAddFloatingIPTwiceFails(c *gc.C) {
	ip := neutron.FloatingIPV2{Id: "1"}
	s.createIP(c, ip)
	defer s.deleteIP(c, ip)
	err := s.service.addFloatingIP(ip)
	c.Assert(err, gc.ErrorMatches, "conflictingRequest: A floating IP with id 1 already exists")
}

func (s *NeutronSuite) TestRemoveFloatingIPTwiceFails(c *gc.C) {
	ip := neutron.FloatingIPV2{Id: "1"}
	s.createIP(c, ip)
	s.deleteIP(c, ip)
	err := s.service.removeFloatingIP(ip.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such floating IP \"1\"")
}

func (s *NeutronSuite) TestAllFloatingIPs(c *gc.C) {
	fips := s.service.allFloatingIPs()
	c.Assert(fips, gc.HasLen, 0)
	fips = []neutron.FloatingIPV2{
		{Id: "1"},
		{Id: "2"},
	}
	s.createIP(c, fips[0])
	defer s.deleteIP(c, fips[0])
	s.createIP(c, fips[1])
	defer s.deleteIP(c, fips[1])
	ips := s.service.allFloatingIPs()
	c.Assert(ips, gc.HasLen, len(fips))
	if ips[0].Id != fips[0].Id {
		ips[0], ips[1] = ips[1], ips[0]
	}
	c.Assert(ips, gc.DeepEquals, fips)
}

func (s *NeutronSuite) TestGetFloatingIP(c *gc.C) {
	//inst := "sr1"
	//fixedIP := "4.3.2.1"
	fip := neutron.FloatingIPV2{
		Id:                "1",
		IP:                "1.2.3.4",
		FloatingNetworkId: "sr1",
		FixedIP:           "4.3.2.1",
	}
	s.createIP(c, fip)
	defer s.deleteIP(c, fip)
	ip, _ := s.service.floatingIP(fip.Id)
	c.Assert(*ip, gc.DeepEquals, fip)
}

func (s *NeutronSuite) TestGetFloatingIPByAddr(c *gc.C) {
	fip := neutron.FloatingIPV2{Id: "1", IP: "1.2.3.4"}
	s.ensureNoIP(c, fip)
	ip, err := s.service.floatingIPByAddr(fip.IP)
	c.Assert(err, gc.NotNil)
	s.createIP(c, fip)
	defer s.deleteIP(c, fip)
	ip, err = s.service.floatingIPByAddr(fip.IP)
	c.Assert(err, gc.IsNil)
	c.Assert(*ip, gc.DeepEquals, fip)
	_, err = s.service.floatingIPByAddr("invalid")
	c.Assert(err, gc.ErrorMatches, `itemNotFound: No such floating IP "invalid"`)
}