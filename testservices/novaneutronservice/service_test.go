// Nova double testing service - internal direct API tests

package novaneutronservice

import (
	"fmt"

	gc "gopkg.in/check.v1"

	"gopkg.in/goose.v1/neutron"
	"gopkg.in/goose.v1/nova"
	"gopkg.in/goose.v1/testservices/hook"
)

type NovaNeutronSuite struct {
	service *NovaNeutron
}

const (
	versionPath = "v2"
	hostname    = "http://example.com"
	region      = "region"
)

var _ = gc.Suite(&NovaNeutronSuite{})

func (s *NovaNeutronSuite) SetUpSuite(c *gc.C) {
	fmt.Printf("NovaNeutronSuite.SetUpSuite() called\n")
	s.service = New(hostname, versionPath, "tenant", region, nil, nil)
}

func (s *NovaNeutronSuite) ensureNoFlavor(c *gc.C, flavor nova.FlavorDetail) {
	_, err := s.service.flavor(flavor.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: No such flavor %q", flavor.Id))
}

func (s *NovaNeutronSuite) ensureNoServer(c *gc.C, server nova.ServerDetail) {
	_, err := s.service.server(server.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: No such server %q", server.Id))
}

func (s *NovaNeutronSuite) ensureNoGroup(c *gc.C, group neutron.SecurityGroupV2) {
	_, err := s.service.securityGroup(group.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: No such security group %s", group.Id))
}

func (s *NovaNeutronSuite) ensureNoRule(c *gc.C, rule neutron.SecurityGroupRuleV2) {
	_, err := s.service.securityGroupRule(rule.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: No such security group rule %s", rule.Id))
}

func (s *NovaNeutronSuite) ensureNoIP(c *gc.C, ip neutron.FloatingIPV2) {
	_, err := s.service.floatingIP(ip.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: No such floating IP %q", ip.Id))
}

func (s *NovaNeutronSuite) ensureNoNetwork(c *gc.C, network neutron.NetworkV2) {
	_, err := s.service.network(network.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: No such network %q", network.Id))
}

func (s *NovaNeutronSuite) ensureNoSubnet(c *gc.C, subnet neutron.SubnetV2) {
	_, err := s.service.subnet(subnet.Id)
	c.Assert(err, gc.ErrorMatches, fmt.Sprintf("itemNotFound: No such subnet %q", subnet.Id))
}

func (s *NovaNeutronSuite) createFlavor(c *gc.C, flavor nova.FlavorDetail) {
	s.ensureNoFlavor(c, flavor)
	err := s.service.addFlavor(flavor)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) createServer(c *gc.C, server nova.ServerDetail) {
	s.ensureNoServer(c, server)
	err := s.service.addServer(server)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) createGroup(c *gc.C, group neutron.SecurityGroupV2) {
	s.ensureNoGroup(c, group)
	err := s.service.addSecurityGroup(group)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) createIP(c *gc.C, ip neutron.FloatingIPV2) {
	s.ensureNoIP(c, ip)
	err := s.service.addFloatingIP(ip)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) deleteFlavor(c *gc.C, flavor nova.FlavorDetail) {
	err := s.service.removeFlavor(flavor.Id)
	c.Assert(err, gc.IsNil)
	s.ensureNoFlavor(c, flavor)
}

func (s *NovaNeutronSuite) deleteServer(c *gc.C, server nova.ServerDetail) {
	err := s.service.removeServer(server.Id)
	c.Assert(err, gc.IsNil)
	s.ensureNoServer(c, server)
}

func (s *NovaNeutronSuite) deleteGroup(c *gc.C, group neutron.SecurityGroupV2) {
	err := s.service.removeSecurityGroup(group.Id)
	c.Assert(err, gc.IsNil)
	s.ensureNoGroup(c, group)
}

func (s *NovaNeutronSuite) deleteRule(c *gc.C, rule neutron.SecurityGroupRuleV2) {
	err := s.service.removeSecurityGroupRule(rule.Id)
	c.Assert(err, gc.IsNil)
	s.ensureNoRule(c, rule)
}

func (s *NovaNeutronSuite) deleteIP(c *gc.C, ip neutron.FloatingIPV2) {
	err := s.service.removeFloatingIP(ip.Id)
	c.Assert(err, gc.IsNil)
	s.ensureNoIP(c, ip)
}

func (s *NovaNeutronSuite) TestAddRemoveFlavor(c *gc.C) {
	flavor := nova.FlavorDetail{Id: "test"}
	s.createFlavor(c, flavor)
	s.deleteFlavor(c, flavor)
}

func (s *NovaNeutronSuite) TestBuildLinksAndAddFlavor(c *gc.C) {
	flavor := nova.FlavorDetail{Id: "test"}
	s.service.buildFlavorLinks(&flavor)
	s.createFlavor(c, flavor)
	defer s.deleteFlavor(c, flavor)
	fl, _ := s.service.flavor(flavor.Id)
	url := "/flavors/" + flavor.Id
	links := []nova.Link{
		{Href: s.service.endpointURL(true, url), Rel: "self"},
		{Href: s.service.endpointURL(false, url), Rel: "bookmark"},
	}
	c.Assert(fl.Links, gc.DeepEquals, links)
}

func (s *NovaNeutronSuite) TestAddFlavorWithLinks(c *gc.C) {
	flavor := nova.FlavorDetail{
		Id: "test",
		Links: []nova.Link{
			{Href: "href", Rel: "rel"},
		},
	}
	s.createFlavor(c, flavor)
	defer s.deleteFlavor(c, flavor)
	fl, _ := s.service.flavor(flavor.Id)
	c.Assert(*fl, gc.DeepEquals, flavor)
}

func (s *NovaNeutronSuite) TestAddFlavorTwiceFails(c *gc.C) {
	flavor := nova.FlavorDetail{Id: "test"}
	s.createFlavor(c, flavor)
	defer s.deleteFlavor(c, flavor)
	err := s.service.addFlavor(flavor)
	c.Assert(err, gc.ErrorMatches, `conflictingRequest: A flavor with id "test" already exists`)
}

func (s *NovaNeutronSuite) TestRemoveFlavorTwiceFails(c *gc.C) {
	flavor := nova.FlavorDetail{Id: "test"}
	s.createFlavor(c, flavor)
	s.deleteFlavor(c, flavor)
	err := s.service.removeFlavor(flavor.Id)
	c.Assert(err, gc.ErrorMatches, `itemNotFound: No such flavor "test"`)
}

func (s *NovaNeutronSuite) TestAllFlavors(c *gc.C) {
	// The test service has 2 default flavours.
	flavors := s.service.allFlavors()
	c.Assert(flavors, gc.HasLen, 3)
	for _, fl := range flavors {
		c.Assert(fl.Name == "m1.tiny" || fl.Name == "m1.small" || fl.Name == "m1.medium", gc.Equals, true)
	}
}

func (s *NovaNeutronSuite) TestAllFlavorsAsEntities(c *gc.C) {
	// The test service has 2 default flavours.
	entities := s.service.allFlavorsAsEntities()
	c.Assert(entities, gc.HasLen, 3)
	for _, fl := range entities {
		c.Assert(fl.Name == "m1.tiny" || fl.Name == "m1.small" || fl.Name == "m1.medium", gc.Equals, true)
	}
}

func (s *NovaNeutronSuite) TestGetFlavor(c *gc.C) {
	flavor := nova.FlavorDetail{
		Id:    "test",
		Name:  "flavor",
		RAM:   128,
		VCPUs: 2,
		Disk:  123,
	}
	s.createFlavor(c, flavor)
	defer s.deleteFlavor(c, flavor)
	fl, _ := s.service.flavor(flavor.Id)
	c.Assert(*fl, gc.DeepEquals, flavor)
}

func (s *NovaNeutronSuite) TestGetFlavorAsEntity(c *gc.C) {
	entity := nova.Entity{
		Id:   "test",
		Name: "flavor",
	}
	flavor := nova.FlavorDetail{
		Id:   entity.Id,
		Name: entity.Name,
	}
	s.createFlavor(c, flavor)
	defer s.deleteFlavor(c, flavor)
	ent, _ := s.service.flavorAsEntity(flavor.Id)
	c.Assert(*ent, gc.DeepEquals, entity)
}

func (s *NovaNeutronSuite) TestAddRemoveServer(c *gc.C) {
	server := nova.ServerDetail{Id: "test"}
	s.createServer(c, server)
	s.deleteServer(c, server)
}

func (s *NovaNeutronSuite) TestBuildLinksAndAddServer(c *gc.C) {
	server := nova.ServerDetail{Id: "test"}
	s.service.buildServerLinks(&server)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	sr, _ := s.service.server(server.Id)
	url := "/servers/" + server.Id
	links := []nova.Link{
		{Href: s.service.endpointURL(true, url), Rel: "self"},
		{Href: s.service.endpointURL(false, url), Rel: "bookmark"},
	}
	c.Assert(sr.Links, gc.DeepEquals, links)
}

func (s *NovaNeutronSuite) TestAddServerWithLinks(c *gc.C) {
	server := nova.ServerDetail{
		Id: "test",
		Links: []nova.Link{
			{Href: "href", Rel: "rel"},
		},
	}
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	sr, _ := s.service.server(server.Id)
	c.Assert(*sr, gc.DeepEquals, server)
}

func (s *NovaNeutronSuite) TestAddServerTwiceFails(c *gc.C) {
	server := nova.ServerDetail{Id: "test"}
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	err := s.service.addServer(server)
	c.Assert(err, gc.ErrorMatches, `conflictingRequest: A server with id "test" already exists`)
}

// A control point can be used to change the status of the added server.
func (s *NovaNeutronSuite) TestAddServerControlPoint(c *gc.C) {
	cleanup := s.service.RegisterControlPoint(
		"addServer",
		func(sc hook.ServiceControl, args ...interface{}) error {
			details := args[0].(*nova.ServerDetail)
			details.Status = nova.StatusBuildSpawning
			return nil
		},
	)
	defer cleanup()

	server := &nova.ServerDetail{
		Id:     "test",
		Status: nova.StatusActive,
	}
	s.createServer(c, *server)
	defer s.deleteServer(c, *server)

	server, _ = s.service.server(server.Id)
	c.Assert(server.Status, gc.Equals, nova.StatusBuildSpawning)
}

func (s *NovaNeutronSuite) TestRemoveServerTwiceFails(c *gc.C) {
	server := nova.ServerDetail{Id: "test"}
	s.createServer(c, server)
	s.deleteServer(c, server)
	err := s.service.removeServer(server.Id)
	c.Assert(err, gc.ErrorMatches, `itemNotFound: No such server "test"`)
}

func (s *NovaNeutronSuite) TestAllServers(c *gc.C) {
	servers, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(servers, gc.HasLen, 0)
	servers = []nova.ServerDetail{
		{Id: "sr1"},
		{Id: "sr2"},
	}
	s.createServer(c, servers[0])
	defer s.deleteServer(c, servers[1])
	s.createServer(c, servers[1])
	defer s.deleteServer(c, servers[0])
	sr, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, len(servers))
	if sr[0].Id != servers[0].Id {
		sr[0], sr[1] = sr[1], sr[0]
	}
	c.Assert(sr, gc.DeepEquals, servers)
}

func (s *NovaNeutronSuite) TestAllServersWithFilters(c *gc.C) {
	servers, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(servers, gc.HasLen, 0)
	servers = []nova.ServerDetail{
		{Id: "sr1", Name: "test", Status: nova.StatusActive},
		{Id: "sr2", Name: "other", Status: nova.StatusBuild},
		{Id: "sr3", Name: "foo", Status: nova.StatusRescue},
	}
	for _, server := range servers {
		s.createServer(c, server)
		defer s.deleteServer(c, server)
	}
	f := filter{
		nova.FilterStatus: nova.StatusRescue,
	}
	sr, err := s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 1)
	c.Assert(sr[0], gc.DeepEquals, servers[2])
	f[nova.FilterStatus] = nova.StatusBuild
	sr, err = s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 1)
	c.Assert(sr[0], gc.DeepEquals, servers[1])
	f = filter{
		nova.FilterServer: "test",
	}
	sr, err = s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 1)
	c.Assert(sr[0], gc.DeepEquals, servers[0])
	f[nova.FilterServer] = "other"
	sr, err = s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 1)
	c.Assert(sr[0], gc.DeepEquals, servers[1])
	f[nova.FilterServer] = "foo"
	f[nova.FilterStatus] = nova.StatusRescue
	sr, err = s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 1)
	c.Assert(sr[0], gc.DeepEquals, servers[2])
}

func (s *NovaNeutronSuite) TestAllServersWithEmptyFilter(c *gc.C) {
	servers, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(servers, gc.HasLen, 0)
	servers = []nova.ServerDetail{
		{Id: "sr1", Name: "srv1"},
		{Id: "sr2", Name: "srv2"},
	}
	for _, server := range servers {
		s.createServer(c, server)
		defer s.deleteServer(c, server)
	}
	sr, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 2)
	if sr[0].Id != servers[0].Id {
		sr[0], sr[1] = sr[1], sr[0]
	}
	c.Assert(sr, gc.DeepEquals, servers)
}

func (s *NovaNeutronSuite) TestAllServersWithRegexFilters(c *gc.C) {
	servers, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(servers, gc.HasLen, 0)
	servers = []nova.ServerDetail{
		{Id: "sr1", Name: "foobarbaz"},
		{Id: "sr2", Name: "foo123baz"},
		{Id: "sr3", Name: "123barbaz"},
		{Id: "sr4", Name: "foobar123"},
	}
	for _, server := range servers {
		s.createServer(c, server)
		defer s.deleteServer(c, server)
	}
	f := filter{
		nova.FilterServer: `foo.*baz`,
	}
	sr, err := s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 2)
	if sr[0].Id != servers[0].Id {
		sr[0], sr[1] = sr[1], sr[0]
	}
	c.Assert(sr, gc.DeepEquals, servers[:2])
	f[nova.FilterServer] = `^[a-z]+[0-9]+`
	sr, err = s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 2)
	if sr[0].Id != servers[1].Id {
		sr[0], sr[1] = sr[1], sr[0]
	}
	c.Assert(sr[0], gc.DeepEquals, servers[1])
	c.Assert(sr[1], gc.DeepEquals, servers[3])
}

func (s *NovaNeutronSuite) TestAllServersWithMultipleFilters(c *gc.C) {
	servers, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(servers, gc.HasLen, 0)
	servers = []nova.ServerDetail{
		{Id: "sr1", Name: "s1", Status: nova.StatusActive},
		{Id: "sr2", Name: "s2", Status: nova.StatusActive},
		{Id: "sr3", Name: "s3", Status: nova.StatusActive},
	}
	for _, server := range servers {
		s.createServer(c, server)
		defer s.deleteServer(c, server)
	}
	f := filter{
		nova.FilterStatus: nova.StatusActive,
		nova.FilterServer: `.*2.*`,
	}
	sr, err := s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 1)
	c.Assert(sr[0], gc.DeepEquals, servers[1])
	f[nova.FilterStatus] = nova.StatusBuild
	sr, err = s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 0)
	f[nova.FilterStatus] = nova.StatusPassword
	f[nova.FilterServer] = `.*[23].*`
	sr, err = s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 0)
	f[nova.FilterStatus] = nova.StatusActive
	sr, err = s.service.allServers(f)
	c.Assert(err, gc.IsNil)
	c.Assert(sr, gc.HasLen, 2)
	if sr[0].Id != servers[1].Id {
		sr[0], sr[1] = sr[1], sr[0]
	}
	c.Assert(sr, gc.DeepEquals, servers[1:])
}

func (s *NovaNeutronSuite) TestAllServersAsEntities(c *gc.C) {
	entities, err := s.service.allServersAsEntities(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(entities, gc.HasLen, 0)
	entities = []nova.Entity{
		{Id: "sr1"},
		{Id: "sr2"},
	}
	servers := []nova.ServerDetail{
		{Id: entities[0].Id},
		{Id: entities[1].Id},
	}
	s.createServer(c, servers[0])
	defer s.deleteServer(c, servers[0])
	s.createServer(c, servers[1])
	defer s.deleteServer(c, servers[1])
	ent, err := s.service.allServersAsEntities(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(ent, gc.HasLen, len(entities))
	if ent[0].Id != entities[0].Id {
		ent[0], ent[1] = ent[1], ent[0]
	}
	c.Assert(ent, gc.DeepEquals, entities)
}

func (s *NovaNeutronSuite) TestAllServersAsEntitiesWithFilters(c *gc.C) {
	servers, err := s.service.allServers(nil)
	c.Assert(err, gc.IsNil)
	c.Assert(servers, gc.HasLen, 0)
	servers = []nova.ServerDetail{
		{Id: "sr1", Name: "test", Status: nova.StatusActive},
		{Id: "sr2", Name: "other", Status: nova.StatusBuild},
		{Id: "sr3", Name: "foo", Status: nova.StatusRescue},
	}
	entities := []nova.Entity{}
	for _, server := range servers {
		s.createServer(c, server)
		defer s.deleteServer(c, server)
		entities = append(entities, nova.Entity{
			Id:    server.Id,
			Name:  server.Name,
			Links: server.Links,
		})
	}
	f := filter{
		nova.FilterStatus: nova.StatusRescue,
	}
	ent, err := s.service.allServersAsEntities(f)
	c.Assert(err, gc.IsNil)
	c.Assert(ent, gc.HasLen, 1)
	c.Assert(ent[0], gc.DeepEquals, entities[2])
	f[nova.FilterStatus] = nova.StatusBuild
	ent, err = s.service.allServersAsEntities(f)
	c.Assert(err, gc.IsNil)
	c.Assert(ent, gc.HasLen, 1)
	c.Assert(ent[0], gc.DeepEquals, entities[1])
	f = filter{
		nova.FilterServer: "test",
	}
	ent, err = s.service.allServersAsEntities(f)
	c.Assert(err, gc.IsNil)
	c.Assert(ent, gc.HasLen, 1)
	c.Assert(ent[0], gc.DeepEquals, entities[0])
	f[nova.FilterServer] = "other"
	ent, err = s.service.allServersAsEntities(f)
	c.Assert(err, gc.IsNil)
	c.Assert(ent, gc.HasLen, 1)
	c.Assert(ent[0], gc.DeepEquals, entities[1])
	f[nova.FilterServer] = "foo"
	f[nova.FilterStatus] = nova.StatusRescue
	ent, err = s.service.allServersAsEntities(f)
	c.Assert(err, gc.IsNil)
	c.Assert(ent, gc.HasLen, 1)
	c.Assert(ent[0], gc.DeepEquals, entities[2])
}

func (s *NovaNeutronSuite) TestGetServer(c *gc.C) {
	server := nova.ServerDetail{
		Id:          "test",
		Name:        "server",
		AddressIPv4: "1.2.3.4",
		AddressIPv6: "1::fff",
		Created:     "1/1/1",
		Flavor:      nova.Entity{Id: "fl1", Name: "flavor1"},
		Image:       nova.Entity{Id: "im1", Name: "image1"},
		HostId:      "myhost",
		Progress:    123,
		Status:      "st",
		TenantId:    "tenant",
		Updated:     "2/3/4",
		UserId:      "user",
	}
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	sr, _ := s.service.server(server.Id)
	c.Assert(*sr, gc.DeepEquals, server)
}

func (s *NovaNeutronSuite) TestGetServerAsEntity(c *gc.C) {
	entity := nova.Entity{
		Id:   "test",
		Name: "server",
	}
	server := nova.ServerDetail{
		Id:   entity.Id,
		Name: entity.Name,
	}
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	ent, _ := s.service.serverAsEntity(server.Id)
	c.Assert(*ent, gc.DeepEquals, entity)
}

func (s *NovaNeutronSuite) TestGetServerByName(c *gc.C) {
	named, err := s.service.serverByName("test")
	c.Assert(err, gc.ErrorMatches, `itemNotFound: No such server named "test"`)
	servers := []nova.ServerDetail{
		{Id: "sr1", Name: "test"},
		{Id: "sr2", Name: "test"},
		{Id: "sr3", Name: "not test"},
	}
	for _, server := range servers {
		s.createServer(c, server)
		defer s.deleteServer(c, server)
	}
	named, err = s.service.serverByName("test")
	c.Assert(err, gc.IsNil)
	// order is not guaranteed, so check both possible results
	if named.Id == servers[0].Id {
		c.Assert(*named, gc.DeepEquals, servers[0])
	} else {
		c.Assert(*named, gc.DeepEquals, servers[1])
	}
}

func (s *NovaNeutronSuite) TestAddHasRemoveServerSecurityGroup(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	group := neutron.SecurityGroupV2{Id: "1"}
	s.ensureNoServer(c, server)
	s.ensureNoGroup(c, group)
	ok := s.service.hasServerSecurityGroup(server.Id, group.Id)
	c.Assert(ok, gc.Equals, false)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	ok = s.service.hasServerSecurityGroup(server.Id, group.Id)
	c.Assert(ok, gc.Equals, false)
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ok = s.service.hasServerSecurityGroup(server.Id, group.Id)
	c.Assert(ok, gc.Equals, false)
	err := s.service.addServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
	ok = s.service.hasServerSecurityGroup(server.Id, group.Id)
	c.Assert(ok, gc.Equals, true)
	err = s.service.removeServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
	ok = s.service.hasServerSecurityGroup(server.Id, group.Id)
	c.Assert(ok, gc.Equals, false)
}

func (s *NovaNeutronSuite) TestAddServerSecurityGroupWithInvalidServerFails(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	group := neutron.SecurityGroupV2{Id: "1"}
	s.ensureNoServer(c, server)
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	err := s.service.addServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.ErrorMatches, `itemNotFound: No such server "sr1"`)
}

func (s *NovaNeutronSuite) TestAddServerSecurityGroupWithInvalidGroupFails(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	server := nova.ServerDetail{Id: "sr1"}
	s.ensureNoGroup(c, group)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	err := s.service.addServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such security group 1")
}

func (s *NovaNeutronSuite) TestAddServerSecurityGroupTwiceFails(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	err := s.service.addServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
	err = s.service.addServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.ErrorMatches, `conflictingRequest: Server "sr1" already belongs to group 1`)
	err = s.service.removeServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) TestAllServerSecurityGroups(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	srvGroups := s.service.allServerSecurityGroups(server.Id)
	c.Assert(srvGroups, gc.HasLen, 0)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	groups := []neutron.SecurityGroupV2{
		{
			Id:       "1",
			Name:     "gr1",
			TenantId: s.service.TenantId,
			Rules:    []neutron.SecurityGroupRuleV2{},
		},
		{
			Id:       "2",
			Name:     "gr2",
			TenantId: s.service.TenantId,
			Rules:    []neutron.SecurityGroupRuleV2{},
		},
	}
	for _, group := range groups {
		s.createGroup(c, group)
		defer s.deleteGroup(c, group)
		err := s.service.addServerSecurityGroup(server.Id, group.Id)
		defer s.service.removeServerSecurityGroup(server.Id, group.Id)
		c.Assert(err, gc.IsNil)
	}
	srvGroups = s.service.allServerSecurityGroups(server.Id)
	c.Assert(srvGroups, gc.HasLen, len(groups))
	if srvGroups[0].Id != groups[0].Id {
		srvGroups[0], srvGroups[1] = srvGroups[1], srvGroups[0]
	}
	c.Assert(srvGroups, gc.DeepEquals, groups)
}

func (s *NovaNeutronSuite) TestRemoveServerSecurityGroupWithInvalidServerFails(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createServer(c, server)
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	err := s.service.addServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
	s.deleteServer(c, server)
	err = s.service.removeServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.ErrorMatches, `itemNotFound: No such server "sr1"`)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	err = s.service.removeServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) TestRemoveServerSecurityGroupWithInvalidGroupFails(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	server := nova.ServerDetail{Id: "sr1"}
	s.createGroup(c, group)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	err := s.service.addServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
	s.deleteGroup(c, group)
	err = s.service.removeServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such security group 1")
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	err = s.service.removeServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) TestRemoveServerSecurityGroupTwiceFails(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	err := s.service.addServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
	err = s.service.removeServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.IsNil)
	err = s.service.removeServerSecurityGroup(server.Id, group.Id)
	c.Assert(err, gc.ErrorMatches, `badRequest: Server "sr1" does not belong to group 1`)
}

func (s *NovaNeutronSuite) TestAddHasRemoveServerFloatingIP(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	fip := neutron.FloatingIPV2{Id: "1", IP: "1.2.3.4"}
	s.ensureNoServer(c, server)
	s.ensureNoIP(c, fip)
	ok := s.service.hasServerFloatingIP(server.Id, fip.IP)
	c.Assert(ok, gc.Equals, false)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	ok = s.service.hasServerFloatingIP(server.Id, fip.IP)
	c.Assert(ok, gc.Equals, false)
	s.createIP(c, fip)
	defer s.deleteIP(c, fip)
	ok = s.service.hasServerFloatingIP(server.Id, fip.IP)
	c.Assert(ok, gc.Equals, false)
	err := s.service.addServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
	ok = s.service.hasServerFloatingIP(server.Id, fip.IP)
	c.Assert(ok, gc.Equals, true)
	err = s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
	ok = s.service.hasServerFloatingIP(server.Id, fip.IP)
	c.Assert(ok, gc.Equals, false)
}

func (s *NovaNeutronSuite) TestAddServerFloatingIPWithInvalidServerFails(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	fip := neutron.FloatingIPV2{Id: "1"}
	s.ensureNoServer(c, server)
	s.createIP(c, fip)
	defer s.deleteIP(c, fip)
	err := s.service.addServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.ErrorMatches, `itemNotFound: No such server "sr1"`)
}

func (s *NovaNeutronSuite) TestAddServerFloatingIPWithInvalidIPFails(c *gc.C) {
	fip := neutron.FloatingIPV2{Id: "1"}
	server := nova.ServerDetail{Id: "sr1"}
	s.ensureNoIP(c, fip)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	err := s.service.addServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such floating IP \"1\"")
}

func (s *NovaNeutronSuite) TestAddServerFloatingIPTwiceFails(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	fip := neutron.FloatingIPV2{Id: "1"}
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	s.createIP(c, fip)
	defer s.deleteIP(c, fip)
	err := s.service.addServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
	err = s.service.addServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.ErrorMatches, `conflictingRequest: Server "sr1" already has floating IP 1`)
	err = s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) TestRemoveServerFloatingIPWithInvalidServerFails(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	fip := neutron.FloatingIPV2{Id: "1"}
	s.createServer(c, server)
	s.createIP(c, fip)
	defer s.deleteIP(c, fip)
	err := s.service.addServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
	s.deleteServer(c, server)
	err = s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.ErrorMatches, `itemNotFound: No such server "sr1"`)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	err = s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) TestRemoveServerFloatingIPWithInvalidIPFails(c *gc.C) {
	fip := neutron.FloatingIPV2{Id: "1"}
	server := nova.ServerDetail{Id: "sr1"}
	s.createIP(c, fip)
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	err := s.service.addServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
	s.deleteIP(c, fip)
	err = s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such floating IP \"1\"")
	s.createIP(c, fip)
	defer s.deleteIP(c, fip)
	err = s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
}

func (s *NovaNeutronSuite) TestRemoveServerFloatingIPTwiceFails(c *gc.C) {
	server := nova.ServerDetail{Id: "sr1"}
	fip := neutron.FloatingIPV2{Id: "1"}
	s.createServer(c, server)
	defer s.deleteServer(c, server)
	s.createIP(c, fip)
	defer s.deleteIP(c, fip)
	err := s.service.addServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
	err = s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.IsNil)
	err = s.service.removeServerFloatingIP(server.Id, fip.Id)
	c.Assert(err, gc.ErrorMatches, `itemNotFound: Server "sr1" does not have floating IP 1`)
}

func (s *NovaNeutronSuite) TestAddRemoveSecurityGroup(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createGroup(c, group)
	s.deleteGroup(c, group)
}

func (s *NovaNeutronSuite) TestRemoveSecurityGroupTwiceFails(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1", Name: "test"}
	s.createGroup(c, group)
	s.deleteGroup(c, group)
	err := s.service.removeSecurityGroup(group.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such security group 1")
}

func (s *NovaNeutronSuite) TestAllSecurityGroups(c *gc.C) {
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

func (s *NovaNeutronSuite) TestGetSecurityGroup(c *gc.C) {
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

func (s *NovaNeutronSuite) TestGetSecurityGroupByName(c *gc.C) {
	group := neutron.SecurityGroupV2{
		Id:       "1",
		Name:     "test",
		TenantId: s.service.TenantId,
		Rules:    []neutron.SecurityGroupRuleV2{},
	}
	s.ensureNoGroup(c, group)
	gr, err := s.service.securityGroupByName(group.Name)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such security group named \"test\"")
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	gr, err = s.service.securityGroupByName(group.Name)
	c.Assert(err, gc.IsNil)
	c.Assert(*gr, gc.DeepEquals, group)
}

func (s *NovaNeutronSuite) TestAddHasRemoveSecurityGroupRule(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	ri := neutron.RuleInfoV2{ParentGroupId: group.Id, Direction: "egress"}
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

func (s *NovaNeutronSuite) TestAddGetIngressSecurityGroupRule(c *gc.C) {
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

func (s *NovaNeutronSuite) TestAddGetGroupSecurityGroupRule(c *gc.C) {
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
func (s *NovaNeutronSuite) TestAddSecurityGroupRuleTwiceFails(c *gc.C) {
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
*/

func (s *NovaNeutronSuite) TestAddSecurityGroupRuleToParentTwiceFails(c *gc.C) {
	group := neutron.SecurityGroupV2{
		Id:   "1",
		Name: "TestAddSecurityGroupRuleToParentTwiceFails",
	}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ri := neutron.RuleInfoV2{ParentGroupId: group.Id, Direction: "ingress"}
	rule := neutron.SecurityGroupRuleV2{Id: "10"}
	defer s.deleteRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)
	err = s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.ErrorMatches, "conflictingRequest: Security group rule already exists. Group id is 1.")
}

func (s *NovaNeutronSuite) TestAddSecurityGroupRuleWithInvalidParentFails(c *gc.C) {
	invalidGroup := neutron.SecurityGroupV2{Id: "1"}
	s.ensureNoGroup(c, invalidGroup)
	ri := neutron.RuleInfoV2{ParentGroupId: invalidGroup.Id, Direction: "egress"}
	rule := neutron.SecurityGroupRuleV2{Id: "10", Direction: "egress"}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such security group 1")
}

func (s *NovaNeutronSuite) TestAddGroupSecurityGroupRuleWithInvalidDirectionFails(c *gc.C) {
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
	c.Assert(err, gc.ErrorMatches, "badRequest: Invalid input for direction. Reason: 42 is not ingress or egress.")
}

func (s *NovaNeutronSuite) TestAddSecurityGroupRuleUpdatesParent(c *gc.C) {
	group := neutron.SecurityGroupV2{
		Id:       "8",
		Name:     "test",
		TenantId: s.service.TenantId,
	}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ri := neutron.RuleInfoV2{ParentGroupId: group.Id, Direction: "egress"}
	rule := neutron.SecurityGroupRuleV2{
		Id:            "45",
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

func (s *NovaNeutronSuite) TestRemoveSecurityGroupRuleTwiceFails(c *gc.C) {
	group := neutron.SecurityGroupV2{Id: "1"}
	s.createGroup(c, group)
	defer s.deleteGroup(c, group)
	ri := neutron.RuleInfoV2{ParentGroupId: group.Id, Direction: "egress"}
	//ri := neutron.RuleInfoV2{ParentGroupId: group.Id, GroupId: &group.Id}
	rule := neutron.SecurityGroupRuleV2{Id: "10"}
	s.ensureNoRule(c, rule)
	err := s.service.addSecurityGroupRule(rule.Id, ri)
	c.Assert(err, gc.IsNil)
	s.deleteRule(c, rule)
	err = s.service.removeSecurityGroupRule(rule.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such security group rule 10")
}

func (s *NovaNeutronSuite) TestAddHasRemoveFloatingIP(c *gc.C) {
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

func (s *NovaNeutronSuite) TestAddFloatingIPTwiceFails(c *gc.C) {
	ip := neutron.FloatingIPV2{Id: "1"}
	s.createIP(c, ip)
	defer s.deleteIP(c, ip)
	err := s.service.addFloatingIP(ip)
	c.Assert(err, gc.ErrorMatches, "conflictingRequest: A floating IP with id 1 already exists")
}

func (s *NovaNeutronSuite) TestRemoveFloatingIPTwiceFails(c *gc.C) {
	ip := neutron.FloatingIPV2{Id: "1"}
	s.createIP(c, ip)
	s.deleteIP(c, ip)
	err := s.service.removeFloatingIP(ip.Id)
	c.Assert(err, gc.ErrorMatches, "itemNotFound: No such floating IP \"1\"")
}

func (s *NovaNeutronSuite) TestAllFloatingIPs(c *gc.C) {
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

func (s *NovaNeutronSuite) TestGetFloatingIP(c *gc.C) {
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

func (s *NovaNeutronSuite) TestGetFloatingIPByAddr(c *gc.C) {
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

func (s *NovaNeutronSuite) TestAllNetworksV2(c *gc.C) {
	networks := s.service.allNetworks()
	newNets := []neutron.NetworkV2{
		{Id: "75", Name: "ListNetwork75", External: true, SubnetIds: []string{}},
		{Id: "42", Name: "ListNetwork42", External: true, SubnetIds: []string{}},
	}
	err := s.service.addNetwork(newNets[0])
	c.Assert(err, gc.IsNil)
	defer s.service.removeNetwork(newNets[0].Id)
	err = s.service.addNetwork(newNets[1])
	c.Assert(err, gc.IsNil)
	defer s.service.removeNetwork(newNets[1].Id)
	newNets[0].TenantId = s.service.TenantId
	newNets[1].TenantId = s.service.TenantId
	networks = append(networks, newNets...)
	foundNetworks := s.service.allNetworks()
	c.Assert(foundNetworks, gc.HasLen, len(networks))
	for _, net := range networks {
		for _, newNet := range foundNetworks {
			if net.Id == newNet.Id {
				c.Assert(net, gc.DeepEquals, newNet)
			}
		}
	}
}

func (s *NovaNeutronSuite) TestGetNetworkV2(c *gc.C) {
	network := neutron.NetworkV2{
		Id:        "75",
		Name:      "ListNetwork75",
		SubnetIds: []string{"32", "86"},
		External:  true,
		TenantId:  s.service.TenantId,
	}
	s.ensureNoNetwork(c, network)
	s.service.addNetwork(network)
	defer s.service.removeNetwork(network.Id)
	net, _ := s.service.network(network.Id)
	c.Assert(*net, gc.DeepEquals, network)
}

func (s *NovaNeutronSuite) TestAllSubnetsV2(c *gc.C) {
	subnets := s.service.allSubnets()
	newSubs := []neutron.SubnetV2{
		{Id: "86", Name: "ListSubnet86", Cidr: "192.168.0.0/24"},
		{Id: "92", Name: "ListSubnet92", Cidr: "192.169.0.0/24"},
	}
	err := s.service.addSubnet(newSubs[0])
	c.Assert(err, gc.IsNil)
	defer s.service.removeSubnet(newSubs[0].Id)
	err = s.service.addSubnet(newSubs[1])
	c.Assert(err, gc.IsNil)
	defer s.service.removeSubnet(newSubs[1].Id)
	newSubs[0].TenantId = s.service.TenantId
	newSubs[1].TenantId = s.service.TenantId
	subnets = append(subnets, newSubs...)
	foundSubnets := s.service.allSubnets()
	c.Assert(foundSubnets, gc.HasLen, len(subnets))
	for _, sub := range subnets {
		for _, newSub := range foundSubnets {
			if sub.Id == newSub.Id {
				c.Assert(sub, gc.DeepEquals, newSub)
			}
		}
	}
}

func (s *NovaNeutronSuite) TestGetSubnetV2(c *gc.C) {
	subnet := neutron.SubnetV2{
		Id:       "82",
		Name:     "ListSubnet82",
		TenantId: s.service.TenantId,
	}
	s.service.addSubnet(subnet)
	defer s.service.removeSubnet(subnet.Id)
	sub, _ := s.service.subnet(subnet.Id)
	c.Assert(*sub, gc.DeepEquals, subnet)
}
