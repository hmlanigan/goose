// Nova double testing service - internal direct API implementation

package novaneutronservice

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/goose.v1/neutron"
	"gopkg.in/goose.v1/nova"
	"gopkg.in/goose.v1/testservices"
	"gopkg.in/goose.v1/testservices/identityservice"
)

var _ testservices.HttpService = (*NovaNeutron)(nil)
var _ identityservice.ServiceProvider = (*NovaNeutron)(nil)

// NovaNeutron implements a OpenStack Nova testing service utilizing
// neutron networking and security groups and contains the service
// double's internal state.
type NovaNeutron struct {
	testservices.ServiceInstance
	flavors                   map[string]nova.FlavorDetail
	servers                   map[string]nova.ServerDetail
	groups                    map[string]neutron.SecurityGroupV2
	rules                     map[string]neutron.SecurityGroupRuleV2
	floatingIPs               map[string]neutron.FloatingIPV2
	networks                  map[string]neutron.NetworkV2
	subnets                   map[string]neutron.SubnetV2
	serverGroups              map[string][]string
	serverIPs                 map[string][]string
	availabilityZones         map[string]nova.AvailabilityZone
	serverIdToAttachedVolumes map[string][]nova.VolumeAttachment
	nextServerId              int
	nextGroupId               int
	nextRuleId                int
	nextIPId                  int
	nextAttachmentId          int
}

func errorJSONEncode(err error) (int, string) {
	serverError, ok := err.(*testservices.ServerError)
	if !ok {
		serverError = testservices.NewInternalServerError(err.Error())
	}
	return serverError.Code(), serverError.AsJSON()
}

// endpoint returns either a versioned or non-versioned service
// endpoint URL from the given path.
func (n *NovaNeutron) endpointURL(version bool, path string) string {
	ep := n.Scheme + "://" + n.Hostname
	// only the nova endpoints include the version and tentant id
	if !strings.HasPrefix(path, "v2.0") {
		if version {
			ep += n.VersionPath + "/"
		}
		ep += n.TenantId + "/"
	}
	if path != "" {
		ep += strings.TrimLeft(path, "/")
	}
	fmt.Printf("endpointURL(%s, %s): returns %s\n", version, path, ep)
	return ep
}

func (n *NovaNeutron) neutronEndpointURL(version bool, path string) string {
	ep := n.Scheme + "://" + n.Hostname
	if version {
		ep += n.VersionPath + "/"
	}
	if path != "" {
		ep += strings.TrimLeft(path, "/")
	}
	fmt.Printf("neutronEndpointURL(%s, %s): returns %s\n", version, path, ep)
	return ep
}

func (n *NovaNeutron) Endpoints() []identityservice.Endpoint {
	ep := identityservice.Endpoint{
		AdminURL:    n.endpointURL(true, ""),
		InternalURL: n.endpointURL(true, ""),
		PublicURL:   n.endpointURL(true, ""),
		Region:      n.Region,
	}
	return []identityservice.Endpoint{ep}
}

func (n *NovaNeutron) V3Endpoints() []identityservice.V3Endpoint {
	url := n.endpointURL(true, "")
	return identityservice.NewV3Endpoints(url, url, url, n.RegionID)
}

// New creates an instance of the Nova object, given the parameters.
func New(hostURL, versionPath, tenantId, region string, identityService, fallbackIdentity identityservice.IdentityService) *NovaNeutron {
	//fmt.Printf("New(): called \n")
	URL, err := url.Parse(hostURL)
	if err != nil {
		panic(err)
	}
	hostname := URL.Host
	if !strings.HasSuffix(hostname, "/") {
		hostname += "/"
	}
	// Real openstack instances have flavours "out of the box". So we add some here.
	defaultFlavors := []nova.FlavorDetail{
		{Id: "1", Name: "m1.tiny", RAM: 512, VCPUs: 1},
		{Id: "2", Name: "m1.small", RAM: 2048, VCPUs: 1},
		{Id: "3", Name: "m1.medium", RAM: 4096, VCPUs: 2},
	}
	// Real openstack instances have a default security group "out of the box". So we add it here.
	defaultSecurityGroups := []neutron.SecurityGroupV2{
		{Id: "999", Name: "default", Description: "default group"},
	}
	// There are no create/delete network/subnet commands, so make a few default
	defaultNetworks := []neutron.NetworkV2{
		{Id: "999", Name: "private", SubnetIds: []string{"999-01"}, External: false},
		{Id: "998", Name: "public", SubnetIds: []string{"998-01"}, External: true},
	}
	defaultSubnets := []neutron.SubnetV2{
		{Id: "999-01", NetworkId: "999"},
		{Id: "998-01", NetworkId: "998"},
	}
	novaNeutronService := &NovaNeutron{
		flavors:                   make(map[string]nova.FlavorDetail),
		servers:                   make(map[string]nova.ServerDetail),
		groups:                    make(map[string]neutron.SecurityGroupV2),
		rules:                     make(map[string]neutron.SecurityGroupRuleV2),
		floatingIPs:               make(map[string]neutron.FloatingIPV2),
		networks:                  make(map[string]neutron.NetworkV2),
		subnets:                   make(map[string]neutron.SubnetV2),
		serverGroups:              make(map[string][]string),
		serverIPs:                 make(map[string][]string),
		availabilityZones:         make(map[string]nova.AvailabilityZone),
		serverIdToAttachedVolumes: make(map[string][]nova.VolumeAttachment),
		ServiceInstance: testservices.ServiceInstance{
			IdentityService:         identityService,
			FallbackIdentityService: fallbackIdentity,
			Scheme:                  URL.Scheme,
			Hostname:                hostname,
			VersionPath:             versionPath,
			TenantId:                tenantId,
			Region:                  region,
		},
	}
	if identityService != nil {
		identityService.RegisterServiceProvider("nova", "compute", novaNeutronService)
		//identityService.RegisterServiceProvider("neutron", "network", novaNeutronService)
		networkServiceDef := identityservice.V2Service{
			Name: "neutron",
			Type: "network",
			Endpoints: []identityservice.Endpoint{
				{AdminURL: novaNeutronService.neutronEndpointURL(false, ""),
					InternalURL: novaNeutronService.neutronEndpointURL(false, ""),
					PublicURL:   novaNeutronService.neutronEndpointURL(false, ""),
					Region:      novaNeutronService.Region},
			},
		}
		networkService3Def := identityservice.V3Service{
			Name:      "neutron",
			Type:      "network",
			Endpoints: identityservice.NewV3Endpoints("", "", novaNeutronService.neutronEndpointURL(false, ""), novaNeutronService.Region),
		}
		identityService.AddService(identityservice.Service{V2: networkServiceDef, V3: networkService3Def})
	}
	for i, flavor := range defaultFlavors {
		novaNeutronService.buildFlavorLinks(&flavor)
		defaultFlavors[i] = flavor
		err := novaNeutronService.addFlavor(flavor)
		if err != nil {
			panic(err)
		}
	}
	for _, group := range defaultSecurityGroups {
		err := novaNeutronService.addSecurityGroup(group)
		if err != nil {
			panic(err)
		}
	}
	for _, net := range defaultNetworks {
		err := novaNeutronService.addNetwork(net)
		if err != nil {
			panic(err)
		}
	}
	for _, subnet := range defaultSubnets {
		err := novaNeutronService.addSubnet(subnet)
		if err != nil {
			panic(err)
		}
	}
	return novaNeutronService
}

// SetAvailabilityZones sets the availability zones for setting
// availability zones.
//
// Note: this is implemented as a public method rather than as
// an HTTP API for two reasons: availability zones are created
// indirectly via "host aggregates", which are a cloud-provider
// concept that we have not implemented, and because we want to
// be able to synthesize zone state changes.
func (n *NovaNeutron) SetAvailabilityZones(zones ...nova.AvailabilityZone) {
	n.availabilityZones = make(map[string]nova.AvailabilityZone)
	for _, z := range zones {
		n.availabilityZones[z.Name] = z
	}
}

// buildFlavorLinks populates the Links field of the passed
// FlavorDetail as needed by OpenStack HTTP API. Call this
// before addFlavor().
func (n *NovaNeutron) buildFlavorLinks(flavor *nova.FlavorDetail) {
	url := "/flavors/" + flavor.Id
	flavor.Links = []nova.Link{
		{Href: n.endpointURL(true, url), Rel: "self"},
		{Href: n.endpointURL(false, url), Rel: "bookmark"},
	}
}

// addFlavor creates a new flavor.
func (n *NovaNeutron) addFlavor(flavor nova.FlavorDetail) error {
	if err := n.ProcessFunctionHook(n, flavor); err != nil {
		return err
	}
	if _, err := n.flavor(flavor.Id); err == nil {
		return testservices.NewAddFlavorError(flavor.Id)
	}
	n.flavors[flavor.Id] = flavor
	return nil
}

// flavor retrieves an existing flavor by ID.
func (n *NovaNeutron) flavor(flavorId string) (*nova.FlavorDetail, error) {
	if err := n.ProcessFunctionHook(n, flavorId); err != nil {
		return nil, err
	}
	flavor, ok := n.flavors[flavorId]
	if !ok {
		return nil, testservices.NewNoSuchFlavorError(flavorId)
	}
	return &flavor, nil
}

// flavorAsEntity returns the stored FlavorDetail as Entity.
func (n *NovaNeutron) flavorAsEntity(flavorId string) (*nova.Entity, error) {
	if err := n.ProcessFunctionHook(n, flavorId); err != nil {
		return nil, err
	}
	flavor, err := n.flavor(flavorId)
	if err != nil {
		return nil, err
	}
	return &nova.Entity{
		Id:    flavor.Id,
		Name:  flavor.Name,
		Links: flavor.Links,
	}, nil
}

// allFlavors returns a list of all existing flavors.
func (n *NovaNeutron) allFlavors() []nova.FlavorDetail {
	var flavors []nova.FlavorDetail
	for _, flavor := range n.flavors {
		flavors = append(flavors, flavor)
	}
	return flavors
}

// allFlavorsAsEntities returns all flavors as Entity structs.
func (n *NovaNeutron) allFlavorsAsEntities() []nova.Entity {
	var entities []nova.Entity
	for _, flavor := range n.flavors {
		entities = append(entities, nova.Entity{
			Id:    flavor.Id,
			Name:  flavor.Name,
			Links: flavor.Links,
		})
	}
	return entities
}

// removeFlavor deletes an existing flavor.
func (n *NovaNeutron) removeFlavor(flavorId string) error {
	if err := n.ProcessFunctionHook(n, flavorId); err != nil {
		return err
	}
	if _, err := n.flavor(flavorId); err != nil {
		return err
	}
	delete(n.flavors, flavorId)
	return nil
}

// buildServerLinks populates the Links field of the passed
// ServerDetail as needed by OpenStack HTTP API. Call this
// before addServer().
func (n *NovaNeutron) buildServerLinks(server *nova.ServerDetail) {
	url := "/servers/" + server.Id
	server.Links = []nova.Link{
		{Href: n.endpointURL(true, url), Rel: "self"},
		{Href: n.endpointURL(false, url), Rel: "bookmark"},
	}
}

// addServer creates a new server.
func (n *NovaNeutron) addServer(server nova.ServerDetail) error {
	if err := n.ProcessFunctionHook(n, &server); err != nil {
		return err
	}
	if _, err := n.server(server.Id); err == nil {
		return testservices.NewServerAlreadyExistsError(server.Id)
	}
	n.servers[server.Id] = server
	return nil
}

// updateServerName creates a new server.
func (n *NovaNeutron) updateServerName(serverId, name string) error {
	if err := n.ProcessFunctionHook(n, serverId); err != nil {
		return err
	}
	server, err := n.server(serverId)
	if err != nil {
		return testservices.NewServerByIDNotFoundError(serverId)
	}
	server.Name = name
	n.servers[serverId] = *server
	return nil
}

// server retrieves an existing server by ID.
func (n *NovaNeutron) server(serverId string) (*nova.ServerDetail, error) {
	if err := n.ProcessFunctionHook(n, serverId); err != nil {
		return nil, err
	}
	server, ok := n.servers[serverId]
	if !ok {
		return nil, testservices.NewServerByIDNotFoundError(serverId)
	}
	return &server, nil
}

// serverByName retrieves the first existing server with the given name.
func (n *NovaNeutron) serverByName(name string) (*nova.ServerDetail, error) {
	if err := n.ProcessFunctionHook(n, name); err != nil {
		return nil, err
	}
	for _, server := range n.servers {
		if server.Name == name {
			return &server, nil
		}
	}
	return nil, testservices.NewServerByNameNotFoundError(name)
}

// serverAsEntity returns the stored ServerDetail as Entity.
func (n *NovaNeutron) serverAsEntity(serverId string) (*nova.Entity, error) {
	if err := n.ProcessFunctionHook(n, serverId); err != nil {
		return nil, err
	}
	server, err := n.server(serverId)
	if err != nil {
		return nil, err
	}
	return &nova.Entity{
		Id:    server.Id,
		UUID:  server.UUID,
		Name:  server.Name,
		Links: server.Links,
	}, nil
}

// filter is used internally by matchServers.
type filter map[string]string

// matchServers returns a list of matching servers, after applying the
// given filter. Each separate filter is combined with a logical AND.
// Each filter can have only one value. A nil filter matches all servers.
//
// This is tested to match OpenStack behavior. Regular expression
// matching is supported for FilterServer only, and the supported
// syntax is limited to whatever DB backend is used (see SQL
// REGEXP/RLIKE).
//
// Example:
//
// f := filter{
//     nova.FilterStatus: nova.StatusActive,
//     nova.FilterServer: `foo.*`,
// }
//
// This will match all servers with status "ACTIVE", and names starting
// with "foo".
func (n *NovaNeutron) matchServers(f filter) ([]nova.ServerDetail, error) {
	if err := n.ProcessFunctionHook(n, f); err != nil {
		return nil, err
	}
	var servers []nova.ServerDetail
	for _, server := range n.servers {
		servers = append(servers, server)
	}
	if len(f) == 0 {
		return servers, nil // empty filter matches everything
	}
	if status := f[nova.FilterStatus]; status != "" {
		matched := []nova.ServerDetail{}
		for _, server := range servers {
			if server.Status == status {
				matched = append(matched, server)
			}
		}
		if len(matched) == 0 {
			// no match, so no need to look further
			return nil, nil
		}
		servers = matched
	}
	if nameRex := f[nova.FilterServer]; nameRex != "" {
		matched := []nova.ServerDetail{}
		rex, err := regexp.Compile(nameRex)
		if err != nil {
			return nil, err
		}
		for _, server := range servers {
			if rex.MatchString(server.Name) {
				matched = append(matched, server)
			}
		}
		if len(matched) == 0 {
			// no match, here so ignore other results
			return nil, nil
		}
		servers = matched
	}
	return servers, nil
	// TODO(dimitern) - 2013-02-11 bug=1121690
	// implement FilterFlavor, FilterImage, FilterMarker, FilterLimit and FilterChangesSince
}

// allServers returns a list of all existing servers.
// Filtering is supported, see filter type for more info.
func (n *NovaNeutron) allServers(f filter) ([]nova.ServerDetail, error) {
	return n.matchServers(f)
}

// allServersAsEntities returns all servers as Entity structs.
// Filtering is supported, see filter type for more info.
func (n *NovaNeutron) allServersAsEntities(f filter) ([]nova.Entity, error) {
	var entities []nova.Entity
	servers, err := n.matchServers(f)
	if err != nil {
		return nil, err
	}
	for _, server := range servers {
		entities = append(entities, nova.Entity{
			Id:    server.Id,
			UUID:  server.UUID,
			Name:  server.Name,
			Links: server.Links,
		})
	}
	return entities, nil
}

// removeServer deletes an existing server.
func (n *NovaNeutron) removeServer(serverId string) error {
	if err := n.ProcessFunctionHook(n, serverId); err != nil {
		return err
	}
	if _, err := n.server(serverId); err != nil {
		return err
	}
	delete(n.servers, serverId)
	return nil
}

// addServerSecurityGroup attaches an existing server to a group.
func (n *NovaNeutron) addServerSecurityGroup(serverId string, groupId string) error {
	if err := n.ProcessFunctionHook(n, serverId, groupId); err != nil {
		return err
	}
	if _, err := n.server(serverId); err != nil {
		return err
	}
	if _, err := n.securityGroup(groupId); err != nil {
		return err
	}
	groups, ok := n.serverGroups[serverId]
	if ok {
		for _, gid := range groups {
			if gid == groupId {
				return testservices.NewServerBelongsToGroupError(serverId, groupId)
			}
		}
	}
	groups = append(groups, groupId)
	n.serverGroups[serverId] = groups
	return nil
}

// hasServerSecurityGroup returns whether the given server belongs to the group.
func (n *NovaNeutron) hasServerSecurityGroup(serverId string, groupId string) bool {
	if _, err := n.server(serverId); err != nil {
		return false
	}
	if _, err := n.securityGroup(groupId); err != nil {
		return false
	}
	groups, ok := n.serverGroups[serverId]
	if !ok {
		return false
	}
	for _, gid := range groups {
		if gid == groupId {
			return true
		}
	}
	return false
}

// allServerSecurityGroups returns all security groups attached to the
// given server.
func (n *NovaNeutron) allServerSecurityGroups(serverId string) []neutron.SecurityGroupV2 {
	var groups []neutron.SecurityGroupV2
	for _, gid := range n.serverGroups[serverId] {
		group, err := n.securityGroup(gid)
		if err != nil {
			return nil
		}
		groups = append(groups, *group)
	}
	return groups
}

// removeServerSecurityGroup detaches an existing server from a group.
func (n *NovaNeutron) removeServerSecurityGroup(serverId string, groupId string) error {
	if err := n.ProcessFunctionHook(n, serverId, groupId); err != nil {
		return err
	}
	if _, err := n.server(serverId); err != nil {
		return err
	}
	if _, err := n.securityGroup(groupId); err != nil {
		return err
	}
	groups, ok := n.serverGroups[serverId]
	if !ok {
		return testservices.NewServerDoesNotBelongToGroupsError(serverId)
	}
	idx := -1
	for gi, gid := range groups {
		if gid == groupId {
			idx = gi
			break
		}
	}
	if idx == -1 {
		return testservices.NewServerDoesNotBelongToGroupError(serverId, groupId)
	}
	groups = append(groups[:idx], groups[idx+1:]...)
	n.serverGroups[serverId] = groups
	return nil
}

// addServerFloatingIP attaches an existing floating IP to a server.
func (n *NovaNeutron) addServerFloatingIP(serverId string, ipId string) error {
	if err := n.ProcessFunctionHook(n, serverId, ipId); err != nil {
		return err
	}
	if _, err := n.server(serverId); err != nil {
		return err
	}
	if fip, err := n.floatingIP(ipId); err != nil {
		return err
	} else {
		fip.FixedIP = "4.3.2.1" // not important really, unused
		//fip.InstanceId = &serverId
		n.floatingIPs[ipId] = *fip
	}
	fips, ok := n.serverIPs[serverId]
	if ok {
		for _, fipId := range fips {
			if fipId == ipId {
				return testservices.NewServerHasFloatingIPError(serverId, ipId)
			}
		}
	}
	fips = append(fips, ipId)
	n.serverIPs[serverId] = fips
	return nil
}

// hasServerFloatingIP verifies the given floating IP belongs to a server.
func (n *NovaNeutron) hasServerFloatingIP(serverId, address string) bool {
	if _, err := n.server(serverId); err != nil || !n.hasFloatingIP(address) {
		return false
	}
	fips, ok := n.serverIPs[serverId]
	if !ok {
		return false
	}
	for _, fipId := range fips {
		fip := n.floatingIPs[fipId]
		if fip.IP == address {
			return true
		}
	}
	return false
}

// removeServerFloatingIP deletes an attached floating IP from a server.
func (n *NovaNeutron) removeServerFloatingIP(serverId string, ipId string) error {
	if err := n.ProcessFunctionHook(n, serverId); err != nil {
		return err
	}
	if _, err := n.server(serverId); err != nil {
		return err
	}
	if fip, err := n.floatingIP(ipId); err != nil {
		return err
	} else {
		fip.FixedIP = ""
		//fip.InstanceId = nil
		n.floatingIPs[ipId] = *fip
	}
	fips, ok := n.serverIPs[serverId]
	if !ok {
		return testservices.NewNoFloatingIPsToRemoveError(serverId)
	}
	idx := -1
	for fi, fipId := range fips {
		if fipId == ipId {
			idx = fi
			break
		}
	}
	if idx == -1 {
		return testservices.NewNoFloatingIPsError(serverId, ipId)
	}
	fips = append(fips[:idx], fips[idx+1:]...)
	n.serverIPs[serverId] = fips
	return nil
}

// allAvailabilityZones returns a list of all existing availability zones,
// sorted by name.
func (n *NovaNeutron) allAvailabilityZones() (zones []nova.AvailabilityZone) {
	for _, zone := range n.availabilityZones {
		zones = append(zones, zone)
	}
	sort.Sort(azByName(zones))
	return zones
}

type azByName []nova.AvailabilityZone

func (a azByName) Len() int {
	return len(a)
}

func (a azByName) Less(i, j int) bool {
	return a[i].Name < a[j].Name
}

func (a azByName) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// setServerMetadata sets metadata on a server.
func (n *NovaNeutron) setServerMetadata(serverId string, metadata map[string]string) error {
	if err := n.ProcessFunctionHook(n, serverId, metadata); err != nil {
		return err
	}
	server, err := n.server(serverId)
	if err != nil {
		return err
	}
	if server.Metadata == nil {
		server.Metadata = make(map[string]string)
	}
	for k, v := range metadata {
		server.Metadata[k] = v
	}
	n.servers[serverId] = *server
	return nil
}

// updateSecurityGroup updates an existing security group
func (n *NovaNeutron) updateSecurityGroup(group neutron.SecurityGroupV2) error {
	//fmt.Printf("updateSecurityGroup(): called\n")
	if err := n.ProcessFunctionHook(n, group); err != nil {
		return err
	}
	existingGroup, err := n.securityGroup(group.Id)
	if err != nil {
		return testservices.NewSecurityGroupByIDNotFoundError(group.Id)
	}
	existingGroup.Name = group.Name
	existingGroup.Description = group.Description
	n.groups[group.Id] = *existingGroup
	return nil
}

// addSecurityGroup creates a new security group.
func (n *NovaNeutron) addSecurityGroup(group neutron.SecurityGroupV2) error {
	//fmt.Printf("addSecurityGroup(): called\n")
	if err := n.ProcessFunctionHook(n, group); err != nil {
		return err
	}
	if _, err := n.securityGroup(group.Id); err == nil {
		return testservices.NewSecurityGroupAlreadyExistsError(group.Id)
	}
	group.TenantId = n.TenantId
	if group.Rules == nil {
		group.Rules = []neutron.SecurityGroupRuleV2{}
	}
	n.groups[group.Id] = group
	return nil
}

// securityGroup retrieves an existing group by ID.
func (n *NovaNeutron) securityGroup(groupId string) (*neutron.SecurityGroupV2, error) {
	//fmt.Printf("securityGroup(): called\n")
	if err := n.ProcessFunctionHook(n, groupId); err != nil {
		return nil, err
	}
	group, ok := n.groups[groupId]
	if !ok {
		return nil, testservices.NewSecurityGroupByIDNotFoundError(groupId)
	}
	return &group, nil
}

// securityGroupByName retrieves an existing named group.
func (n *NovaNeutron) securityGroupByName(groupName string) (*neutron.SecurityGroupV2, error) {
	//fmt.Printf("securityGroupByName(): called\n")
	if err := n.ProcessFunctionHook(n, groupName); err != nil {
		return nil, err
	}
	for _, group := range n.groups {
		if group.Name == groupName {
			return &group, nil
		}
	}
	return nil, testservices.NewSecurityGroupByNameNotFoundError(groupName)
}

// allSecurityGroups returns a list of all existing groups.
func (n *NovaNeutron) allSecurityGroups() []neutron.SecurityGroupV2 {
	//fmt.Printf("allSecurityGroups(): called\n")
	var groups []neutron.SecurityGroupV2
	for _, group := range n.groups {
		groups = append(groups, group)
	}
	return groups
}

// removeSecurityGroup deletes an existing group.
func (n *NovaNeutron) removeSecurityGroup(groupId string) error {
	//fmt.Printf("removeSecurityGroup(): called\n")
	if err := n.ProcessFunctionHook(n, groupId); err != nil {
		return err
	}
	if _, err := n.securityGroup(groupId); err != nil {
		return err
	}
	delete(n.groups, groupId)
	return nil
}

// addSecurityGroupRule creates a new rule in an existing group.
// This can be either an ingress or an egress rule (see the notes
// about neutron.RuleInfoV2).
func (n *NovaNeutron) addSecurityGroupRule(ruleId string, rule neutron.RuleInfoV2) error {
	//fmt.Printf("addSecurityGroupRule(): called\n")
	if err := n.ProcessFunctionHook(n, ruleId, rule); err != nil {
		return err
	}
	if _, err := n.securityGroupRule(ruleId); err == nil {
		return testservices.NewNeutronSecurityGroupRuleAlreadyExistsError(rule.ParentGroupId)
	}
	group, err := n.securityGroup(rule.ParentGroupId)
	if err != nil {
		return err
	}
	newrule := neutron.SecurityGroupRuleV2{
		ParentGroupId: rule.ParentGroupId,
		Id:            ruleId,
	}
	if rule.Direction == "ingress" || rule.Direction == "egress" {
		newrule.Direction = rule.Direction
	} else {
		return testservices.NewInvalidDirectionSecurityGroupError(rule.Direction)
	}
	if rule.PortRangeMin != 0 {
		newrule.PortRangeMin = &rule.PortRangeMin
	}
	if rule.PortRangeMax != 0 {
		newrule.PortRangeMax = &rule.PortRangeMax
	}
	if rule.IPProtocol != "" {
		newrule.IPProtocol = &rule.IPProtocol
	}
	if group.TenantId != "" {
		newrule.TenantId = group.TenantId
	}
	/*
		else if rule.IPProtocol == "" && (rule.PortRangeMin != 0 || rule.PortRangeMax != 0) {
			return testservices.NewSecurityGroupProtocolRequiresPorts()
		}
	*/

	group.Rules = append(group.Rules, newrule)
	n.groups[group.Id] = *group
	n.rules[newrule.Id] = newrule
	return nil
}

// hasSecurityGroupRule returns whether the given group contains the given rule,
// or (when groupId="-1") whether the given rule exists.
func (n *NovaNeutron) hasSecurityGroupRule(groupId, ruleId string) bool {
	//fmt.Printf("hasSecurityGroupRule(): called\n")
	rule, ok := n.rules[ruleId]
	_, err := n.securityGroup(groupId)
	return ok && (groupId == "-1" || (err == nil && rule.ParentGroupId == groupId))
}

// securityGroupRule retrieves an existing rule by ID.
func (n *NovaNeutron) securityGroupRule(ruleId string) (*neutron.SecurityGroupRuleV2, error) {
	//fmt.Printf("securityGroupRule(%s): called, rules = %q\n", ruleId, n.rules)
	if err := n.ProcessFunctionHook(n, ruleId); err != nil {
		return nil, err
	}
	rule, ok := n.rules[ruleId]
	if !ok {
		return nil, testservices.NewSecurityGroupRuleNotFoundError(ruleId)
	}
	return &rule, nil
}

// removeSecurityGroupRule deletes an existing rule from its group.
func (n *NovaNeutron) removeSecurityGroupRule(ruleId string) error {
	//fmt.Printf("removeSecurityGroupRule(): called\n")
	if err := n.ProcessFunctionHook(n, ruleId); err != nil {
		return err
	}
	rule, err := n.securityGroupRule(ruleId)
	if err != nil {
		return err
	}
	if group, err := n.securityGroup(rule.ParentGroupId); err == nil {
		idx := -1
		for ri, ru := range group.Rules {
			if ru.Id == ruleId {
				idx = ri
				break
			}
		}
		if idx != -1 {
			group.Rules = append(group.Rules[:idx], group.Rules[idx+1:]...)
			n.groups[group.Id] = *group
		}
		// Silently ignore missing rules...
	}
	// ...or groups
	delete(n.rules, ruleId)
	return nil
}

// addFloatingIP creates a new floating IP address in the pool.
func (n *NovaNeutron) addFloatingIP(ip neutron.FloatingIPV2) error {
	//fmt.Printf("addFloatingIP(): called\n")
	if err := n.ProcessFunctionHook(n, ip); err != nil {
		return err
	}
	if _, err := n.floatingIP(ip.Id); err == nil {
		return testservices.NewFloatingIPExistsError(ip.Id)
	}
	n.floatingIPs[ip.Id] = ip
	return nil
}

// hasFloatingIP returns whether the given floating IP address exists.
func (n *NovaNeutron) hasFloatingIP(address string) bool {
	//fmt.Printf("hasFloatingIP(): called\n")
	if len(n.floatingIPs) == 0 {
		return false
	}
	for _, fip := range n.floatingIPs {
		if fip.IP == address {
			return true
		}
	}
	return false
}

// floatingIP retrieves the floating IP by ID.
func (n *NovaNeutron) floatingIP(ipId string) (*neutron.FloatingIPV2, error) {
	//fmt.Printf("floatingIP(): called\n")
	if err := n.ProcessFunctionHook(n, ipId); err != nil {
		return nil, err
	}
	ip, ok := n.floatingIPs[ipId]
	if !ok {
		return nil, testservices.NewFloatingIPNotFoundError(ipId)
	}
	return &ip, nil
}

// floatingIPByAddr retrieves the floating IP by address.
func (n *NovaNeutron) floatingIPByAddr(address string) (*neutron.FloatingIPV2, error) {
	//fmt.Printf("floatingIPByAddr(): called\n")
	if err := n.ProcessFunctionHook(n, address); err != nil {
		return nil, err
	}
	for _, fip := range n.floatingIPs {
		if fip.IP == address {
			return &fip, nil
		}
	}
	return nil, testservices.NewFloatingIPNotFoundError(address)
}

// allFloatingIPs returns a list of all created floating IPs.
func (n *NovaNeutron) allFloatingIPs() []neutron.FloatingIPV2 {
	//fmt.Printf("allFloatingIPs(): called\n")
	var fips []neutron.FloatingIPV2
	for _, fip := range n.floatingIPs {
		fips = append(fips, fip)
	}
	return fips
}

// removeFloatingIP deletes an existing floating IP by ID.
func (n *NovaNeutron) removeFloatingIP(ipId string) error {
	//fmt.Printf("removeFloatingIP(): called\n")
	if err := n.ProcessFunctionHook(n, ipId); err != nil {
		return err
	}
	if _, err := n.floatingIP(ipId); err != nil {
		return err
	}
	delete(n.floatingIPs, ipId)
	return nil
}

// allNetworks returns a list of all existing networks.
func (n *NovaNeutron) allNetworks() (networks []neutron.NetworkV2) {
	//fmt.Printf("allNetworks(): called\n")
	for _, net := range n.networks {
		networks = append(networks, net)
	}
	return networks
}

// network retrieves the network by ID.
func (n *NovaNeutron) network(networkId string) (*neutron.NetworkV2, error) {
	//fmt.Printf("networks(): called\n")
	if err := n.ProcessFunctionHook(n, networkId); err != nil {
		return nil, err
	}
	network, ok := n.networks[networkId]
	if !ok {
		return nil, testservices.NewNetworkNotFoundError(networkId)
	}
	return &network, nil
}

// addNetwork creates a new network.
func (n *NovaNeutron) addNetwork(network neutron.NetworkV2) error {
	//fmt.Printf("addNetwork(): called\n")
	if err := n.ProcessFunctionHook(n, network); err != nil {
		return err
	}
	if _, err := n.network(network.Id); err == nil {
		return testservices.NewNetworkAlreadyExistsError(network.Id)
	}
	network.TenantId = n.TenantId
	if network.SubnetIds == nil {
		network.SubnetIds = []string{}
	}
	n.networks[network.Id] = network
	return nil
}

// removeNetwork deletes an existing group.
func (n *NovaNeutron) removeNetwork(netId string) error {
	//fmt.Printf("removeNetwork(): called\n")
	if err := n.ProcessFunctionHook(n, netId); err != nil {
		return err
	}
	if _, err := n.network(netId); err != nil {
		return err
	}
	delete(n.networks, netId)
	return nil
}

// allSubnets returns a list of all existing subnets.
func (n *NovaNeutron) allSubnets() (subnets []neutron.SubnetV2) {
	//fmt.Printf("allSubnets(): called\n")
	for _, sub := range n.subnets {
		subnets = append(subnets, sub)
	}
	return subnets
}

// subnet retrieves the subnet by ID.
func (n *NovaNeutron) subnet(subnetId string) (*neutron.SubnetV2, error) {
	//fmt.Printf("subnets(): called\n")
	if err := n.ProcessFunctionHook(n, subnetId); err != nil {
		return nil, err
	}
	subnet, ok := n.subnets[subnetId]
	if !ok {
		return nil, testservices.NewSubnetNotFoundError(subnetId)
	}
	return &subnet, nil
}

// addSubnet creates a new subnet.
func (n *NovaNeutron) addSubnet(subnet neutron.SubnetV2) error {
	//fmt.Printf("addSubnet(): called\n")
	if err := n.ProcessFunctionHook(n, subnet); err != nil {
		return err
	}
	if _, err := n.subnet(subnet.Id); err == nil {
		return testservices.NewSubnetAlreadyExistsError(subnet.Id)
	}
	subnet.TenantId = n.TenantId
	n.subnets[subnet.Id] = subnet
	return nil
}

// removeSubnet deletes an existing subnet.
func (n *NovaNeutron) removeSubnet(subnetId string) error {
	//fmt.Printf("removeNetwork(): called\n")
	if err := n.ProcessFunctionHook(n, subnetId); err != nil {
		return err
	}
	if _, err := n.subnet(subnetId); err != nil {
		return err
	}
	delete(n.subnets, subnetId)
	return nil
}
