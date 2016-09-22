// Neutron double testing service - internal direct API implementation

package neutronservice

import (
	//"fmt"
	"net/url"
	//"regexp"
	//"sort"
	"strings"

	//"gopkg.in/goose.v1/nova"
	"gopkg.in/goose.v1/neutron"
	"gopkg.in/goose.v1/testservices"
	"gopkg.in/goose.v1/testservices/identityservice"
)

var _ testservices.HttpService = (*Neutron)(nil)
var _ identityservice.ServiceProvider = (*Neutron)(nil)

// Neutron implements a OpenStack Neutron testing service and
// contains the service double's internal state.
type Neutron struct {
	testservices.ServiceInstance
	groups           map[string]neutron.SecurityGroupV2
	rules            map[string]neutron.SecurityGroupRuleV2
	floatingIPs      map[string]neutron.FloatingIPV2
	networks         map[string]neutron.NetworkV2
	subnets          map[string]neutron.SubnetV2
	serverGroups     map[string][]string
	serverIPs        map[string][]string
	nextServerId     int
	nextGroupId      int
	nextRuleId       int
	nextIPId         int
	nextAttachmentId int
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
func (n *Neutron) endpointURL(version bool, path string) string {
	//fmt.Printf("endpointURL(): starts with path of %s: \n", path)
	ep := n.Scheme + "://" + n.Hostname
	if version {
		ep += n.VersionPath + "/"
	}
	/*
		ep += n.TenantId
	*/
	if path != "" {
		ep += strings.TrimLeft(path, "/")
	}
	//fmt.Printf("endpointURL(): returning ep of %s: \n", ep)
	return ep
}

func (n *Neutron) Endpoints() []identityservice.Endpoint {
	ep := identityservice.Endpoint{
		AdminURL:    n.endpointURL(false, ""),
		InternalURL: n.endpointURL(false, ""),
		PublicURL:   n.endpointURL(false, ""),
		Region:      n.Region,
	}
	return []identityservice.Endpoint{ep}
}

func (n *Neutron) V3Endpoints() []identityservice.V3Endpoint {
	url := n.endpointURL(false, "")
	return identityservice.NewV3Endpoints(url, url, url, n.RegionID)
}

// New creates an instance of the Neutron object, given the parameters.
func New(hostURL, versionPath, tenantId, region string, identityService, fallbackIdentity identityservice.IdentityService) *Neutron {
	URL, err := url.Parse(hostURL)
	if err != nil {
		panic(err)
	}
	hostname := URL.Host
	if !strings.HasSuffix(hostname, "/") {
		hostname += "/"
	}
	/*
		// Real openstack instances have flavours "out of the box". So we add some here.
		defaultFlavors := []nova.FlavorDetail{
			{Id: "1", Name: "m1.tiny", RAM: 512, VCPUs: 1},
			{Id: "2", Name: "m1.small", RAM: 2048, VCPUs: 1},
			{Id: "3", Name: "m1.medium", RAM: 4096, VCPUs: 2},
		}
	*/
	// Real openstack instances have a default security group "out of the box". So we add it here.
	defaultSecurityGroups := []neutron.SecurityGroupV2{
		{Id: "999", Name: "default", Description: "default group"},
	}
	neutronService := &Neutron{
		groups:       make(map[string]neutron.SecurityGroupV2),
		rules:        make(map[string]neutron.SecurityGroupRuleV2),
		floatingIPs:  make(map[string]neutron.FloatingIPV2),
		networks:     make(map[string]neutron.NetworkV2),
		subnets:      make(map[string]neutron.SubnetV2),
		serverGroups: make(map[string][]string),
		serverIPs:    make(map[string][]string),
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
		identityService.RegisterServiceProvider("neutron", "network", neutronService)
	}
	for _, group := range defaultSecurityGroups {
		err := neutronService.addSecurityGroup(group)
		if err != nil {
			panic(err)
		}
	}
	// Add a sample default network
	var netId = "1"
	var subnetId = "1"
	neutronService.networks[netId] = neutron.NetworkV2{
		Id:        netId,
		Name:      "net",
		SubnetIds: []string{subnetId},
	}
	neutronService.subnets[subnetId] = neutron.SubnetV2{
		Id:        subnetId,
		NetworkId: netId,
		Name:      "subnet",
		Cidr:      "10.0.0.0/24",
	}
	return neutronService
}

func (n *Neutron) updateSecurityGroup(group neutron.SecurityGroupV2) error {
	if err := n.ProcessFunctionHook(n, group); err != nil {
		return err
	}
	existingGroup, err := n.securityGroup(group.Id)
	if err != nil {
		return testservices.NewNeutronSecurityGroupByIDNotFoundError(group.Id)
	}
	existingGroup.Name = group.Name
	existingGroup.Description = group.Description
	n.groups[group.Id] = *existingGroup
	return nil
}

// addSecurityGroup creates a new security group.
func (n *Neutron) addSecurityGroup(group neutron.SecurityGroupV2) error {
	if err := n.ProcessFunctionHook(n, group); err != nil {
		return err
	}
	if _, err := n.securityGroup(group.Id); err == nil {
		return testservices.NewSecurityGroupAlreadyExistsError(group.Id)
	}
	group.TenantId = n.TenantId
	group.Rules = []neutron.SecurityGroupRuleV2{}
	n.groups[group.Id] = group
	return nil
}

// securityGroup retrieves an existing group by ID.
func (n *Neutron) securityGroup(groupId string) (*neutron.SecurityGroupV2, error) {
	if err := n.ProcessFunctionHook(n, groupId); err != nil {
		return nil, err
	}
	//fmt.Printf("securityGroup(%s): groups = %s\n", groupId, n.groups)
	group, ok := n.groups[groupId]
	if !ok {
		return nil, testservices.NewNeutronSecurityGroupByIDNotFoundError(groupId)
	}
	return &group, nil
}

// securityGroupByName retrieves an existing named group.
func (n *Neutron) securityGroupByName(groupName string) (*neutron.SecurityGroupV2, error) {
	if err := n.ProcessFunctionHook(n, groupName); err != nil {
		return nil, err
	}
	for _, group := range n.groups {
		if group.Name == groupName {
			return &group, nil
		}
	}
	return nil, testservices.NewNeutronSecurityGroupByNameNotFoundError(groupName)
}

// allSecurityGroups returns a list of all existing groups.
func (n *Neutron) allSecurityGroups() []neutron.SecurityGroupV2 {
	var groups []neutron.SecurityGroupV2
	for _, group := range n.groups {
		groups = append(groups, group)
	}
	return groups
}

// removeSecurityGroup deletes an existing group.
func (n *Neutron) removeSecurityGroup(groupId string) error {
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
func (n *Neutron) addSecurityGroupRule(ruleId string, rule neutron.RuleInfoV2) error {
	if err := n.ProcessFunctionHook(n, ruleId, rule); err != nil {
		return err
	}
	/*
		if _, err := n.securityGroupRule(ruleId); err == nil {
			return testservices.NewSecurityGroupRuleAlreadyExistsError(ruleId)
		}
	*/
	group, err := n.securityGroup(rule.ParentGroupId)
	if err != nil {
		return err
	}
	/*
		for _, ru := range group.Rules {
			if ru.Id == ruleId {
				return testservices.NewCannotAddTwiceRuleToGroupError(ru.Id, group.Id)
			}
		}
	*/
	newrule := neutron.SecurityGroupRuleV2{
		ParentGroupId: rule.ParentGroupId,
		Id:            ruleId,
	}
	if rule.ParentGroupId != "" {
		sourceGroup, err := n.securityGroup(rule.ParentGroupId)
		if err != nil {
			return testservices.NewUnknownSecurityGroupError(rule.ParentGroupId)
		}
		newrule.TenantId = sourceGroup.TenantId
	}
	if rule.PortRangeMax != 0 {
		newrule.PortRangeMax = &rule.PortRangeMax
	}
	if rule.PortRangeMin != 0 {
		newrule.PortRangeMin = &rule.PortRangeMin
	}
	if rule.IPProtocol != "" {
		newrule.IPProtocol = &rule.IPProtocol
	} else if rule.IPProtocol == "" && (rule.PortRangeMin != 0 || rule.PortRangeMax != 0) {
		return testservices.NewSecurityGroupProtocolRequiresPorts()
	}

	//fmt.Printf("addSecurityGroupRule(): new rule direction (%s)", rule.Direction)
	if rule.Direction == "ingress" || rule.Direction == "egress" {
		newrule.Direction = rule.Direction
	} else {
		return testservices.NewInvalidDirectionSecurityGroupError(rule.Direction)
	}

	group.Rules = append(group.Rules, newrule)
	n.groups[group.Id] = *group
	n.rules[newrule.Id] = newrule
	return nil
}

// hasSecurityGroupRule returns whether the given group contains the given rule,
// or (when groupId="-1") whether the given rule exists.
func (n *Neutron) hasSecurityGroupRule(groupId, ruleId string) bool {
	rule, ok := n.rules[ruleId]
	_, err := n.securityGroup(groupId)
	return ok && (groupId == "-1" || (err == nil && rule.ParentGroupId == groupId))
}

// securityGroupRule retrieves an existing rule by ID.
func (n *Neutron) securityGroupRule(ruleId string) (*neutron.SecurityGroupRuleV2, error) {
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
func (n *Neutron) removeSecurityGroupRule(ruleId string) error {
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
func (n *Neutron) addFloatingIP(ip neutron.FloatingIPV2) error {
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
func (n *Neutron) hasFloatingIP(address string) bool {
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
func (n *Neutron) floatingIP(ipId string) (*neutron.FloatingIPV2, error) {
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
func (n *Neutron) floatingIPByAddr(address string) (*neutron.FloatingIPV2, error) {
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
func (n *Neutron) allFloatingIPs() []neutron.FloatingIPV2 {
	var fips []neutron.FloatingIPV2
	for _, fip := range n.floatingIPs {
		fips = append(fips, fip)
	}
	return fips
}

// removeFloatingIP deletes an existing floating IP by ID.
func (n *Neutron) removeFloatingIP(ipId string) error {
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
func (n *Neutron) allNetworks() (networks []neutron.NetworkV2) {
	for _, net := range n.networks {
		networks = append(networks, net)
	}
	return networks
}

// network retrieves the network by ID.
func (n *Neutron) network(networkId string) (*neutron.NetworkV2, error) {
	if err := n.ProcessFunctionHook(n, networkId); err != nil {
		return nil, err
	}
	network, ok := n.networks[networkId]
	if !ok {
		return nil, testservices.NewNetworkIdNotFoundError(networkId)
	}
	return &network, nil
}

// allSubnets returns a list of all existing subnets.
func (n *Neutron) allSubnets() (subnets []neutron.SubnetV2) {
	for _, sub := range n.subnets {
		subnets = append(subnets, sub)
	}
	return subnets
}
