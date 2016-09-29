// Neutron double testing service - internal direct API implementation

package neutronservice

import (
	"fmt"
	"net/url"
	"strings"

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
	groups      map[string]neutron.SecurityGroupV2
	rules       map[string]neutron.SecurityGroupRuleV2
	floatingIPs map[string]neutron.FloatingIPV2
	networks    map[string]neutron.NetworkV2
	subnets     map[string]neutron.SubnetV2
	nextGroupId int
	nextRuleId  int
	nextIPId    int
}

func errorJSONEncode(err error) (int, string) {
	serverError, ok := err.(*testservices.ServerError)
	if !ok {
		serverError = testservices.NewInternalServerError(err.Error())
	}
	return serverError.Code(), serverError.AsJSON()
}

// endpoint returns endpoint URL from the given path.
// openstack catalog list
// | neutron  | network      | RegionOne
// |          |              |   publicURL: http://<keystone ip>:9696
// |          |              |   internalURL: http://<keystone ip>:9696
// |          |              |   adminURL: http://<keystone ip>:9696
func (n *Neutron) endpointURL(path string) string {
	ep := n.Scheme + "://" + n.Hostname
	if path != "" {
		ep += strings.TrimLeft(path, "/")
	}
	return ep
}

func (n *Neutron) Endpoints() []identityservice.Endpoint {
	ep := identityservice.Endpoint{
		AdminURL:    n.endpointURL(""),
		InternalURL: n.endpointURL(""),
		PublicURL:   n.endpointURL(""),
		Region:      n.Region,
	}
	fmt.Printf("Endpoints(): %q\n", ep)
	return []identityservice.Endpoint{ep}
}

func (n *Neutron) V3Endpoints() []identityservice.V3Endpoint {
	url := n.endpointURL("")
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
	// Real openstack instances have a default security group "out of the box". So we add it here.
	defaultSecurityGroups := []neutron.SecurityGroupV2{
		{Id: "999", Name: "default", Description: "default group"},
	}
	neutronService := &Neutron{
		groups:      make(map[string]neutron.SecurityGroupV2),
		rules:       make(map[string]neutron.SecurityGroupRuleV2),
		floatingIPs: make(map[string]neutron.FloatingIPV2),
		networks:    make(map[string]neutron.NetworkV2),
		subnets:     make(map[string]neutron.SubnetV2),
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
	return neutronService
}

// updateSecurityGroup updates an existing security group
func (n *Neutron) updateSecurityGroup(group neutron.SecurityGroupV2) error {
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
func (n *Neutron) addSecurityGroup(group neutron.SecurityGroupV2) error {
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
func (n *Neutron) securityGroup(groupId string) (*neutron.SecurityGroupV2, error) {
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
func (n *Neutron) securityGroupByName(groupName string) (*neutron.SecurityGroupV2, error) {
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
func (n *Neutron) allSecurityGroups() []neutron.SecurityGroupV2 {
	//fmt.Printf("allSecurityGroups(): called\n")
	var groups []neutron.SecurityGroupV2
	for _, group := range n.groups {
		groups = append(groups, group)
	}
	return groups
}

// removeSecurityGroup deletes an existing group.
func (n *Neutron) removeSecurityGroup(groupId string) error {
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
func (n *Neutron) addSecurityGroupRule(ruleId string, rule neutron.RuleInfoV2) error {
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
func (n *Neutron) hasSecurityGroupRule(groupId, ruleId string) bool {
	//fmt.Printf("hasSecurityGroupRule(): called\n")
	rule, ok := n.rules[ruleId]
	_, err := n.securityGroup(groupId)
	return ok && (groupId == "-1" || (err == nil && rule.ParentGroupId == groupId))
}

// securityGroupRule retrieves an existing rule by ID.
func (n *Neutron) securityGroupRule(ruleId string) (*neutron.SecurityGroupRuleV2, error) {
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
func (n *Neutron) removeSecurityGroupRule(ruleId string) error {
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
func (n *Neutron) addFloatingIP(ip neutron.FloatingIPV2) error {
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
func (n *Neutron) hasFloatingIP(address string) bool {
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
func (n *Neutron) floatingIP(ipId string) (*neutron.FloatingIPV2, error) {
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
func (n *Neutron) floatingIPByAddr(address string) (*neutron.FloatingIPV2, error) {
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
func (n *Neutron) allFloatingIPs() []neutron.FloatingIPV2 {
	//fmt.Printf("allFloatingIPs(): called\n")
	var fips []neutron.FloatingIPV2
	for _, fip := range n.floatingIPs {
		fips = append(fips, fip)
	}
	return fips
}

// removeFloatingIP deletes an existing floating IP by ID.
func (n *Neutron) removeFloatingIP(ipId string) error {
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
func (n *Neutron) allNetworks() (networks []neutron.NetworkV2) {
	//fmt.Printf("allNetworks(): called\n")
	for _, net := range n.networks {
		networks = append(networks, net)
	}
	return networks
}

// network retrieves the network by ID.
func (n *Neutron) network(networkId string) (*neutron.NetworkV2, error) {
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
func (n *Neutron) addNetwork(network neutron.NetworkV2) error {
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
func (n *Neutron) removeNetwork(netId string) error {
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
func (n *Neutron) allSubnets() (subnets []neutron.SubnetV2) {
	//fmt.Printf("allSubnets(): called\n")
	for _, sub := range n.subnets {
		subnets = append(subnets, sub)
	}
	return subnets
}

// subnet retrieves the subnet by ID.
func (n *Neutron) subnet(subnetId string) (*neutron.SubnetV2, error) {
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
func (n *Neutron) addSubnet(subnet neutron.SubnetV2) error {
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
func (n *Neutron) removeSubnet(subnetId string) error {
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

