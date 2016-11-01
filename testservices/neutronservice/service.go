// Neutron double testing service - internal direct API implementation

package neutronservice

import (
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/goose.v1/neutron"
	"gopkg.in/goose.v1/testservices"
	"gopkg.in/goose.v1/testservices/identityservice"
	"gopkg.in/goose.v1/testservices/neutronmodel"
)

var _ testservices.HttpService = (*Neutron)(nil)
var _ identityservice.ServiceProvider = (*Neutron)(nil)

// Neutron implements a OpenStack Neutron testing service and
// contains the service double's internal state.
type Neutron struct {
	testservices.ServiceInstance
	neutronModel *neutronmodel.NeutronModel
	groups       map[string]neutron.SecurityGroupV2
	rules        map[string]neutron.SecurityGroupRuleV2
	floatingIPs  map[string]neutron.FloatingIPV2
	networks     map[string]neutron.NetworkV2
	subnets      map[string]neutron.SubnetV2
	nextGroupId  int
	nextRuleId   int
	nextIPId     int
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
func (n *Neutron) endpointURL(version bool, path string) string {
	ep := n.Scheme + "://" + n.Hostname
	if version {
		ep += n.VersionPath + "/"
	}
	if path != "" {
		ep += strings.TrimLeft(path, "/")
	}
	return ep
}

func (n *Neutron) Endpoints() []identityservice.Endpoint {
	ep := identityservice.Endpoint{
		AdminURL:    n.endpointURL(false, ""),
		InternalURL: n.endpointURL(false, ""),
		PublicURL:   n.endpointURL(false, ""),
		Region:      n.Region,
	}
	fmt.Printf("Endpoints(): %q\n", ep)
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
	defaultSubnets := []neutron.SubnetV2{
		{Id: "999-01", NetworkId: "999", Name: "subnet-999", Cidr: "10.9.0.0/24"},
		{Id: "998-01", NetworkId: "998", Name: "subnet-998", Cidr: "10.8.0.0/24"},
	}
	neutronService := &Neutron{
		subnets: make(map[string]neutron.SubnetV2),
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
	for _, subnet := range defaultSubnets {
		err := neutronService.addSubnet(subnet)
		if err != nil {
			panic(err)
		}
	}
	return neutronService
}

func (n *Neutron) Stop() {
	// noop
}

// AddNeutronModel setups up the test double for shared data between the nova 
// and neutron test doubles.  Required for the neutron test double.
func (n *Neutron) AddNeutronModel(neutronModel *neutronmodel.NeutronModel) {
	n.neutronModel = neutronModel
}

// updateSecurityGroup updates an existing security group.
func (n *Neutron) updateSecurityGroup(group neutron.SecurityGroupV2) error {
	if err := n.ProcessFunctionHook(n, group); err != nil {
		return err
	}
	return n.neutronModel.UpdateSecurityGroup(group)
}

// addSecurityGroup creates a new security group.
func (n *Neutron) addSecurityGroup(group neutron.SecurityGroupV2) error {
	if err := n.ProcessFunctionHook(n, group); err != nil {
		return err
	}
	return n.neutronModel.AddSecurityGroup(group)
}

// securityGroup retrieves an existing group by ID.
func (n *Neutron) securityGroup(groupId string) (*neutron.SecurityGroupV2, error) {
	if err := n.ProcessFunctionHook(n, groupId); err != nil {
		return nil, err
	}
	return n.neutronModel.SecurityGroup(groupId)
}

// securityGroupByName retrieves an existing named group.
func (n *Neutron) securityGroupByName(groupName string) (*neutron.SecurityGroupV2, error) {
	if err := n.ProcessFunctionHook(n, groupName); err != nil {
		return nil, err
	}
	return n.neutronModel.SecurityGroupByName(groupName)
}

// allSecurityGroups returns a list of all existing groups.
func (n *Neutron) allSecurityGroups() []neutron.SecurityGroupV2 {
	return n.neutronModel.AllSecurityGroups()
}

// removeSecurityGroup deletes an existing group.
func (n *Neutron) removeSecurityGroup(groupId string) error {
	if err := n.ProcessFunctionHook(n, groupId); err != nil {
		return err
	}
	return n.neutronModel.RemoveSecurityGroup(groupId)
}

// addSecurityGroupRule creates a new rule in an existing group.
// This can be either an ingress or an egress rule (see the notes
// about neutron.RuleInfoV2).
func (n *Neutron) addSecurityGroupRule(ruleId string, rule neutron.RuleInfoV2) error {
	if err := n.ProcessFunctionHook(n, ruleId, rule); err != nil {
		return err
	}
	return n.neutronModel.AddSecurityGroupRule(ruleId, rule)
}

// hasSecurityGroupRule returns whether the given group contains the given rule.
func (n *Neutron) hasSecurityGroupRule(groupId, ruleId string) bool {
	return n.neutronModel.HasSecurityGroupRule(groupId, ruleId)
}

// securityGroupRule retrieves an existing rule by ID.
func (n *Neutron) securityGroupRule(ruleId string) (*neutron.SecurityGroupRuleV2, error) {
	if err := n.ProcessFunctionHook(n, ruleId); err != nil {
		return nil, err
	}
	return n.neutronModel.SecurityGroupRule(ruleId)
}

// removeSecurityGroupRule deletes an existing rule from its group.
func (n *Neutron) removeSecurityGroupRule(ruleId string) error {
	if err := n.ProcessFunctionHook(n, ruleId); err != nil {
		return err
	}
	return n.neutronModel.RemoveSecurityGroupRule(ruleId)
}

// addFloatingIP creates a new floating IP address in the pool.
func (n *Neutron) addFloatingIP(ip neutron.FloatingIPV2) error {
	if err := n.ProcessFunctionHook(n, ip); err != nil {
		return err
	}
	return n.neutronModel.AddFloatingIP(ip)
}

// hasFloatingIP returns whether the given floating IP address exists.
func (n *Neutron) hasFloatingIP(address string) bool {
	return n.neutronModel.HasFloatingIP(address)
}

// floatingIP retrieves the floating IP by ID.
func (n *Neutron) floatingIP(ipId string) (*neutron.FloatingIPV2, error) {
	if err := n.ProcessFunctionHook(n, ipId); err != nil {
		return nil, err
	}
	return n.neutronModel.FloatingIP(ipId)
}

// floatingIPByAddr retrieves the floating IP by address.
func (n *Neutron) floatingIPByAddr(address string) (*neutron.FloatingIPV2, error) {
	if err := n.ProcessFunctionHook(n, address); err != nil {
		return nil, err
	}
	return n.neutronModel.FloatingIPByAddr(address)
}

// allFloatingIPs returns a list of all created floating IPs.
func (n *Neutron) allFloatingIPs() []neutron.FloatingIPV2 {
	return n.neutronModel.AllFloatingIPs()
}

// removeFloatingIP deletes an existing floating IP by ID.
func (n *Neutron) removeFloatingIP(ipId string) error {
	if err := n.ProcessFunctionHook(n, ipId); err != nil {
		return err
	}
	return n.neutronModel.RemoveFloatingIP(ipId)
}

// allNetworks returns a list of all existing networks.
func (n *Neutron) allNetworks() (networks []neutron.NetworkV2) {
	return n.neutronModel.AllNetworks()
}

// network retrieves the network by ID.
func (n *Neutron) network(networkId string) (*neutron.NetworkV2, error) {
	if err := n.ProcessFunctionHook(n, networkId); err != nil {
		return nil, err
	}
	return n.neutronModel.Network(networkId)
}

// addNetwork creates a new network.
func (n *Neutron) addNetwork(network neutron.NetworkV2) error {
	if err := n.ProcessFunctionHook(n, network); err != nil {
		return err
	}
	return n.neutronModel.AddNetwork(network)
}

// removeNetwork deletes an existing group.
func (n *Neutron) removeNetwork(netId string) error {
	if err := n.ProcessFunctionHook(n, netId); err != nil {
		return err
	}
	return n.neutronModel.RemoveNetwork(netId)
}

// allSubnets returns a list of all existing subnets.
func (n *Neutron) allSubnets() (subnets []neutron.SubnetV2) {
	for _, sub := range n.subnets {
		subnets = append(subnets, sub)
	}
	return subnets
}

// subnet retrieves the subnet by ID.
func (n *Neutron) subnet(subnetId string) (*neutron.SubnetV2, error) {
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
	if err := n.ProcessFunctionHook(n, subnetId); err != nil {
		return err
	}
	if _, err := n.subnet(subnetId); err != nil {
		return err
	}
	delete(n.subnets, subnetId)
	return nil
}
