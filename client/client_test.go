package client_test

import (
	"flag"
	. "launchpad.net/gocheck"
	"launchpad.net/goose/identity"
	"testing"
)

var live = flag.Bool("live", false, "Include live OpenStack (Canonistack) tests")
var liveAuthMethod = flag.String(
	"live-auth-mode", "userpass", "The authentication mode to use when running live tests [all|legacy|userpass]")

func Test(t *testing.T) {
	var allAuthMethods = []identity.AuthMode{identity.AuthLegacy, identity.AuthUserPass}
	var liveAuthMethods []identity.AuthMode
	switch *liveAuthMethod {
	default:
		t.Fatalf("Invalid auth method specified: %s", *liveAuthMethod)
	case "all":
		liveAuthMethods = allAuthMethods
	case "":
	case "userpass":
		liveAuthMethods = []identity.AuthMode{identity.AuthUserPass}
	case "legacy":
		liveAuthMethods = []identity.AuthMode{identity.AuthLegacy}
	}

	if *live {
		cred, err := identity.CompleteCredentialsFromEnv()
		if err != nil {
			t.Fatalf("Error setting up test suite: %s", err.Error())
		}
		registerOpenStackTests(cred, liveAuthMethods)
	}
	registerLocalTests(allAuthMethods)
	TestingT(t)
}
