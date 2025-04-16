package factories

import (
	"fmt"

	"github.com/Nerzal/gocloak/v13"
)

type AuthDriver string

const (
	AUTH_KEYCLOAK_DRIVER = AuthDriver("keycloak")
)

type Keycloak struct {
	Client *gocloak.GoCloak
}

type KeycloakAdminCfg struct {
	ClientID      string
	ClientSecret  string
	AdminUser     string
	AdminPassword string
	Realm         string
}

type KeyclockConfig struct {
	Admin KeycloakAdminCfg
	URL   string
}

type Auth struct {
	Keycloak Keycloak
}

type AuthConfig struct {
	Driver   AuthDriver
	Keycloak KeyclockConfig
}

func (cfg AuthConfig) AuthFactory() Auth {
	switch cfg.Driver {
	case AUTH_KEYCLOAK_DRIVER:
		return cfg.ConnectKeycloak()
	default:
		return Auth{}
	}
}

func (cfg AuthConfig) ConnectKeycloak() Auth {
	fmt.Println(cfg.Keycloak.URL)
	client := gocloak.NewClient(cfg.Keycloak.URL)
	return Auth{
		Keycloak: Keycloak{
			Client: client,
		},
	}
}
