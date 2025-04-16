package configs

import (
	"os"

	"github.com/WV-Consultancy/pkg/factories"
)

func GetAuthConfig() factories.AuthConfig {
	return factories.AuthConfig{
		Keycloak: factories.KeyclockConfig{
			URL: os.Getenv("KC_URL"),
			Admin: factories.KeycloakAdminCfg{
				ClientID:      os.Getenv("KC_CLIENT_ID"),
				ClientSecret:  os.Getenv("KC_CLIENT_SECRET"),
				AdminUser:     os.Getenv("KC_ADMIN"),
				AdminPassword: os.Getenv("KC_ADMIN_PASSWORD"),
				Realm:         os.Getenv("KC_REALM"),
			},
		},
	}
}
