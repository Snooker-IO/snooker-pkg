package configs

import "github.com/WV-Consultancy/pkg/factories"

type Environment string

const (
	DEVELOPMENT_ENVIRONMENT = Environment("development")
	PRODUCTION_ENVIRONMENT  = Environment("production")
)

type Config struct {
	Environment  Environment
	ApiPort      string
	RoutesConfig factories.RoutesConfig
	DbConfig     factories.DatabaseConfig
	LoggerConfig factories.LoggerConfig
	AuthConfig   factories.AuthConfig
}
