package configs

import (
	"os"

	"github.com/WV-Consultancy/snooker-pkg/factories"
)

func GetDatabaseConfig() factories.DatabaseConfig {
	return factories.DatabaseConfig{
		Postgres: factories.PostgresConfig{
			Host:     os.Getenv("POSTGRES_HOST"),
			Username: os.Getenv("POSTGRES_USER"),
			Password: os.Getenv("POSTGRES_PASSWORD"),
			Database: os.Getenv("POSTGRES_DATABASE"),
			Port:     os.Getenv("POSTGRES_PORT"),
			TimeZone: os.Getenv("POSTGRES_TIMEZONE"),
			SSLMode:  os.Getenv("POSTGRES_SSL_MODE"),
		},
	}
}
