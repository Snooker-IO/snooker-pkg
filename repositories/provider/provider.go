package provider

import (
	"github.com/Snooker-IO/snooker-pkg/factories"
	"github.com/Snooker-IO/snooker-pkg/repositories"
)

type RepositoriesProviderI interface {
	UserRepositoryProvider() repositories.UserRepositoryI
	RouteRepositoryProvider() repositories.RouteRepositoryI
}

type RepositoriesProvider struct {
	Database factories.Database
}

func (provider *RepositoriesProvider) UserRepositoryProvider() repositories.UserRepositoryI {
	return repositories.NewUserRepository(provider.Database)
}

func (provider *RepositoriesProvider) RouteRepositoryProvider() repositories.RouteRepositoryI {
	return repositories.NewRouteRepository(provider.Database)
}
