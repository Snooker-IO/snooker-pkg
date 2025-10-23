package repositories

import (
	"context"

	"github.com/Snooker-IO/snooker-pkg/adapters/dtos"
	"github.com/Snooker-IO/snooker-pkg/factories"
	"github.com/Snooker-IO/snooker-pkg/repositories/postgres"
)

type RouteRepositoryI interface {
	FindByPath(ctx context.Context, path string) (dtos.RouteDTO, error)
}

type UserRepositoryI interface {
	FindByEmail(ctx context.Context, orgUUID string, email string) (dtos.UserDTO, error)
}

func NewRouteRepository(db factories.Database) RouteRepositoryI {
	return &postgres.RouteRepository{
		WriteOnly: db.Postgres.WriteDB,
		ReadOnly:  db.Postgres.ReadOnly,
	}
}

func NewUserRepository(db factories.Database) UserRepositoryI {
	return &postgres.UserRepository{
		WriteOnly: db.Postgres.WriteDB,
		ReadOnly:  db.Postgres.ReadOnly,
	}
}
