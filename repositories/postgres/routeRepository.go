package postgres

import (
	"context"
	"net/http"

	"github.com/Snooker-IO/snooker-pkg/adapters/dtos"
	"github.com/Snooker-IO/snooker-pkg/exceptions"
	"github.com/Snooker-IO/snooker-pkg/utils"
	"gorm.io/gorm"
)

const (
	RouteTableName = "routes"
)

type RouteRepository struct {
	WriteOnly *gorm.DB
	ReadOnly  *gorm.DB
}

func (repo *RouteRepository) FindByPath(ctx context.Context, path string) (dtos.RouteDTO, error) {
	route := dtos.RouteDTO{}
	err := repo.ReadOnly.Table(RouteTableName).
		Where("path = ?", path).Debug().Find(&route).Error
	if err != nil {
		return dtos.RouteDTO{}, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.Exception{},
			Err:        err,
		}
	}

	return route, nil
}
