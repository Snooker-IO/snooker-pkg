package postgres

import (
	"context"
	"errors"
	"net/http"

	"github.com/Snooker-IO/snooker-pkg/adapters/dtos"
	"github.com/Snooker-IO/snooker-pkg/exceptions"
	"github.com/Snooker-IO/snooker-pkg/utils"
	"gorm.io/gorm"
)

const (
	UserTableName = "users"
)

type UserRepository struct {
	WriteOnly *gorm.DB
	ReadOnly  *gorm.DB
}

func (userRepository *UserRepository) FindByEmail(ctx context.Context, orgUUID string, email string) (dtos.UserDTO, error) {
	var user dtos.UserDTO
	query := userRepository.ReadOnly.Table(UserTableName)

	if orgUUID != "" {
		query.Joins("INNER JOIN organization_users ON users.uuid = organization_users.user_uuid").Where("organization_users.organization_uuid = ?", orgUUID)
	}

	err := query.Where("email = ?", email).Debug().First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return dtos.UserDTO{}, utils.RequestError{
			StatusCode: http.StatusNotFound,
			Exception: exceptions.Exception{
				Message: "user not found",
				Code:    "AUTH_USER_NOT_FOUND",
			},
		}
	}

	if err != nil {
		return dtos.UserDTO{}, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception: exceptions.Exception{
				Message: "error find user",
				Code:    "API_V1_DB_FIND_USER_ERROR",
			},
			Err: err,
		}
	}

	return user, nil
}
