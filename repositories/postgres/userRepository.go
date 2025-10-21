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

func (userRepository *UserRepository) FindByEmail(ctx context.Context, email string) (dtos.UserDTO, error) {
	var user dtos.UserDTO
	err := userRepository.ReadOnly.Table(UserTableName).Where("email = ?", email).First(&user).Debug().Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return dtos.UserDTO{}, nil
	}

	if err != nil {
		return dtos.UserDTO{}, utils.RequestError{
			StatusCode: http.StatusInternalServerError,
			Exception:  exceptions.Exception{},
			Err:        err,
		}
	}

	return user, nil
}
