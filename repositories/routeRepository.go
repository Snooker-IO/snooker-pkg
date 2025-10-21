package repositories

import "gorm.io/gorm"

type RouteRepository struct {
	WriteOnly *gorm.DB
	ReadOnly  *gorm.DB
}
