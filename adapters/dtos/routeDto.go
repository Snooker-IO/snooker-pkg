package dtos

type RouteDTO struct {
	Path          string `gorm:"column:path" json:"path"`
	Name          string `gorm:"column:name" json:"name"`
	Auth          bool   `gorm:"column:auth" json:"auth"`
	PermissionKey string `gorm:"column:permission_key" json:"permission_key"`
}
