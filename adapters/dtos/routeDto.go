package dtos

type RouteDTO struct {
	Path           string `gorm:"column:path" json:"path"`
	Name           string `gorm:"column:name" json:"name"`
	Auth           bool   `gorm:"column:auth" json:"auth"`
	PermissionUUID string `gorm:"column:permission_uuid" json:"permission_uuid"`
	Key            string `gorm:"column:key" json:"key"`
}
