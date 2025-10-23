package dtos

type RouteDTO struct {
	Path          string `gorm:"column:path" json:"path"`
	Name          string `gorm:"column:name" json:"name"`
	Auth          bool   `gorm:"column:auth" json:"auth"`
	RequiredOrg   bool   `gorm:"column:required_org" json:"required_org"`
	PermissionKey string `gorm:"column:permission_key" json:"permission_key"`
}
