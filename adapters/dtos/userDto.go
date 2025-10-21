package dtos

import "time"

type UserDTO struct {
	UUID                string         `gorm:"column:uuid" json:"uuid"`
	Name                string         `gorm:"column:name" json:"name"`
	Email               string         `gorm:"column:email" json:"email"`
	Phone               string         `gorm:"column:phone" json:"phone"`
	Password            string         `gorm:"-" json:"password,omitempty"`
	Document            string         `gorm:"column:document" json:"document"`
	DocumentType        int            `gorm:"column:document_type" json:"document_type"`
	ExternalId          string         `gorm:"column:external_id" json:"external_id"`
	AttributesPermitted map[string]int `gorm:"-" json:"attributes_permitted"`
	CreatedAt           *time.Time     `gorm:"column:created_at" json:"created_at"`
	UpdatedAt           *time.Time     `gorm:"column:updated_at" json:"updated_at"`
}
