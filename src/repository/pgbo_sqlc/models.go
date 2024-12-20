// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package sqlc

import (
	"database/sql"
	"time"
)

type AppKey struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

type AuthToken struct {
	ID                  int64          `json:"id"`
	Name                string         `json:"name"`
	DeviceID            string         `json:"device_id"`
	DeviceType          string         `json:"device_type"`
	Token               string         `json:"token"`
	TokenExpired        time.Time      `json:"token_expired"`
	RefreshToken        string         `json:"refresh_token"`
	RefreshTokenExpired time.Time      `json:"refresh_token_expired"`
	IsLogin             bool           `json:"is_login"`
	UserLogin           sql.NullString `json:"user_login"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           sql.NullTime   `json:"updated_at"`
}

type Config struct {
	ID          int64          `json:"id"`
	Key         string         `json:"key"`
	Description sql.NullString `json:"description"`
	Value       string         `json:"value"`
	CreatedAt   sql.NullTime   `json:"created_at"`
	UpdatedAt   sql.NullTime   `json:"updated_at"`
	UpdatedBy   sql.NullString `json:"updated_by"`
}

type UserBackoffice struct {
	ID                     int64          `json:"id"`
	Guid                   string         `json:"guid"`
	Name                   sql.NullString `json:"name"`
	ProfilePictureImageUrl sql.NullString `json:"profile_picture_image_url"`
	Phone                  string         `json:"phone"`
	Email                  string         `json:"email"`
	RoleID                 int32          `json:"role_id"`
	Password               string         `json:"password"`
	Salt                   string         `json:"salt"`
	IsActive               sql.NullBool   `json:"is_active"`
	CreatedAt              time.Time      `json:"created_at"`
	CreatedBy              string         `json:"created_by"`
	UpdatedAt              sql.NullTime   `json:"updated_at"`
	UpdatedBy              sql.NullString `json:"updated_by"`
	DeletedAt              sql.NullTime   `json:"deleted_at"`
	DeletedBy              sql.NullString `json:"deleted_by"`
	LastLogin              sql.NullTime   `json:"last_login"`
}

type UserBackofficeRole struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	Access      sql.NullString `json:"access"`
	IsAllAccess sql.NullBool   `json:"is_all_access"`
	CreatedAt   time.Time      `json:"created_at"`
	CreatedBy   string         `json:"created_by"`
	UpdatedAt   sql.NullTime   `json:"updated_at"`
	UpdatedBy   sql.NullString `json:"updated_by"`
	DeletedAt   sql.NullTime   `json:"deleted_at"`
	DeletedBy   sql.NullString `json:"deleted_by"`
}

type UserHandheld struct {
	ID                     int64          `json:"id"`
	Guid                   string         `json:"guid"`
	Name                   string         `json:"name"`
	ProfilePictureImageUrl sql.NullString `json:"profile_picture_image_url"`
	Phone                  sql.NullString `json:"phone"`
	Email                  string         `json:"email"`
	Gender                 string         `json:"gender"`
	Address                sql.NullString `json:"address"`
	Salt                   string         `json:"salt"`
	Password               string         `json:"password"`
	IsActive               sql.NullBool   `json:"is_active"`
	FcmToken               sql.NullString `json:"fcm_token"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              sql.NullTime   `json:"updated_at"`
	DeletedAt              sql.NullTime   `json:"deleted_at"`
	LastLogin              sql.NullTime   `json:"last_login"`
}
