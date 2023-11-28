package permission

import (
	"encryption/file"
	"encryption/user"
)

// Permission defines the existence of
// a permission for source user to view
// target user's data using the symmetric key "Key".
type Permission struct {
	ID           uint64 `json:"id"`
	SourceUserID uint64 `json:"source_user_id"`
	TargetUserID uint64 `json:"target_user_id"`

	// Key is an encrypted symmetric key
	Key []byte

	KeyReference []byte `json:"-"`
}

// Notification defines a permission request notification
// from source user to target user.
type Notification struct {
	ID           uint64    `json:"id"`
	SourceUserID uint64    `json:"source_user_id"`
	SourceUser   user.User `json:"source_user"`
	TargetUserID uint64    `json:"target_user_id"`
	TargetUser   user.User `json:"target_user"`

	// Status defines the status of the notification
	// - 0 : Awaiting for response.
	// - 1 : Request rejected.
	// - 2 : Request accepted
	Status int `json:"status"`
}

type RespondRequest struct {
	Status int `json:"status"`
}

// FilePermission defines a permission to file
// relationship.
type FilePermission struct {
	ID           uint64 `json:"id"`
	Filepath     string `json:"filepath"`
	PermissionID uint64
	Permission   Permission

	FileID uint64
	File   file.File `json:"file"`
}
