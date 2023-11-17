package permission

import "encryption/user"

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
