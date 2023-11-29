package filepermission

// [defined here to avoid import cycle]
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

// [defined here to avoid import cycle]
// File represents a file entity.
type File struct {
	ID     uint64 `json:"id"`
	UserID uint64 `json:"user_id"`

	Filename string `json:"filename"`
	Type     string `json:"type"`
	Filepath string `json:"filepath,omitempty"`
}

// FilePermission defines a permission to file
// relationship.
type FilePermission struct {
	ID           uint64 `json:"id"`
	Filepath     string `json:"filepath"`
	PermissionID uint64
	Permission   Permission

	FileID uint64
	File   File `json:"file"`
}
