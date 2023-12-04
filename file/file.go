package file

import (
	filepermission "encryption/user/file_permission"
	"errors"
	"time"
)

// File represents a file entity.
type File struct {
	ID     uint64 `json:"id"`
	UserID uint64 `json:"user_id"`

	Filename string `json:"filename"`
	Type     string `json:"type"`
	Filepath string `json:"filepath,omitempty"`
	IsSigned bool   `json:"is_signed"`

	// Metadata is an encrypted reference to
	// the file's key.
	KeyReference []byte `json:"-"`

	FilePermissions filepermission.FilePermission `json:"file_permissions"`

	// File content.
	Content []byte
}

// Types for File.
const (
	IDCard         string = "id_card"
	ProfilePicture string = "profile_picture"
	Video          string = "video"
	Docs           string = "docs"
	Misc           string = "misc"
)

// Digital signature const.
const (
	DataCommentKey      string = "DataKeyf-14_"
	SignatureCommentKey string = "SignatureKeyf-14_"
	PublicKeyCommentKey string = "Publickeyf-14_"
)

func ValidateType(s string) (string, error) {
	switch s {
	case "id_card":
		return IDCard, nil
	case "profile_picture":
		return ProfilePicture, nil
	case "video":
		return Video, nil
	case "docs":
		return Docs, nil
	case "misc":
		return Misc, nil
	}

	return "", errors.New("invalid type")
}

type SignatureMetadata struct {
	SignDate time.Time
	SignBy   string
	Contact  string
}
