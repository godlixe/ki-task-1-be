package guard

type Key struct {
	id       uint64
	PlainKey []byte
}

type ReferencedKey struct {
	Key
	KeyReference []byte
}
