package sss

type Option struct {
	Version int
	Key     []byte
}

func DefaultOption() *Option {
	return &Option{
		Version: Version1,
		Key:     []byte("Heisenberg"),
	}
}
