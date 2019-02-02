package sb

type Kext struct {
	PlatformProfile   []byte
	SandboxCollection []byte
	OperationNames    []string
}

func OpenOrNew() (*Kext, error) {
	return nil, nil
}
