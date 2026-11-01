package manage

import "sync"

// creationSecret is shared by copies of a creation result, so the secret can
// be exported once, including under concurrent callers.
type creationSecret struct {
	mu    sync.Mutex
	bytes []byte
}

func (s *creationSecret) take() ([]byte, error) {
	if s == nil {
		return nil, ErrSecretConsumed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.bytes) == 0 {
		return nil, ErrSecretConsumed
	}

	taken := s.bytes
	s.bytes = nil

	return taken, nil
}

func (s *creationSecret) wipe() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	clear(s.bytes)
	s.bytes = nil
}
