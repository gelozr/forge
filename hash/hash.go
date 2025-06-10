package hash

import (
	"errors"
	"fmt"
	"sync"
)

type Driver string

const (
	Bcrypt   = Driver("bcrypt")
	Argon2ID = Driver("argon2id")
)

type Hasher interface {
	Hash(password string) (string, error)
	Check(password, hash string) (bool, error)
}

type Hash interface {
	Hasher
	RegisterHasher(d Driver, hasher Hasher) error
}

type Manager struct {
	mu            sync.RWMutex
	hashers       map[Driver]Hasher
	defaultDriver Driver
}

func NewManager() *Manager {
	hashers := make(map[Driver]Hasher)
	hashers[Bcrypt] = NewBcryptHasher()
	hashers[Argon2ID] = NewArgon2IDHasher()

	return &Manager{
		hashers:       hashers,
		defaultDriver: Bcrypt,
	}
}

func (m *Manager) getHasher(driver Driver) (Hasher, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if hasher, ok := m.hashers[driver]; ok {
		return hasher, nil
	}
	return nil, fmt.Errorf("hasher not found for driver %s", driver)
}

func (m *Manager) RegisterHasher(d Driver, hasher Hasher) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.hashers[d]
	if ok {
		return errors.New("hash driver already registered")
	}

	m.hashers[d] = hasher
	return nil
}

// Hash hashes a plaintext
func (m *Manager) Hash(password string) (string, error) {
	hasher, err := m.getHasher(m.defaultDriver)
	if err != nil {
		return "", fmt.Errorf("get hasher: %w", err)
	}

	return hasher.Hash(password)
}

// Check checks if the given password matches the hashed password
func (m *Manager) Check(password, hash string) (bool, error) {
	hasher, err := m.getHasher(m.defaultDriver)
	if err != nil {
		return false, fmt.Errorf("get hasher: %w", err)
	}

	return hasher.Check(password, hash)
}

// func getDefaultDriver(cfg *config.Config) Driver {
// 	defaultHasher := Bcrypt
// 	if cfg.HashingDriver != "" {
// 		defaultHasher = Driver(cfg.HashingDriver)
// 	}
// 	return defaultHasher
// }
