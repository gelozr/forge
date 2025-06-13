package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrIncorrectPassword = errors.New("incorrect password")
)

// User represents a basic user record for MemoryUserProvider.
type User struct {
	ID       string
	Email    string
	Password string
}

// PasswordCredentials is a simple email/password credential struct.
type PasswordCredentials struct {
	Email    string
	Password string
}

// MemoryUserProvider is an in-memory, demo/test only UserProvider.
// It stores users keyed by email and implements FindByCredentials
// to satisfy AnyHandler’s dynamic handler model.
type MemoryUserProvider struct {
	mu    sync.RWMutex
	users map[string]*User
}

var _ UserProvider[any, any] = (*MemoryUserProvider)(nil)
var _ UserRegisterer[any] = (*MemoryUserProvider)(nil)

// NewMemoryUserProvider creates an empty in-memory provider.
// Intended for testing or demos; not for production use.
func NewMemoryUserProvider() *MemoryUserProvider {
	return &MemoryUserProvider{
		users: make(map[string]*User),
	}
}

// FindByCredentials looks up a user by email/password.
// Expects credentials of type PasswordCredentials, returns any to fit AnyHandler.
func (p *MemoryUserProvider) FindByCredentials(ctx context.Context, credentials any) (any, error) {
	creds, ok := credentials.(PasswordCredentials)
	if !ok {
		return nil, errors.New("invalid credentials type")
	}

	u, err := p.GetByEmail(creds.Email)
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	if creds.Password != u.Password {
		return nil, ErrIncorrectPassword
	}

	return u, nil
}

// GetByEmail returns the user with the given email or ErrUserNotFound.
func (p *MemoryUserProvider) GetByEmail(email string) (*User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if u, ok := p.users[email]; ok {
		return u, nil
	}
	return nil, ErrUserNotFound
}

// RegisterUser creates a new user with a generated ID and stores it in memory.
// Expects user of type *User, returns any to satisfy AnyHandler.
func (p *MemoryUserProvider) RegisterUser(ctx context.Context, user any) (any, error) {
	u, ok := user.(*User)
	if !ok {
		return nil, errors.New("invalid user type")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok = p.users[u.Email]; ok {
		return nil, ErrUserAlreadyExists
	}

	u.ID = uniqid()
	p.users[u.Email] = u
	return u, nil
}
