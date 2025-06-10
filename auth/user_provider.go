package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrIncorrectPassword = errors.New("incorrect password")
)

func uniqid() string {
	return uuid.NewString()
}

type User struct {
	ID       string
	Email    string
	Password string
}

type PasswordCredentials struct {
	Email    string
	Password string
}

type MemoryUserProvider struct {
	mu    sync.RWMutex
	users map[string]*User
}

var _ UserProvider[any, any] = (*MemoryUserProvider)(nil)
var _ UserRegisterer[any] = (*MemoryUserProvider)(nil)

func NewMemoryUserProvider() *MemoryUserProvider {
	return &MemoryUserProvider{
		users: make(map[string]*User),
	}
}

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

func (p *MemoryUserProvider) GetByEmail(email string) (*User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if u, ok := p.users[email]; ok {
		return u, nil
	}
	return nil, ErrUserNotFound
}

func (p *MemoryUserProvider) Register(ctx context.Context, user any) (any, error) {
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
