package auth2

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrLoginNotSupported        = errors.New("login not supported")
	ErrLogoutNotSupported       = errors.New("logout not supported")
	ErrIssueTokenNotSupported   = errors.New("issue token not supported")
	ErrRefreshTokenNotSupported = errors.New("refresh token not supported")
	ErrRevokeTokenNotSupported  = errors.New("revoke token not supported")
)

type Manager struct {
	mu             sync.RWMutex
	handlers       map[string]AnyHandler
	defaultHandler string
}

var _ Auth = (*Manager)(nil)

func New() *Manager {
	return &Manager{
		handlers:       make(map[string]AnyHandler),
		defaultHandler: "",
	}
}

func (a *Manager) Authenticate(ctx context.Context, creds any) (any, error) {
	return a.MustHandler(a.defaultHandler).Authenticate(ctx, creds)
}

func (a *Manager) Validate(ctx context.Context, payload any) (Verified[any], error) {
	return a.MustHandler(a.defaultHandler).Validate(ctx, payload)
}

func (a *Manager) Login(ctx context.Context, user any) (any, error) {
	if h, ok := a.MustHandler(a.defaultHandler).(LoginHandler[any, any]); ok {
		return h.Login(ctx, user)
	}

	return nil, ErrLoginNotSupported
}

func (a *Manager) Logout(ctx context.Context, id any) error {
	if h, ok := a.MustHandler(a.defaultHandler).(LogoutHandler[any]); ok {
		return h.Logout(ctx, id)
	}

	return ErrLogoutNotSupported
}

func (a *Manager) IssueToken(ctx context.Context, user any) (any, error) {
	if h, ok := a.MustHandler(a.defaultHandler).(TokenIssuer[any, any]); ok {
		return h.IssueToken(ctx, user)
	}
	return nil, ErrIssueTokenNotSupported
}

func (a *Manager) RefreshToken(ctx context.Context, refreshToken string) (any, error) {
	if h, ok := a.MustHandler(a.defaultHandler).(TokenRefresher[any]); ok {
		return h.RefreshToken(ctx, refreshToken)
	}
	return nil, ErrRefreshTokenNotSupported
}

func (a *Manager) RevokeToken(ctx context.Context, token string) error {
	if h, ok := a.MustHandler(a.defaultHandler).(TokenRevoker); ok {
		return h.RevokeToken(ctx, token)
	}
	return ErrRevokeTokenNotSupported
}

func (a *Manager) Handler(name string) (AnyHandler, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if g, ok := a.handlers[name]; ok {
		return g, nil
	}
	return nil, fmt.Errorf("guard '%s' not found", name)
}

func (a *Manager) MustHandler(name string) AnyHandler {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if g, ok := a.handlers[name]; ok {
		return g
	}

	panic(fmt.Sprintf("DefaultAuth '%s' not found", name))
}

func (a *Manager) Extend(name string, option GuardOption[any, any, any]) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if option.UserProvider == nil || option.Driver == nil {
		panic("UserProvider or Driver cannot be nil")
	}

	if a.handlers == nil {
		a.handlers = make(map[string]AnyHandler)
	}

	if len(a.handlers) == 0 {
		a.defaultHandler = name
	}

	a.handlers[name] = &handler{
		userProvider: option.UserProvider,
		driver:       option.Driver,
	}

	return nil
}

func (a *Manager) HasHandler(name string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	_, ok := a.handlers[name]
	return ok
}

func (a *Manager) SetDefaultGuard(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.handlers[name]; !ok {
		return fmt.Errorf("guard '%s' not found", name)
	}

	a.defaultHandler = name
	return nil
}

type ctxKey string

var userCtxKey = ctxKey("user")

func WithUserCtx(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, userCtxKey, user)
}

func UserFromCtx(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userCtxKey).(User)
	return u, ok
}
