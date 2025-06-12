package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Common errors returned by Manager when operations are unsupported
var (
	ErrHandlerNotFound          = errors.New("handler not found")
	ErrRegisterUserNotSupported = errors.New("register user not supported")
	ErrLoginNotSupported        = errors.New("login not supported")
	ErrLogoutNotSupported       = errors.New("logout not supported")
	ErrIssueTokenNotSupported   = errors.New("issue token not supported")
	ErrRefreshTokenNotSupported = errors.New("refresh token not supported")
	ErrRevokeTokenNotSupported  = errors.New("revoke token not supported")
)

// Manager orchestrates one or more named authentication handlers.
// It implements the Auth interface.
type Manager struct {
	mu             sync.RWMutex
	handlers       map[string]AnyHandler
	defaultHandler string
}

var _ Auth = (*Manager)(nil)

// New creates a Manager and registers a "default" handler.
// Optionally accepts a HandlerOption to override the default driver or user provider.
func New(option ...HandlerOption) *Manager {
	m := &Manager{
		handlers:       make(map[string]AnyHandler),
		defaultHandler: "",
	}

	var o HandlerOption
	if len(option) > 0 {
		o = option[0]
	}

	if o.Driver == nil {
		o.Driver = NewJWTDriver()
	}
	if o.UserProvider == nil {
		o.UserProvider = NewMemoryUserProvider()
	}

	_ = m.Extend("default", o)

	return m
}

// Register delegates user registration to the default handler if supported.
func (a *Manager) Register(ctx context.Context, user any) (any, error) {
	if h, ok := a.MustHandler(a.defaultHandler).(UserRegisterer[any]); ok {
		return h.Register(ctx, user)
	}

	return nil, ErrRegisterUserNotSupported
}

// Authenticate delegates credential-based authentication to the default handler.
func (a *Manager) Authenticate(ctx context.Context, creds any) (any, error) {
	return a.MustHandler(a.defaultHandler).Authenticate(ctx, creds)
}

// Validate delegates proof validation (e.g., token/session) to the default handler.
func (a *Manager) Validate(ctx context.Context, proof any) (Verified[any], error) {
	return a.MustHandler(a.defaultHandler).Validate(ctx, proof)
}

// Login delegates login to the default handler if supported.
func (a *Manager) Login(ctx context.Context, user any) (string, error) {
	if h, ok := a.MustHandler(a.defaultHandler).(LoginHandler[any]); ok {
		return h.Login(ctx, user)
	}

	return "", ErrLoginNotSupported
}

// Logout delegates logout to the default handler if supported.
func (a *Manager) Logout(ctx context.Context, sessionID string) error {
	if h, ok := a.MustHandler(a.defaultHandler).(LogoutHandler); ok {
		return h.Logout(ctx, sessionID)
	}

	return ErrLogoutNotSupported
}

// IssueToken delegates token issuance to the default handler if supported.
func (a *Manager) IssueToken(ctx context.Context, user any) (any, error) {
	if h, ok := a.MustHandler(a.defaultHandler).(TokenIssuer[any, any]); ok {
		return h.IssueToken(ctx, user)
	}
	return nil, ErrIssueTokenNotSupported
}

// RefreshToken delegates token refreshing to the default handler if supported.
func (a *Manager) RefreshToken(ctx context.Context, refreshToken string) (any, error) {
	if h, ok := a.MustHandler(a.defaultHandler).(TokenRefresher[any]); ok {
		return h.RefreshToken(ctx, refreshToken)
	}
	return nil, ErrRefreshTokenNotSupported
}

// RevokeToken delegates token revocation to the default handler if supported.
func (a *Manager) RevokeToken(ctx context.Context, token string) error {
	if h, ok := a.MustHandler(a.defaultHandler).(TokenRevoker); ok {
		return h.RevokeToken(ctx, token)
	}
	return ErrRevokeTokenNotSupported
}

// LookupHandler returns a named handler or ErrHandlerNotFound if it does not exist.
func (a *Manager) LookupHandler(name string) (AnyHandler, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if g, ok := a.handlers[name]; ok {
		return g, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrHandlerNotFound, name)
}

// MustHandler returns a named handler, panicking if it does not exist.
// Useful for startup code where handlers are expected to be present.
func (a *Manager) MustHandler(name string) AnyHandler {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if g, ok := a.handlers[name]; ok {
		return g
	}

	panic(fmt.Sprintf("handler '%s' not found", name))
}

// Extend registers or replaces a handler under the given name.
// The first handler registered becomes the default.
func (a *Manager) Extend(name string, option HandlerOption) error {
	if option.UserProvider == nil || option.Driver == nil {
		panic("UserProvider or Validator cannot be nil")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// set the first handler as default
	if len(a.handlers) == 0 {
		a.defaultHandler = name
	}

	a.handlers[name] = &handler{
		userProvider: option.UserProvider,
		driver:       option.Driver,
	}

	return nil
}

// SetDefault sets the default handler to the named handler, returning an error if not found.
func (a *Manager) SetDefault(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.handlers[name]; !ok {
		return fmt.Errorf("%w: %s", ErrHandlerNotFound, name)
	}

	a.defaultHandler = name
	return nil
}

// HandlerOption configures a handler by supplying a Validator and UserProvider.
type HandlerOption struct {
	Driver       Validator[any, any]
	UserProvider UserProvider[any, any]
}

// ctxKey is a private type for context keys in this package.
type ctxKey string

var userCtxKey = ctxKey("user")

// WithUserCtx stores the authenticated user in the context.
func WithUserCtx(ctx context.Context, user any) context.Context {
	return context.WithValue(ctx, userCtxKey, user)
}

// UserFromCtx retrieves the authenticated user from the context.
func UserFromCtx(ctx context.Context) any {
	return ctx.Value(userCtxKey)
}

var (
	defaultAuth *Manager
	once        sync.Once
)

// getManager returns the singleton default Manager, initializing it once.
func getManager() *Manager {
	once.Do(func() {
		defaultAuth = New()
	})
	return defaultAuth
}

// Package-level convenience functions (facade) using the default Manager:

// Register registers a new user using the default handler.
func Register(ctx context.Context, user any) (any, error) {
	return getManager().Register(ctx, user)
}

// Authenticate authenticates credentials using the default handler.
func Authenticate(ctx context.Context, creds any) (any, error) {
	return getManager().Authenticate(ctx, creds)
}

// Validate validates a proof (token/session) using the default handler.
func Validate(ctx context.Context, proof any) (Verified[any], error) {
	return getManager().Validate(ctx, proof)
}

// Login logs in a user using the default handler.
func Login(ctx context.Context, user any) (string, error) {
	return getManager().Login(ctx, user)
}

// Logout logs out a session using the default handler.
func Logout(ctx context.Context, sessionID string) error {
	return getManager().Logout(ctx, sessionID)
}

// IssueToken issues a token using the default handler.
func IssueToken(ctx context.Context, user any) (any, error) {
	return getManager().IssueToken(ctx, user)
}

// RefreshToken refreshes a token using the default handler.
func RefreshToken(ctx context.Context, refreshToken string) (any, error) {
	return getManager().RefreshToken(ctx, refreshToken)
}

// RevokeToken revokes a token using the default handler.
func RevokeToken(ctx context.Context, token string) error {
	return getManager().RevokeToken(ctx, token)
}

// LookupHandler finds a named handler using the default Manager.
func LookupHandler(name string) (AnyHandler, error) {
	return getManager().LookupHandler(name)
}

// MustHandler finds a named handler or panics if not present.
func MustHandler(name string) AnyHandler {
	return getManager().MustHandler(name)
}

// Extend registers or replaces a named handler on the default Manager.
func Extend(name string, option HandlerOption) error {
	return getManager().Extend(name, option)
}

// SetDefault sets the default handler on the default Manager.
func SetDefault(name string) error {
	return getManager().SetDefault(name)
}

// UseDriver replaces the Validator on the default handler (preserving user provider).
func UseDriver(driver Validator[any, any]) {
	m := getManager()

	m.mu.Lock()
	defer m.mu.Unlock()

	if h, ok := m.handlers[m.defaultHandler].(*handler); ok {
		h.driver = driver
	}
}

// UseUserProvider replaces the UserProvider on the default handler (preserving driver).
func UseUserProvider(provider UserProvider[any, any]) {
	m := getManager()

	m.mu.Lock()
	defer m.mu.Unlock()

	if h, ok := m.handlers[m.defaultHandler].(*handler); ok {
		h.userProvider = provider
	}
}

// handler is the untyped implementation of AnyHandler that Manager uses
// to delegate Authenticate, Validate, and other optional methods.
type handler struct {
	driver       Validator[any, any]
	userProvider UserProvider[any, any]
}

var (
	_ AnyHandler            = (*handler)(nil)
	_ UserRegisterer[any]   = (*handler)(nil)
	_ LoginHandler[any]     = (*handler)(nil)
	_ LogoutHandler         = (*handler)(nil)
	_ TokenIssuer[any, any] = (*handler)(nil)
	_ TokenRefresher[any]   = (*handler)(nil)
	_ TokenRevoker          = (*handler)(nil)
)

func (h *handler) Register(ctx context.Context, user any) (any, error) {
	if d, ok := h.userProvider.(UserRegisterer[any]); ok {
		return d.Register(ctx, user)
	}
	return nil, ErrRegisterUserNotSupported
}

func (h *handler) Authenticate(ctx context.Context, creds any) (any, error) {
	user, err := h.userProvider.FindByCredentials(ctx, creds)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (h *handler) Validate(ctx context.Context, proof any) (Verified[any], error) {
	verified, err := h.driver.Validate(ctx, proof)
	if err != nil {
		return Verified[any]{}, err
	}

	return verified, nil
}

func (h *handler) Login(ctx context.Context, user any) (string, error) {
	if d, ok := h.driver.(LoginHandler[any]); ok {
		return d.Login(ctx, user)
	}
	return "", ErrLoginNotSupported
}

func (h *handler) Logout(ctx context.Context, sessionID string) error {
	if d, ok := h.driver.(LogoutHandler); ok {
		return d.Logout(ctx, sessionID)
	}
	return ErrLogoutNotSupported
}

func (h *handler) IssueToken(ctx context.Context, user any) (any, error) {
	if d, ok := h.driver.(TokenIssuer[any, any]); ok {
		return d.IssueToken(ctx, user)
	}
	return nil, ErrIssueTokenNotSupported
}

func (h *handler) RefreshToken(ctx context.Context, refreshToken string) (any, error) {
	if d, ok := h.driver.(TokenRefresher[any]); ok {
		return d.RefreshToken(ctx, refreshToken)
	}
	return nil, ErrRefreshTokenNotSupported
}

func (h *handler) RevokeToken(ctx context.Context, token string) error {
	if d, ok := h.driver.(TokenRevoker); ok {
		return d.RevokeToken(ctx, token)
	}
	return ErrRevokeTokenNotSupported
}
