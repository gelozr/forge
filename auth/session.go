package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrInvalidSessionID = errors.New("invalid session id")
	ErrSessionNotFound  = errors.New("session not found")
	ErrSessionExpired   = errors.New("session expired")
	ErrInvalidUser      = errors.New("invalid user")
)

// SessionDriver defines the contract for session-based drivers.
// U is the user type; P is the proof type used by Validate (often string).
// Login must return a session ID (string), and Logout removes that session.
type SessionDriver[U, P any] interface {
	Validator[U, P] // Validate(ctx, proof P) -> Verified[U]
	Login(ctx context.Context, user U) (string, error)
	Logout(ctx context.Context, sessionID string) error
}

// SessionAuth is an authentication handler that uses sessions.
// It embeds BaseAuth for Authenticate and adds Login/Logout behavior.
//
// C is the credential type for Authenticate (e.g., login form struct).
// U is the user type returned from Authenticate.
// P is the proof type for Validate (e.g., session ID type, typically string).
type SessionAuth[C, U, P any] struct {
	BaseAuth[C, U, P]
	driver SessionDriver[U, P]
}

// Compile-time checks that SessionAuth implements the expected handler interfaces.
var (
	_ AnyHandler        = (*SessionAuth[any, any, any])(nil)
	_ LoginHandler[any] = (*SessionAuth[any, any, any])(nil)
	_ LogoutHandler     = (*SessionAuth[any, any, any])(nil)
)

// NewSessionAuth constructs a new SessionAuth with the given driver and user provider.
func NewSessionAuth[C, U, P any, D SessionDriver[U, P], UP UserProvider[C, U]](driver D, userProvider UP) *SessionAuth[C, U, P] {
	return &SessionAuth[C, U, P]{
		BaseAuth: BaseAuth[C, U, P]{userProvider: userProvider},
		driver:   driver,
	}
}

// Validate delegates to the session driver to verify the proof and return a Verified user.
func (s *SessionAuth[C, U, P]) Validate(ctx context.Context, proof P) (Verified[U], error) {
	return s.driver.Validate(ctx, proof)
}

// Attempt combines Authenticate and Login: it verifies credentials and creates a session.
// Returns the user, the new session ID, or an error.
func (s *SessionAuth[C, U, P]) Attempt(ctx context.Context, creds C) (U, string, error) {
	var sess string

	user, err := s.Authenticate(ctx, creds)
	if err != nil {
		return user, sess, fmt.Errorf("authenticate: %w", err)
	}

	sess, err = s.Login(ctx, user)
	if err != nil {
		return user, sess, fmt.Errorf("login: %w", err)
	}

	return user, sess, nil
}

// Login calls the driver to create a new session for the given user.
func (s *SessionAuth[C, U, P]) Login(ctx context.Context, user U) (string, error) {
	return s.driver.Login(ctx, user)
}

// Logout calls the driver to invalidate the session by its ID.
func (s *SessionAuth[C, U, P]) Logout(ctx context.Context, sessionID string) error {
	return s.driver.Logout(ctx, sessionID)
}

// session holds in-memory session data.
type session struct {
	id           string
	uid          string
	exp          time.Time
	lastActivity time.Time
}

// MemorySessionDriver is an in-memory implementation of SessionDriver.
// Useful for testing or simple setups without external storage.
type MemorySessionDriver struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

// NewMemorySessionDriver initializes a MemorySessionDriver with an empty session store.
func NewMemorySessionDriver() *MemorySessionDriver {
	return &MemorySessionDriver{
		sessions: make(map[string]*session),
	}
}

// Validate checks that the session ID exists, is unexpired, updates lastActivity,
// and returns a Verified user context.
func (m *MemorySessionDriver) Validate(ctx context.Context, proof any) (Verified[any], error) {
	sessionID, ok := proof.(string)
	if !ok {
		return Verified[any]{}, ErrInvalidSessionID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[sessionID]
	if !ok {
		return Verified[any]{}, ErrSessionNotFound
	}

	if time.Now().After(sess.exp) {
		return Verified[any]{}, ErrSessionExpired
	}

	m.sessions[sessionID].lastActivity = time.Now()

	return Verified[any]{
		User: &User{ID: sess.uid},
	}, nil
}

// Login generates a new session ID for the given user and stores it in memory.
func (m *MemorySessionDriver) Login(ctx context.Context, user any) (string, error) {
	usr, ok := user.(*User)
	if !ok {
		return "", ErrInvalidUser
	}

	if usr.ID == "" {
		return "", ErrInvalidUser
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sessID := uniqid()

	m.sessions[sessID] = &session{
		id:           sessID,
		uid:          usr.ID,
		lastActivity: time.Now(),
		exp:          time.Now().Add(time.Hour),
	}

	return sessID, nil
}

// Logout removes the session with the given ID from the in-memory store.
func (m *MemorySessionDriver) Logout(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	delete(m.sessions, sessionID)

	return nil
}
