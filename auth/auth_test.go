package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gelozr/forge/auth"
)

type MockUser struct {
	ID any
}

func (u MockUser) UserID() any {
	return u.ID
}

type MockUserProvider struct {
	shouldFail bool
	user       *MockUser
}

func (m *MockUserProvider) FindByCredentials(ctx context.Context, credentials auth.Credentials) (auth.User, error) {
	if m.shouldFail {
		return nil, errors.New("mock error")
	}

	return m.user, nil
}

type MockDriver struct {
	shouldFail bool
	verified   auth.Verified
}

func (m *MockDriver) Validate(ctx context.Context, payload any) (auth.Verified, error) {
	if m.shouldFail {
		return auth.Verified{}, errors.New("mock error")
	}

	return m.verified, nil
}

type MockWithLoginDriver struct {
	shouldFail bool
}

func (m MockWithLoginDriver) Validate(ctx context.Context, payload any) (auth.Verified, error) {
	return auth.Verified{User: &MockUser{ID: "verifiedID"}}, nil
}

func (m MockWithLoginDriver) Login(ctx context.Context, user auth.User) (any, error) {
	if m.shouldFail {
		return nil, errors.New("mock error login")
	}
	return "loginID", nil
}

func newTestAuth(t *testing.T, guard string, userProvider auth.UserProvider, driver auth.Driver) *auth.Provider {
	a := auth.New()

	if err := a.Extend(guard, auth.GuardOption{
		UserProvider: userProvider,
		Driver:       driver,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return a
}

func withDefaultGuard(t *testing.T, a *auth.Provider, name string) *auth.Provider {
	if err := a.SetDefaultGuard(name); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return a
}

func getSelectedGuard(t *testing.T, a *auth.Provider, name string) auth.Guard {
	g, err := a.Guard(name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return g
}

func TestProvider_Extend_PanicOnNil(t *testing.T) {
	a := auth.New()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for nil provider and driver")
		}
	}()

	if err := a.Extend("mock", auth.GuardOption{}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProvider_Extend(t *testing.T) {
	a := newTestAuth(t, "mock", &MockUserProvider{}, &MockDriver{})

	if ok := a.HasGuard("mock"); !ok {
		t.Errorf("guard '%s' not found", "mock")
	}
}

func TestProvider_SetDefaultGuard(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		guard      string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:       "guard not found",
			input:      "guard",
			guard:      "randomGuard",
			wantErr:    true,
			wantErrMsg: "guard 'randomGuard' not found",
		},
		{
			name:       "guard found",
			input:      "guard",
			guard:      "guard",
			wantErr:    false,
			wantErrMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAuth(t, tt.input, &MockUserProvider{}, &MockDriver{})

			err := a.SetDefaultGuard(tt.guard)
			if (err != nil) != tt.wantErr {
				t.Errorf("expected error: %v, got: %v", tt.wantErrMsg, err)
			}

			if tt.wantErr && err.Error() != tt.wantErrMsg {
				t.Errorf("expected error message %q, got %q", tt.wantErrMsg, err.Error())
			}
		})
	}
}

func TestProvider_MustGuard_PanicOnNotFound(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for guard not found")
		}
	}()

	a := newTestAuth(t, "mock", &MockUserProvider{}, &MockDriver{})
	a = withDefaultGuard(t, a, "mock")

	a.MustGuard("notfound")
}

func TestProvider_MustGuard(t *testing.T) {
	a := newTestAuth(t, "mock", &MockUserProvider{user: &MockUser{ID: "mustGuardUserID"}}, &MockDriver{})
	a = withDefaultGuard(t, a, "mock")

	g := a.MustGuard("mock")
	user, err := g.Authenticate(context.Background(), any("creds"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user == nil {
		t.Errorf("expected user")
	} else if user.UserID() != "mustGuardUserID" {
		t.Errorf("expected user id to be mustGuardUserID, got %s", user.UserID())
	}
}

func TestProvider_Guard(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		guard      string
		wantErrMsg string
		wantErr    bool
	}{
		{
			name:       "guard not found",
			input:      "guard",
			guard:      "randomGuard",
			wantErr:    true,
			wantErrMsg: "guard 'randomGuard' not found",
		},
		{
			name:       "guard found",
			input:      "guard",
			guard:      "guard",
			wantErr:    false,
			wantErrMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAuth(t, tt.input, &MockUserProvider{user: &MockUser{ID: "guardUserID"}}, &MockDriver{})
			a = withDefaultGuard(t, a, tt.input)

			g, err := a.Guard(tt.guard)
			if (err != nil) != tt.wantErr {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, err)
			}

			if tt.wantErr && err.Error() != tt.wantErrMsg {
				t.Errorf("expected error message %q, got %q", tt.wantErrMsg, err.Error())
			}

			if !tt.wantErr {
				user, err := g.Authenticate(context.Background(), any("creds"))
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if user.UserID() != "guardUserID" {
					t.Errorf("expected user id to be guardUserID, got %s", user.UserID())
				}
			}
		})
	}
}

func TestProvider_Authenticate(t *testing.T) {
	tests := []struct {
		name         string
		userProvider *MockUserProvider
		wantErr      bool
	}{
		{
			name:         "authenticate success",
			userProvider: &MockUserProvider{user: &MockUser{ID: "successID"}},
			wantErr:      false,
		},
		{
			name:         "authenticate failed",
			userProvider: &MockUserProvider{shouldFail: true},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAuth(t, "mock", tt.userProvider, &MockDriver{})
			a = withDefaultGuard(t, a, "mock")

			user, err := a.Authenticate(context.Background(), any("creds"))

			if (err != nil) != tt.wantErr {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, err)
			}
			if !tt.wantErr && user.UserID() != "successID" {
				t.Errorf("expected user id to be successID, got %s", user.UserID())
			}
		})
	}
}

func TestProvider_Login(t *testing.T) {
	tests := []struct {
		name    string
		driver  auth.Driver
		wantErr bool
	}{
		{
			name:    "login success",
			driver:  &MockWithLoginDriver{},
			wantErr: false,
		},
		{
			name:    "login failed",
			driver:  &MockWithLoginDriver{shouldFail: true},
			wantErr: true,
		},
		{
			name:    "login not supported",
			driver:  &MockDriver{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAuth(t, "mock", &MockUserProvider{}, tt.driver)
			a = withDefaultGuard(t, a, "mock")

			_, err := a.Login(context.Background(), &MockUser{})

			if (err != nil) != tt.wantErr {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, err)
			}

			if tt.wantErr && tt.name == "login not supported" && !errors.Is(err, auth.ErrLoginNotSupported) {
				t.Errorf("expected error: %q, got: %q", auth.ErrLoginNotSupported, err)
			}
		})
	}
}

func TestProvider_Check(t *testing.T) {
	tests := []struct {
		name    string
		driver  auth.Driver
		wantErr bool
	}{
		{
			name:    "check success",
			driver:  &MockDriver{},
			wantErr: false,
		},
		{
			name:    "check failed",
			driver:  &MockDriver{shouldFail: true},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAuth(t, "mock", &MockUserProvider{}, tt.driver)
			a = withDefaultGuard(t, a, "mock")

			// TODO: test returned auth.Verified
			_, err := a.Check(context.Background(), &MockUser{})

			if (err != nil) != tt.wantErr {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
