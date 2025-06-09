package main

import (
	"context"
	"fmt"

	"github.com/gelozr/himo/auth2"
)

type User struct {
	ID string
}

type sampleUserProvider struct{}

func (s sampleUserProvider) FindByCredentials(ctx context.Context, c auth2.Credentials) (any, error) {
	return &User{ID: "123"}, nil
}

type sampleDriver struct{}

func (s sampleDriver) Validate(ctx context.Context, payload any) (auth2.Verified[any], error) {
	return auth2.Verified[any]{User: &User{ID: "234"}, Permissions: []string{"*"}}, nil
}

type passwordCredentials struct {
	username string
	password string
}

type typedUserProvider struct{}

func (s typedUserProvider) FindByCredentials(ctx context.Context, c passwordCredentials) (User, error) {
	return User{ID: "123"}, nil
}

type verifiedUser struct {
	user   *User
	claims any
}

type typedDriver struct{}

func (s typedDriver) Validate(ctx context.Context, payload string) (auth2.Verified[User], error) {
	return auth2.Verified[User]{User: User{ID: "234"}}, nil
}

type sessionDriver struct{}

func (s sessionDriver) Validate(ctx context.Context, sessionID string) (auth2.Verified[User], error) {
	return auth2.Verified[User]{User: User{ID: "234"}}, nil
}

func (s sessionDriver) Login(ctx context.Context, user User) (string, error) {
	return "newSession", nil
}

func (s sessionDriver) Logout(ctx context.Context, sessionID string) error {
	return nil
}

func main() {
	auth := auth2.New()
	option := auth2.GuardOption[any, any, any]{
		Driver:       sampleDriver{},
		UserProvider: sampleUserProvider{},
	}

	if err := auth.Extend("test", option); err != nil {
		panic(err)
	}

	user, err := auth.Authenticate(context.Background(), &User{ID: "123"})
	if err != nil {
		panic(err)
	}

	fmt.Println(user)

	typedAuth := auth2.NewDefaultAuth(typedUserProvider{}, typedDriver{})
	user, _ = typedAuth.Authenticate(context.Background(), passwordCredentials{username: "test", password: "test"})

	fmt.Println("typed", user)

	v, _ := typedAuth.Validate(context.Background(), "test")
	fmt.Println("typed", v)

	sessionAuth := auth2.NewSessionAuth(&sessionDriver{}, &typedUserProvider{})
	user, sess, err := sessionAuth.Attempt(context.Background(), passwordCredentials{username: "test", password: "test"})

	fmt.Println("session", user, sess, err)
}
