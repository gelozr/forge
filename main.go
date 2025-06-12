package main

import (
	"context"
	"fmt"
	"log"

	"github.com/gelozr/himo/auth"
)

type User struct {
	ID string
}

type sampleUserProvider struct{}

func (s sampleUserProvider) FindByCredentials(ctx context.Context, c any) (any, error) {
	return &User{ID: "123"}, nil
}

type sampleDriver struct{}

func (s sampleDriver) Validate(ctx context.Context, proof any) (auth.Verified[any], error) {
	return auth.Verified[any]{User: &User{ID: "234"}, Permissions: []string{"*"}}, nil
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

func (s typedDriver) Validate(ctx context.Context, proof string) (auth.Verified[User], error) {
	return auth.Verified[User]{User: User{ID: "234"}}, nil
}

type sessionDriver struct{}

func (s sessionDriver) Validate(ctx context.Context, sessionID string) (auth.Verified[User], error) {
	return auth.Verified[User]{User: User{ID: "234"}}, nil
}

func (s sessionDriver) Login(ctx context.Context, user User) (string, error) {
	return "newSession", nil
}

func (s sessionDriver) Logout(ctx context.Context, sessionID string) error {
	return nil
}

func main() {
	ctx := context.Background()
	a := auth.New()
	option := auth.HandlerOption{
		Driver:       sampleDriver{},
		UserProvider: sampleUserProvider{},
	}

	if err := a.Extend("test", option); err != nil {
		panic(err)
	}

	user, err := auth.Register(ctx, &auth.User{Email: "test", Password: "123456"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(user)

	user, err = auth.Authenticate(ctx, auth.PasswordCredentials{Email: "test", Password: "123456"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(user)

	auth.UseDriver(auth.NewMemorySessionDriver())
	auth.UseUserProvider(auth.NewMemoryUserProvider())

	// token, err := auth.IssueToken(ctx, user)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println(token)

	sess, err := auth.Login(ctx, user)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sess)

	verified, err := auth.Validate(ctx, sess)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(verified.User)

	// user, err = auth.Validate(ctx, token)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	anyUser, err := a.Register(ctx, &auth.User{Email: "test", Password: "test"})
	if err != nil {
		panic(err)
	}
	fmt.Println(anyUser)

	user, err = a.Authenticate(ctx, auth.PasswordCredentials{Email: "test", Password: "test"})
	if err != nil {
		panic(err)
	}
	fmt.Println(user)

	typedAuth := auth.NewBaseAuth(typedUserProvider{}, typedDriver{})
	user, _ = typedAuth.Authenticate(ctx, passwordCredentials{username: "test", password: "test"})

	fmt.Println("typed", user)
	//
	v, _ := typedAuth.Validate(ctx, "test")
	fmt.Println("typed", v)

	sessionAuth := auth.NewSessionAuth(&sessionDriver{}, &typedUserProvider{})
	user, sess, err = sessionAuth.Attempt(ctx, passwordCredentials{username: "test", password: "test"})
	user, err = sessionAuth.Validate(ctx, sess)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("session", user, sess, err)
}
