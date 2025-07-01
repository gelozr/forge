package mail

import (
	"context"
	"errors"
)

type Driver string

const (
	SMTP   = Driver("smtp")
	Custom = Driver("custom")
)

type Mailer interface {
	Send(context.Context, *Message) error
}

type Manager interface {
	Mailer
	RegisterDriver(Driver, Mailer) error
	Mailer(Driver) (Mailer, error)
}

type Address struct {
	Name    string
	Address string
}

type Message struct {
	From    Address
	To      []Address
	Subject string
	HTML    string
	Text    string
	Headers map[string]string
}

type Config struct {
	MailDriver        string
	MailHost          string
	MailPort          int
	MailUser          string
	MailPass          string
	MailSkipTLSVerify bool
}

type manager struct {
	mailers       map[Driver]Mailer
	defaultDriver Driver
}

func NewManager(cfg Config) Manager {
	mailers := make(map[Driver]Mailer)
	mailers[SMTP] = NewSMTPMailer(cfg)

	return &manager{
		mailers:       mailers,
		defaultDriver: getDefaultDriver(cfg),
	}
}

func (m *manager) Mailer(driver Driver) (Mailer, error) {
	if ml, ok := m.mailers[driver]; ok {
		return ml, nil
	}
	return nil, errors.New("mailer not found")
}

func (m *manager) Send(ctx context.Context, msg *Message) error {
	mailer, err := m.Mailer(m.defaultDriver)
	if err != nil {
		return err
	}

	return mailer.Send(ctx, msg)
}

func (m *manager) RegisterDriver(driver Driver, mailer Mailer) error {
	_, ok := m.mailers[driver]
	if ok {
		return errors.New("driver already exists")
	}

	m.mailers[driver] = mailer
	return nil
}

func (m *manager) SetDefaultDriver(driver Driver) error {
	if _, ok := m.mailers[driver]; !ok {
		return errors.New("driver not found")
	}

	m.defaultDriver = driver
	return nil
}

func getDefaultDriver(cfg Config) Driver {
	defaultDriver := SMTP
	if cfg.MailDriver != "" {
		defaultDriver = Driver(cfg.MailDriver)
	}
	return defaultDriver
}
