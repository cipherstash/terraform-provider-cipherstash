package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/invopop/validation"
)

// AccessKey binds a parsed credential to the role required when exchanging it.
// Parsing checks syntax; only a verified CTS token proves the credential's role.
// The interface is sealed: use ControlAccessKey, AdminAccessKey or MemberAccessKey.
type AccessKey interface {
	Validate() error
	secret() string
	requiredRole() string
}

// ControlAccessKey requires Control or, for compatibility, Admin permission.
type ControlAccessKey struct{ controlSecret string }

// AdminAccessKey requires Admin permission.
type AdminAccessKey struct{ adminSecret string }

// MemberAccessKey requires Member permission; Admin is not a substitute.
type MemberAccessKey struct{ memberSecret string }

func ParseControlAccessKey(value string) (ControlAccessKey, error) {
	if err := validateAccessKey(value); err != nil {
		return ControlAccessKey{}, err
	}

	return ControlAccessKey{controlSecret: value}, nil
}

func ParseAdminAccessKey(value string) (AdminAccessKey, error) {
	if err := validateAccessKey(value); err != nil {
		return AdminAccessKey{}, err
	}

	return AdminAccessKey{adminSecret: value}, nil
}

func ParseMemberAccessKey(value string) (MemberAccessKey, error) {
	if err := validateAccessKey(value); err != nil {
		return MemberAccessKey{}, err
	}

	return MemberAccessKey{memberSecret: value}, nil
}

func validateAccessKey(value string) error {
	credential, found := strings.CutPrefix(value, "CSAK")
	if !found {
		return errors.New("CipherStash access key must have the CSAK prefix")
	}

	id, secret, found := strings.Cut(credential, ".")
	if !found || id == "" || secret == "" {
		return errors.New("CipherStash access key must contain an ID and secret separated by a dot")
	}

	return nil
}

func (k ControlAccessKey) Validate() error {
	return validation.Validate(k.controlSecret, validation.Required)
}

func (k AdminAccessKey) Validate() error {
	return validation.Validate(k.adminSecret, validation.Required)
}

func (k MemberAccessKey) Validate() error {
	return validation.Validate(k.memberSecret, validation.Required)
}

func (k *ControlAccessKey) EnvDecode(_ context.Context, value string) error {
	parsed, err := ParseControlAccessKey(value)
	if err != nil {
		return err
	}

	*k = parsed

	return nil
}

func (k *AdminAccessKey) EnvDecode(_ context.Context, value string) error {
	parsed, err := ParseAdminAccessKey(value)
	if err != nil {
		return err
	}

	*k = parsed

	return nil
}

func (k *MemberAccessKey) EnvDecode(_ context.Context, value string) error {
	parsed, err := ParseMemberAccessKey(value)
	if err != nil {
		return err
	}

	*k = parsed

	return nil
}

// Format redacts the credential for every fmt verb, including in logs.
func (ControlAccessKey) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "auth.ControlAccessKey(***)")
}

func (AdminAccessKey) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "auth.AdminAccessKey(***)")
}

func (MemberAccessKey) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "auth.MemberAccessKey(***)")
}

func (k ControlAccessKey) secret() string     { return k.controlSecret }
func (k AdminAccessKey) secret() string       { return k.adminSecret }
func (k MemberAccessKey) secret() string      { return k.memberSecret }
func (ControlAccessKey) requiredRole() string { return "control" }
func (AdminAccessKey) requiredRole() string   { return "admin" }
func (MemberAccessKey) requiredRole() string  { return "member" }
