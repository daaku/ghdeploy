// Package ghook provides functionality to unmarshal a JSON payload including
// verifying the signature for Github Hooks.
package ghook

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	ErrEmptySecret       = errors.New("ghook: empty secret provided")
	ErrHookMisconfigured = errors.New("ghook: hook secret not configured on github")
	ErrInvalidSigPrefix  = errors.New("ghook: invalid signature prefix")
	ErrInvalidSigHex     = errors.New("ghook: invalid signature hex")
	ErrSigMismatch       = errors.New("ghook: signature mismatch")
)

// Unmarshal the hook payload, ensuring it is signed using the provided secret.
func Unmarshal(secret []byte, r *http.Request, v interface{}) error {
	if len(secret) == 0 {
		return ErrEmptySecret
	}

	hubSig := r.Header.Get("X-Hub-Signature")
	if hubSig == "" {
		return ErrHookMisconfigured
	}

	jb, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("ghook: error reading json payload: %w", err)
	}

	const prefix = "sha1="
	if !strings.HasPrefix(hubSig, prefix) {
		return ErrInvalidSigPrefix
	}
	hubSig = hubSig[len(prefix):]

	hubMac, err := hex.DecodeString(hubSig)
	if err != nil {
		return ErrInvalidSigHex
	}

	mac := hmac.New(sha1.New, secret)
	mac.Write(jb)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(hubMac, expectedMAC) {
		return ErrSigMismatch
	}

	// allow passing in nil if we just want to ignore the payload but verify
	// the signature.
	if v == nil {
		return nil
	}

	if err := json.Unmarshal(jb, &v); err != nil {
		return fmt.Errorf("ghook: invalid json: %w", err)
	}
	return nil
}
