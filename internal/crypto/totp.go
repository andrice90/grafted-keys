package crypto

import (
	"crypto/subtle"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const totpPeriod = 30 // seconds

var totpOpts = totp.ValidateOpts{
	Period:    totpPeriod,
	Skew:      0, // we widen the window manually so we can capture the matched step
	Digits:    otp.DigitsSix,
	Algorithm: otp.AlgorithmSHA1,
}

// NewTOTPSecret generates a fresh TOTP secret for account, returning the base32
// secret and the otpauth:// provisioning URI.
func NewTOTPSecret(account string) (secret, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Grafted Secrets",
		AccountName: account,
		Period:      totpPeriod,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// totpCode generates the expected code for secret at time t (used in tests).
func totpCode(secret string, t time.Time) (string, error) {
	return totp.GenerateCodeCustom(secret, t, totpOpts)
}

// ValidateTOTP checks code against secret within a ±1 step window at time now.
// It returns the matched 30s time-step so callers can reject replays
// (steps <= lastStep are refused). step is meaningful only when ok is true.
func ValidateTOTP(secret, code string, now time.Time, lastStep int64) (ok bool, step int64, err error) {
	for _, d := range []int64{-1, 0, 1} {
		t := now.Add(time.Duration(d*totpPeriod) * time.Second)
		want, e := totp.GenerateCodeCustom(secret, t, totpOpts)
		if e != nil {
			return false, 0, e
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			s := t.Unix() / totpPeriod
			if s <= lastStep {
				return false, s, nil // replay / already-used step
			}
			return true, s, nil
		}
	}
	return false, 0, nil
}
