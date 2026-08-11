package otpauth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// b32 encodes an ASCII shared secret the way the RFCs present it (as raw
// bytes) into the unpadded base32 form a Key carries.
func b32(ascii string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(ascii))
}

// rfc4226Secret is the 20-byte ASCII seed used throughout RFC 4226 Appendix D.
const rfc4226Secret = "12345678901234567890"

// TestHOTPRFC4226Vectors checks Key.CodeAtCounter against the complete
// truncated-value table in RFC 4226 Appendix D.
func TestHOTPRFC4226Vectors(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	k := Key{Type: HOTP, Account: "alice", Secret: b32(rfc4226Secret)}
	for counter, code := range want {
		got, err := k.CodeAtCounter(uint64(counter))
		if err != nil {
			t.Fatalf("counter %d: unexpected error: %v", counter, err)
		}
		if got != code {
			t.Errorf("CodeAtCounter(%d) = %q, want %q", counter, got, code)
		}
	}
}

// TestTOTPRFC6238Vectors checks Key.Code against RFC 6238 Appendix B, which
// covers all three HMAC algorithms at 8 digits. Each algorithm uses a seed of
// its own hash's block-relevant length, exactly as the RFC specifies.
func TestTOTPRFC6238Vectors(t *testing.T) {
	seeds := map[string]string{
		"SHA1":   rfc4226Secret,
		"SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
	}
	times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	want := map[string][]string{
		"SHA1":   {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"},
		"SHA256": {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"},
		"SHA512": {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"},
	}
	for alg, codes := range want {
		k := Key{
			Type:      TOTP,
			Account:   "alice",
			Secret:    b32(seeds[alg]),
			Algorithm: alg,
			Digits:    8,
			Period:    30,
		}
		for i, code := range codes {
			ts := time.Unix(times[i], 0).UTC()
			got, err := k.Code(ts)
			if err != nil {
				t.Fatalf("%s at %d: unexpected error: %v", alg, times[i], err)
			}
			if got != code {
				t.Errorf("%s Code(%d) = %q, want %q", alg, times[i], got, code)
			}
		}
	}
}

// TestVerifyWindow pins the asymmetry between the two OTP types: TOTP tolerates
// drift in both directions, HOTP only looks forward so a counter the server has
// already passed can never be replayed.
func TestVerifyWindow(t *testing.T) {
	totpKey := Key{Type: TOTP, Account: "alice", Secret: b32(rfc4226Secret), Period: 30}
	now := time.Unix(1_000_000_000, 0).UTC()
	step := 30 * time.Second

	prev, err := totpKey.Code(now.Add(-step))
	if err != nil {
		t.Fatal(err)
	}
	next, err := totpKey.Code(now.Add(step))
	if err != nil {
		t.Fatal(err)
	}
	twoAhead, err := totpKey.Code(now.Add(2 * step))
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name   string
		code   string
		window int
		want   bool
	}{
		{"previous step inside window 1", prev, 1, true},
		{"next step inside window 1", next, 1, true},
		{"previous step outside window 0", prev, 0, false},
		{"two steps ahead outside window 1", twoAhead, 1, false},
		{"two steps ahead inside window 2", twoAhead, 2, true},
		{"negative window clamps to strict", prev, -5, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := totpKey.Verify(tt.code, now, tt.window); ok != tt.want {
				t.Errorf("Verify(window=%d) = %v, want %v", tt.window, ok, tt.want)
			}
		})
	}

	// HOTP: the look-ahead accepts counters 5..8 but never counter 4, which
	// the server has already consumed.
	hotpKey := Key{Type: HOTP, Account: "alice", Secret: b32(rfc4226Secret), Counter: 5}
	behind, err := hotpKey.CodeAtCounter(4)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hotpKey.Verify(behind, time.Time{}, 3); ok {
		t.Error("HOTP must never accept a counter behind the stored one (replay)")
	}
	ahead, err := hotpKey.CodeAtCounter(8)
	if err != nil {
		t.Fatal(err)
	}
	matched, ok := hotpKey.Verify(ahead, time.Time{}, 3)
	if !ok || matched != 8 {
		t.Errorf("Verify(ahead) = (%d, %v), want (8, true)", matched, ok)
	}
	if _, ok := hotpKey.Verify(ahead, time.Time{}, 2); ok {
		t.Error("counter 8 is outside a window of 2 from counter 5")
	}
}

// TestVerifyRejectsBadInput covers the paths where Verify must fail closed
// rather than compute a code from nonsense.
func TestVerifyRejectsBadInput(t *testing.T) {
	k := Key{Type: TOTP, Account: "alice", Secret: b32(rfc4226Secret)}
	now := time.Unix(1_000_000_000, 0).UTC()
	good, err := k.Code(now)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name string
		key  Key
		code string
	}{
		{"wrong length", k, good[:5]},
		{"empty code", k, ""},
		{"non-digits", k, "abcdef"},
		{"undecodable secret", Key{Type: TOTP, Secret: "not!base32"}, good},
		{"unknown algorithm", Key{Type: TOTP, Secret: b32(rfc4226Secret), Algorithm: "MD5"}, good},
		{"unknown type", Key{Type: "bogus", Secret: b32(rfc4226Secret)}, good},
		{"missing secret", Key{Type: TOTP}, good},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := tt.key.Verify(tt.code, now, 1); ok {
				t.Error("Verify must reject this input")
			}
		})
	}
}

// TestCodeErrors checks that Code and CodeAtCounter surface a descriptive
// error instead of silently returning an unusable string.
func TestCodeErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		key  Key
		want string
	}{
		{"unknown algorithm", Key{Type: TOTP, Secret: b32(rfc4226Secret), Algorithm: "SHA3"}, "unknown algorithm"},
		{"digits too low", Key{Type: TOTP, Secret: b32(rfc4226Secret), Digits: 4}, "out of range"},
		{"digits too high", Key{Type: TOTP, Secret: b32(rfc4226Secret), Digits: 11}, "out of range"},
		{"negative period", Key{Type: TOTP, Secret: b32(rfc4226Secret), Period: -30}, "must be positive"},
		{"unknown type", Key{Type: "sms", Secret: b32(rfc4226Secret)}, "unknown type"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.key.Code(time.Unix(0, 0))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// TestParseRejectsOutOfRangeParams pins the boundary validation added to Parse:
// a URI carrying a nonsensical digits or period value must be rejected rather
// than producing a Key that cannot generate codes.
func TestParseRejectsOutOfRangeParams(t *testing.T) {
	for _, raw := range []string{
		"otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQ&digits=0",
		"otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQ&digits=-6",
		"otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQ&digits=99",
		"otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQ&period=0",
		"otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQ&period=-30",
		"otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5",
	} {
		if k, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded, giving %+v", raw, k)
		}
	}
}

// TestMovingFactor checks the TOTP time-step derivation, including the
// pre-epoch case where truncating division would round the wrong way.
func TestMovingFactor(t *testing.T) {
	k := Key{Type: TOTP, Secret: b32(rfc4226Secret), Period: 30}
	for _, tt := range []struct {
		unix int64
		want uint64
	}{
		{0, 0},
		{29, 0},
		{30, 1},
		{59, 1},
		{1111111109, 37037036},
	} {
		if got := k.MovingFactor(time.Unix(tt.unix, 0)); got != tt.want {
			t.Errorf("MovingFactor(%d) = %d, want %d", tt.unix, got, tt.want)
		}
	}
	h := Key{Type: HOTP, Secret: b32(rfc4226Secret), Counter: 42}
	if got := h.MovingFactor(time.Now()); got != 42 {
		t.Errorf("HOTP MovingFactor = %d, want the stored counter 42", got)
	}
}
