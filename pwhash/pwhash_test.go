package pwhash

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// RFC 6070 PBKDF2-HMAC-SHA1 test vectors.
func TestKeyRFC6070(t *testing.T) {
	tests := []struct {
		password, salt string
		iter, keyLen   int
		want           string
	}{
		{"password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
		{"pass\x00word", "sa\x00lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"},
	}
	for i, tt := range tests {
		got := Key([]byte(tt.password), []byte(tt.salt), tt.iter, tt.keyLen, sha1.New)
		if hex.EncodeToString(got) != tt.want {
			t.Errorf("vector %d: got %x, want %s", i, got, tt.want)
		}
	}
}

// A widely-cited PBKDF2-HMAC-SHA256 vector.
func TestKeySHA256(t *testing.T) {
	got := Key([]byte("password"), []byte("salt"), 1, 32, sha256.New)
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if hex.EncodeToString(got) != want {
		t.Errorf("got %x, want %s", got, want)
	}
}

func TestHashAndVerify(t *testing.T) {
	// Small iteration count keeps the test fast; the algorithm is identical.
	p := Params{Algorithm: SHA256, Iterations: 1000, SaltLength: 16, KeyLength: 32}
	enc, err := HashWithParams("hunter2", p)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify("hunter2", enc)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Verify should accept the correct password")
	}
	ok, err = Verify("wrong", enc)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("Verify should reject the wrong password")
	}
}

func TestHashSaltIsRandom(t *testing.T) {
	a, _ := HashWithParams("same", Params{Iterations: 10})
	b, _ := HashWithParams("same", Params{Iterations: 10})
	if a == b {
		t.Error("two hashes of the same password must differ due to random salt")
	}
}

func TestDecode(t *testing.T) {
	p := Params{Algorithm: SHA1, Iterations: 123, SaltLength: 8, KeyLength: 20}
	enc, _ := HashWithParams("pw", p)
	alg, iter, salt, dk, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if alg != SHA1 || iter != 123 || len(salt) != 8 || len(dk) != 20 {
		t.Errorf("Decode = %v %d %d %d", alg, iter, len(salt), len(dk))
	}
}

func TestDecodeErrors(t *testing.T) {
	cases := []string{
		"not-a-hash",
		"pbkdf2_sha256$notanumber$c2FsdA$ZGs",
		"pbkdf2_md5$1$c2FsdA$ZGs",
		"pbkdf2_sha256$1$!!!$ZGs",
	}
	for _, c := range cases {
		if _, _, _, _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q) should error", c)
		}
	}
	if _, err := Verify("x", "garbage"); err == nil {
		t.Error("Verify on garbage should error")
	}
}

func TestUnknownAlgorithm(t *testing.T) {
	if _, err := HashWithParams("x", Params{Algorithm: Algorithm("md5")}); err != ErrUnknownAlgorithm {
		t.Errorf("err = %v, want ErrUnknownAlgorithm", err)
	}
}

func BenchmarkKeySHA256(b *testing.B) {
	salt := []byte("benchmark-salt")
	for i := 0; i < b.N; i++ {
		_ = Key([]byte("password"), salt, 1000, 32, sha256.New)
	}
}
