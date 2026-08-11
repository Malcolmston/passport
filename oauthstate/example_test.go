package oauthstate_test

import (
	"fmt"
	"time"

	"github.com/malcolmston/passport/oauthstate"
)

// ExampleMemoryStore shows the server-side style: a state is issued before the
// redirect and consumed exactly once on the callback, so a replayed callback
// cannot succeed.
func ExampleMemoryStore() {
	store := oauthstate.NewMemoryStore(10 * time.Minute)

	// Before redirecting: remember where the user was headed.
	state, err := store.Issue("/dashboard")
	if err != nil {
		panic(err)
	}

	// On the callback: consume the state and recover the payload.
	returnTo, err := store.Verify(state)
	fmt.Println("return to:", returnTo, "err:", err)

	// A second callback with the same state is rejected.
	_, err = store.Verify(state)
	fmt.Println("replay:", err)

	// So is a state we never issued.
	_, err = store.Verify("made-up")
	fmt.Println("forged:", err)
	// Output:
	// return to: /dashboard err: <nil>
	// replay: oauthstate: unknown or expired state
	// forged: oauthstate: unknown or expired state
}

// ExampleHMACStore shows the stateless style, which needs no server storage and
// therefore works across restarts and multiple instances sharing the key.
func ExampleHMACStore() {
	store := oauthstate.NewHMACStore([]byte("a-32-byte-or-longer-secret-key!!"), 5*time.Minute)

	state, err := store.Issue("/settings")
	if err != nil {
		panic(err)
	}

	returnTo, err := store.Verify(state)
	fmt.Println("return to:", returnTo, "err:", err)

	// Tampering with the payload invalidates the signature.
	_, err = store.Verify(state + "x")
	fmt.Println("tampered:", err)
	// Output:
	// return to: /settings err: <nil>
	// tampered: oauthstate: signature mismatch
}

// ExampleMemoryStore_Sweep shows explicit expiry collection, for callers that
// want a predictable schedule rather than the amortized sweeping Issue does.
func ExampleMemoryStore_Sweep() {
	store := oauthstate.NewMemoryStore(time.Nanosecond)
	for i := 0; i < 3; i++ {
		if _, err := store.Issue(""); err != nil {
			panic(err)
		}
	}
	time.Sleep(time.Millisecond)

	fmt.Println("swept:", store.Sweep())
	fmt.Println("remaining:", store.Len())
	// Output:
	// swept: 3
	// remaining: 0
}
