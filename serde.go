package passport

import (
	"errors"
	"fmt"
	"net/http"
)

// This file ports the multi-layer serializer / deserializer / auth-info
// transformer chains from Passport.js's Authenticator (jaredhanson/passport,
// lib/authenticator.js). Passport.js lets an application register *several*
// serializers, deserializers, and info transformers; each layer may handle the
// value, defer to the next layer, invalidate the session, or fail. The
// single-function SerializeUser / DeserializeUser setters remain the common
// case; the chain API below adds the full upstream behaviour and is used by
// Serialize / Deserialize / TransformAuthInfo when one or more layers are
// registered (falling back to the single functions otherwise).

// ErrPass is the sentinel a serializer, deserializer, or info transformer
// returns to decline the current value and defer to the next layer in the
// chain. It mirrors Passport.js's convention of calling done('pass'): the
// error is not propagated, it merely advances to the next registered layer.
var ErrPass = errors.New("passport: pass to next layer")

// ErrFailedToSerialize is returned by Serialize when no registered serializer
// produced a session value. The message matches Passport.js verbatim.
var ErrFailedToSerialize = errors.New("Failed to serialize user into session")

// ErrFailedToDeserialize is returned by Deserialize when no registered
// deserializer produced a user or a session-invalidation signal. The message
// matches Passport.js verbatim.
var ErrFailedToDeserialize = errors.New("Failed to deserialize user out of session")

// invalidateSentinel is the concrete type of Invalidate.
type invalidateSentinel struct{}

// Invalidate is the sentinel a deserializer returns to signal that the stored
// session is no longer valid and the user should be logged out. It corresponds
// to a Passport.js deserializer calling done(null, false) or done(null, null):
// Deserialize reports it back as the boolean value false (Passport.js's
// invalidation marker) with a nil error.
var Invalidate any = invalidateSentinel{}

// Serializer reduces a user to a value stored in the session. Returning ErrPass
// defers to the next serializer; returning any other error aborts the chain;
// returning a "falsy" value (nil, false, or the empty string) also defers to
// the next serializer. The integer 0 is treated as a valid serialized value,
// matching Passport.js's obj === 0 special case. The request is supplied for
// request-scoped serializers and may be nil.
type Serializer func(user any, r *http.Request) (id any, err error)

// Deserializer reconstructs a user from a session value. Returning ErrPass
// defers to the next deserializer; returning any other error aborts the chain;
// returning Invalidate (or the boolean false) signals session invalidation;
// returning nil (with a nil error) defers to the next deserializer. The request
// is supplied for request-scoped deserializers and may be nil.
type Deserializer func(id any, r *http.Request) (user any, err error)

// InfoTransformer converts the raw auth-info object attached by a strategy into
// an application-facing value. Returning ErrPass or a nil value defers to the
// next transformer; if every transformer defers, the original info is returned
// unchanged. Returning any other error aborts the chain.
type InfoTransformer func(info any, r *http.Request) (out any, err error)

// AddSerializer appends a serializer to the chain (Passport.js's
// serializeUser(fn)). Layers are consulted in registration order by Serialize.
func (p *Passport) AddSerializer(fn Serializer) *Passport {
	p.serializers = append(p.serializers, fn)
	return p
}

// AddDeserializer appends a deserializer to the chain (Passport.js's
// deserializeUser(fn)). Layers are consulted in registration order by
// Deserialize.
func (p *Passport) AddDeserializer(fn Deserializer) *Passport {
	p.deserializers = append(p.deserializers, fn)
	return p
}

// AddInfoTransformer appends an auth-info transformer to the chain
// (Passport.js's transformAuthInfo(fn)).
func (p *Passport) AddInfoTransformer(fn InfoTransformer) *Passport {
	p.infoTransformers = append(p.infoTransformers, fn)
	return p
}

// serializeTruthy reports whether v counts as a serialized session value under
// Passport.js's rule `if (err || obj || obj === 0)`. In JavaScript the falsy
// values false, null, undefined and "" cause the chain to continue, while 0 is
// explicitly rescued as valid. Every other value is accepted.
func serializeTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	default:
		return true
	}
}

// Serialize runs the registered serializer chain for user and returns the
// value to store in the session. When no serializers have been registered it
// falls back to the single function set via SerializeUser. It reproduces
// Passport.js Authenticator#serializeUser: layers are tried in order, ErrPass
// (done('pass')) advances to the next layer, a falsy result advances to the
// next layer, the first truthy result (or 0) wins, and an exhausted chain
// yields ErrFailedToSerialize. A panic in a layer is recovered and returned as
// an error, mirroring the upstream try/catch. r may be nil.
func (p *Passport) Serialize(user any, r *http.Request) (id any, err error) {
	if len(p.serializers) == 0 {
		if p.serialize != nil {
			return p.serialize(user)
		}
		return nil, ErrFailedToSerialize
	}
	for _, layer := range p.serializers {
		v, lerr := callSerializer(layer, user, r)
		if errors.Is(lerr, ErrPass) {
			continue
		}
		if lerr != nil {
			return nil, lerr
		}
		if serializeTruthy(v) {
			return v, nil
		}
	}
	return nil, ErrFailedToSerialize
}

func callSerializer(layer Serializer, user any, r *http.Request) (v any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			v, err = nil, panicErr(rec)
		}
	}()
	return layer(user, r)
}

// Deserialize runs the registered deserializer chain for id and returns the
// reconstructed user. When no deserializers have been registered it falls back
// to the single function set via DeserializeUser. It reproduces Passport.js
// Authenticator#deserializeUser: ErrPass advances to the next layer, a truthy
// value is returned as the user, Invalidate or false yields (false, nil) to
// signal that the session should be invalidated, nil advances to the next
// layer, and an exhausted chain yields ErrFailedToDeserialize. A panic in a
// layer is recovered and returned as an error. r may be nil.
func (p *Passport) Deserialize(id any, r *http.Request) (user any, err error) {
	if len(p.deserializers) == 0 {
		if p.deserialize != nil {
			sid, _ := id.(string)
			return p.deserialize(sid, r)
		}
		return nil, ErrFailedToDeserialize
	}
	for _, layer := range p.deserializers {
		v, lerr := callDeserializer(layer, id, r)
		if errors.Is(lerr, ErrPass) {
			continue
		}
		if lerr != nil {
			return nil, lerr
		}
		if isInvalidate(v) {
			return false, nil
		}
		if isTruthyUser(v) {
			return v, nil
		}
		// nil / undefined: advance to the next layer.
	}
	return nil, ErrFailedToDeserialize
}

func callDeserializer(layer Deserializer, id any, r *http.Request) (v any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			v, err = nil, panicErr(rec)
		}
	}()
	return layer(id, r)
}

// isTruthyUser reports whether a deserialized value is a usable user under
// Passport.js's rule `if (err || user)`: any value except nil, false and "".
func isTruthyUser(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	default:
		return true
	}
}

// isInvalidate reports whether a deserialized value is the session-invalidation
// signal, corresponding to Passport.js's `if (user === null || user === false)`.
func isInvalidate(v any) bool {
	if v == Invalidate {
		return true
	}
	if b, ok := v.(bool); ok {
		return !b
	}
	return false
}

// TransformAuthInfo runs the registered auth-info transformer chain over info.
// With no transformers registered it returns info unchanged (Passport.js's
// default identity behaviour). Otherwise layers are tried in order: ErrPass or
// a nil result advances to the next layer, the first non-nil result wins, and
// if every layer defers the original info is returned. r may be nil.
func (p *Passport) TransformAuthInfo(info any, r *http.Request) (out any, err error) {
	for _, layer := range p.infoTransformers {
		v, lerr := callInfoTransformer(layer, info, r)
		if errors.Is(lerr, ErrPass) {
			continue
		}
		if lerr != nil {
			return nil, lerr
		}
		if v != nil {
			return v, nil
		}
	}
	return info, nil
}

func callInfoTransformer(layer InfoTransformer, info any, r *http.Request) (v any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			v, err = nil, panicErr(rec)
		}
	}()
	return layer(info, r)
}

// panicErr converts a recovered panic value into an error, preserving an
// existing error value's message.
func panicErr(rec any) error {
	if e, ok := rec.(error); ok {
		return e
	}
	return fmt.Errorf("%v", rec)
}
