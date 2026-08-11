package oauthstate

import (
	"encoding/base64"
	"strconv"
)

func b64enc(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
func itoa(i int64) string    { return strconv.FormatInt(i, 10) }
