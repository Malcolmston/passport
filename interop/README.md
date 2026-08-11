# Interop tests

Cross-verifies the JWT strategy's HS256 tokens against Node's
[`jsonwebtoken`](https://www.npmjs.com/package/jsonwebtoken), proving the tokens
this library issues and accepts are standards-compliant and interoperable with
the Node ecosystem.

## Automated check — no Node required

`jwt_interop_test.go` pins real tokens produced by `jsonwebtoken@9` as fixtures
and asserts the compatibility properties on every run:

```sh
go test ./...
```

| Property | Assertion |
| --- | --- |
| Node signs → Go verifies | a checked-in jsonwebtoken HS256 token parses, with its claims intact |
| Go signs → Node verifies | for a single-claim payload, our token is **byte-identical** to jsonwebtoken's output |
| Wrong secret | rejected with `ErrSignature` |
| Expired / not-yet-valid | `exp` and `nbf` written by jsonwebtoken are honoured |
| Algorithm confusion | HS512 and `alg: "none"` tokens are rejected with `ErrAlgorithm` |
| Malformed input | non-JWT, two-segment and empty strings yield `ErrMalformed` |

Multi-claim payloads are compared semantically rather than byte for byte: Go's
`encoding/json` emits map keys in alphabetical order while Node preserves
insertion order, so the two encodings differ legitimately while both remain
valid JWTs that either side accepts.

The `exp`/`nbf` fixtures carry the absolute timestamp `2101472177`
(2036-08-04). Past that date the time-claim test skips with a message telling
you to regenerate them rather than failing cryptically.

## Live round trip against Node

To re-verify against a real `jsonwebtoken` install:

```sh
npm install

# Go signs -> Node verifies
GO_TOKEN=$(go run .)
node -e "const jwt=require('jsonwebtoken'); console.log(jwt.verify(process.argv[1],'shared-secret'))" "$GO_TOKEN"

# Node signs -> Go verifies
NODE_TOKEN=$(node -e "const jwt=require('jsonwebtoken'); process.stdout.write(jwt.sign({sub:'user-2',role:'ops'},'shared-secret'))")
go run . verify "$NODE_TOKEN"
```

## Last verified result (jsonwebtoken@9, Node 24)

```
Go signs -> Node verifies:   NODE_VERIFY_OK {"role":"admin","sub":"user-1"}
Node signs -> Go verifies:   GO_VERIFY_OK sub=user-2 role=ops
Wrong-secret token:          correctly rejected (signature verification failed)
```

## Regenerating the fixtures

```sh
node -e 'const j=require("jsonwebtoken");
  console.log(j.sign({sub:"u9"},"shared-secret",{noTimestamp:true}))'
```

`noTimestamp: true` suppresses the automatic `iat` claim so the encoding is
deterministic and safe to check in.
