# Interop tests

Cross-verifies the JWT strategy's HS256 tokens against Node's
[`jsonwebtoken`](https://www.npmjs.com/package/jsonwebtoken), proving the tokens
this library issues and accepts are standards-compliant and interoperable with
the Node ecosystem.

## Run

```sh
npm install

# Go signs -> Node verifies
GO_TOKEN=$(go run ./jwt_interop.go)
node -e "const jwt=require('jsonwebtoken'); console.log(jwt.verify(process.argv[1],'shared-secret'))" "$GO_TOKEN"

# Node signs -> Go verifies
NODE_TOKEN=$(node -e "const jwt=require('jsonwebtoken'); process.stdout.write(jwt.sign({sub:'user-2',role:'ops'},'shared-secret'))")
go run ./jwt_interop.go verify "$NODE_TOKEN"
```

## Last verified result (jsonwebtoken@9, Node 22)

```
Go signs -> Node verifies:   NODE_VERIFY_OK {"sub":"user-1","role":"admin"}
Node signs -> Go verifies:   GO_VERIFY_OK sub=user-2 role=ops
Wrong-secret token:          correctly rejected (signature verification failed)
```
