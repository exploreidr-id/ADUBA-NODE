validate:
	python3 scripts/validate_genesis.py

hash:
	python3 scripts/hash_genesis.py

test:
	cd node && go test ./...

run:
	cd node && go run . -rpc :8080

all: validate test
