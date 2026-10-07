#!/usr/bin/env python3
import hashlib, pathlib
p = pathlib.Path("genesis/testnet/genesis.json")
print(hashlib.sha256(p.read_bytes()).hexdigest())
