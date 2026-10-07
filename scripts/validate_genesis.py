#!/usr/bin/env python3
import json
from pathlib import Path
p=Path("genesis/testnet/genesis.json")
d=json.loads(p.read_text())
assert d["chain_id"]=="aduba-testnet-1"
assert d["native_asset"]["symbol"]=="ADU"
assert d["native_asset"]["decimals"]==18
print("genesis: OK")
