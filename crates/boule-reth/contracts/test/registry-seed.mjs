// Manual EVM test for the Registry *genesis seed* (#732 write-path, path B)
// against a live reth (NOT a CI test — CI has no EL). Confirms that the storage
// words `registry::genesis_seed_storage` derives are a valid Solidity
// `mapping(bytes32 => KeyEntry[])` state: a seeded genesis answers
// `keyAt(validator, view)` from block zero, with no transaction.
//
// Generate a seeded genesis whose `alloc[Registry].storage` is the output of
// `genesis_seed_storage_json([(validator, key)])` for:
//   validator = 0xaa..aa (32 bytes), key = 0x11..11 (48 bytes), vEff = 0
// then:
//
//   reth node --chain <seeded-genesis.json> --datadir /tmp/reth-B --dev \
//     --http --http.addr 127.0.0.1 --http.port 8546 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   cd crates/boule-reth/contracts/test && npm i ethers@6
//   RPC=http://127.0.0.1:8546 node registry-seed.mjs
//
// Exits non-zero on any assertion failure.
import { ethers } from "ethers";

const RPC = process.env.RPC ?? "http://127.0.0.1:8546";
const REGISTRY = "0x0000000000000000000000000000000000000b12";

const ABI = [
  "function keyAt(bytes32 validator, uint64 viewNum) external view returns (bytes)",
  "function historyLength(bytes32 validator) external view returns (uint256)",
];

const provider = new ethers.JsonRpcProvider(RPC);
const reg = new ethers.Contract(REGISTRY, ABI, provider);

const V = "0x" + "aa".repeat(32);
const KEY = "0x" + "11".repeat(48);
const UNKNOWN = "0x" + "bb".repeat(32);

// Ground-truth storage words `genesis_seed_storage` derives for (V, KEY, vEff=0).
// These must match the constants pinned in src/registry.rs and what reth loaded.
const EXPECT_STORAGE = {
  "0xd4e804f1354b8536b910364132804434559ef187d3b44e1868ebcf9bee54434b":
    "0x0000000000000000000000000000000000000000000000000000000000000001",
  "0x58fe01d67c0d3b0bdcb10eb4c6d3db43abdb90eae559ad453ab2251865a9f3bd":
    "0x0000000000000000000000000000000000000000000000000000000000000000",
  "0x58fe01d67c0d3b0bdcb10eb4c6d3db43abdb90eae559ad453ab2251865a9f3be":
    "0x0000000000000000000000000000000000000000000000000000000000000061",
  "0xc25886be15ecb57b4bb548a15123446d24bef1a38ef876e5a3e3e7a43ae2cd9a":
    "0x1111111111111111111111111111111111111111111111111111111111111111",
  "0xc25886be15ecb57b4bb548a15123446d24bef1a38ef876e5a3e3e7a43ae2cd9b":
    "0x1111111111111111111111111111111100000000000000000000000000000000",
};

function check(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exit(1); }
  console.log("ok:", msg);
}

// 1. The raw genesis storage words are exactly the derived ones.
for (const [slot, want] of Object.entries(EXPECT_STORAGE)) {
  const got = await provider.getStorage(REGISTRY, slot);
  check(got === want, `storage[${slot}] == ${want} (got ${got})`);
}

// 2. The contract reads its own seeded storage as a valid history.
check((await reg.historyLength(V)) === 1n, "historyLength(V) == 1 from genesis seed");
check((await reg.keyAt(V, 0)) === KEY, "keyAt(V, 0) == seeded BLS key");
check((await reg.keyAt(V, 5)) === KEY, "keyAt(V, 5) == seeded key (vEff 0 still active)");
check((await reg.historyLength(UNKNOWN)) === 0n, "historyLength(unknown) == 0");

console.log("ALL REGISTRY GENESIS-SEED EVM TESTS PASSED");
