// Manual EVM test for the Registry *genesis seed* (#732 write-path, path B)
// against a live reth (NOT a CI test — CI has no EL). Confirms that the storage
// words `registry::genesis_seed_storage` derives are a valid Solidity
// `mapping(bytes32 => KeyEntry[])` state: a seeded genesis answers
// `keyAt(validator, view)` from block zero, with no transaction.
//
// Generate a seeded genesis whose `alloc[Registry].storage` is the output of
// `genesis_seed_storage_json([(validator, key)])` for:
//   validator = 0xaa..aa (32 bytes), key = bls_pk(0x11) stored as its 128-byte
//   EIP-2537 uncompressed G1 form (what Slashing.sol requires), vEff = 0
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
// The 128-byte EIP-2537 G1 form of bls_pk(0x11) — what genesis_seed_storage now
// stores (and what Slashing.sol's `key.length == 128` requires). Equals the four
// chunk values below concatenated.
const KEY =
  "0x" +
  "00000000000000000000000000000000053e87ed8d0b6db42de10e966b4f6ed2" +
  "60fc862e31b768a640146a98560344386bb80f26a13943a0661deeba63022467" +
  "000000000000000000000000000000000c3d247b33dabb2b51fc5c740da52780" +
  "6a7be5b8d3a7f0fd0487b2d7d3c7b2291839679f7b2ceb15072e46a85cfe1552";
const UNKNOWN = "0x" + "bb".repeat(32);

// Ground-truth storage words `genesis_seed_storage` derives for (V, KEY, vEff=0).
// These must match the constants pinned in src/registry.rs and what reth loaded.
// 128 bytes -> long-form header (2*128+1 = 0x101) + 4 data chunks.
const EXPECT_STORAGE = {
  "0xd4e804f1354b8536b910364132804434559ef187d3b44e1868ebcf9bee54434b":
    "0x0000000000000000000000000000000000000000000000000000000000000001",
  "0x58fe01d67c0d3b0bdcb10eb4c6d3db43abdb90eae559ad453ab2251865a9f3bd":
    "0x0000000000000000000000000000000000000000000000000000000000000000",
  "0x58fe01d67c0d3b0bdcb10eb4c6d3db43abdb90eae559ad453ab2251865a9f3be":
    "0x0000000000000000000000000000000000000000000000000000000000000101",
  "0xc25886be15ecb57b4bb548a15123446d24bef1a38ef876e5a3e3e7a43ae2cd9a":
    "0x00000000000000000000000000000000053e87ed8d0b6db42de10e966b4f6ed2",
  "0xc25886be15ecb57b4bb548a15123446d24bef1a38ef876e5a3e3e7a43ae2cd9b":
    "0x60fc862e31b768a640146a98560344386bb80f26a13943a0661deeba63022467",
  "0xc25886be15ecb57b4bb548a15123446d24bef1a38ef876e5a3e3e7a43ae2cd9c":
    "0x000000000000000000000000000000000c3d247b33dabb2b51fc5c740da52780",
  "0xc25886be15ecb57b4bb548a15123446d24bef1a38ef876e5a3e3e7a43ae2cd9d":
    "0x6a7be5b8d3a7f0fd0487b2d7d3c7b2291839679f7b2ceb15072e46a85cfe1552",
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
