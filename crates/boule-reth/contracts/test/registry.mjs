// Manual EVM test for Registry.sol against a live reth (NOT a CI test — CI has
// no EL). Validates the contract's storage logic on a real EVM.
//
//   # terminal 1 — a dev reth on the generated genesis (auto-mining):
//   cargo build -p boule-reth            # generates crates/boule-reth/genesis.json
//   reth node --chain crates/boule-reth/genesis.json --datadir /tmp/reth-dev --dev \
//     --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   # terminal 2:
//   cd crates/boule-reth/contracts/test && npm i ethers@6 && node registry.mjs
//
// Exits non-zero on any assertion failure.
import { ethers } from "ethers";

const RPC = process.env.RPC ?? "http://127.0.0.1:8545";
const REGISTRY = "0x0000000000000000000000000000000000000b12";
// boule's SYSTEM account — the only account `recordKey` accepts (see
// src/system_account.rs SYSTEM_ACCOUNT_PRIVATE_KEY; the contract's WRITER is the
// matching SYSTEM_ACCOUNT_ADDRESS). genesis funds it so it can pay gas.
const PK = "0x5005ce11b0017e5750575e11acc011710123456789abcdef0123456789abcdef";
// The genesis-funded dev faucet (Hardhat #0) — a NON-writer, used to prove the
// access-control gate reverts a non-system caller.
const FAUCET_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const ABI = [
  "function recordKey(bytes32 validator, uint64 vEff, bytes key) external",
  "function keyAt(bytes32 validator, uint64 viewNum) external view returns (bytes)",
  "function historyLength(bytes32 validator) external view returns (uint256)",
];

const provider = new ethers.JsonRpcProvider(RPC);
const reg = new ethers.Contract(REGISTRY, ABI, new ethers.Wallet(PK, provider));
const regAsFaucet = new ethers.Contract(REGISTRY, ABI, new ethers.Wallet(FAUCET_PK, provider));

const V = "0x" + "aa".repeat(32);
const k1 = "0x" + "11".repeat(48); // BLS12-381 G1 pubkey, 48 bytes
const k2 = "0x" + "22".repeat(48);

function check(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exit(1); }
  console.log("ok:", msg);
}
async function reverts(fn) {
  try { await (await fn()).wait(); return false; } catch { return true; }
}

// Access control: a non-system caller (the dev faucet) cannot write.
check(await reverts(() => regAsFaucet.recordKey(V, 5, k1)),
  "recordKey from a non-system account reverts (unauthorized)");

await (await reg.recordKey(V, 5, k1)).wait();
await (await reg.recordKey(V, 10, k2)).wait();

check((await reg.historyLength(V)) === 2n, "historyLength == 2 after two records");
check((await reg.keyAt(V, 7)) === k1, "keyAt(7) == k1 (vEff 5 active until 10)");
check((await reg.keyAt(V, 5)) === k1, "keyAt(5) == k1 (boundary inclusive)");
check((await reg.keyAt(V, 12)) === k2, "keyAt(12) == k2");
check((await reg.keyAt(V, 3)) === "0x", "keyAt(3) == empty (before first vEff)");
check((await reg.keyAt("0x" + "bb".repeat(32), 9)) === "0x", "keyAt(unknown) == empty");

let reverted = false;
try { await (await reg.recordKey(V, 10, k1)).wait(); } catch { reverted = true; }
check(reverted, "recordKey with non-increasing vEff reverts");
check((await reg.historyLength(V)) === 2n, "history unchanged after the reverted write");

console.log("ALL REGISTRY EVM TESTS PASSED");
