// Manual EVM test for the Slashing predeploy against a live reth (NOT a CI test
// — CI has no EL). Proves the full equivocation path in-EVM: record a
// validator's BLS key in the Registry (#732a), then submit two `Vote`s for the
// same view but different blocks to the Slashing predeploy (#732b); it verifies
// both signatures against the registry key via the EIP-2537 precompiles and
// emits `Slashed`. Negatives (same block, or a signature that does not match its
// block) must revert.
//
//   # 1. ground-truth vectors from boule's blst -> /tmp/slvecs.txt:
//   cargo test -p boule-consensus gen_slashing_vectors -- --nocapture --ignored \
//     | grep '^SL_' > /tmp/slvecs.txt
//   # 2. a dev Prague reth (EIP-2537 precompiles) on the generated genesis
//   #    (seeds the Registry at …b12 and Slashing at …b13):
//   cargo build -p boule-reth
//   reth node --chain crates/boule-reth/genesis.json --datadir /tmp/reth-dev --dev \
//     --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   # 3. run:
//   cd crates/boule-reth/contracts/test && npm i ethers@6 && node slashing.mjs
import { ethers } from "ethers";
import { readFileSync } from "fs";

const RPC = process.env.RPC ?? "http://127.0.0.1:8545";
// reth --dev funds this account (the standard dev key) — used to call the
// permissionless Slashing predeploy.
const PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// boule's SYSTEM account — the only account `Registry.recordKey` accepts (its
// WRITER; see src/system_account.rs). The registry write below must come from it.
const SYSTEM_PK = "0x5005ce11b0017e5750575e11acc011710123456789abcdef0123456789abcdef";
const REGISTRY = "0x0000000000000000000000000000000000000b12"; // #732a registry predeploy
const SLASHING = "0x0000000000000000000000000000000000000b13"; // #732b slashing predeploy

const v = Object.fromEntries(
  readFileSync(process.env.VECS ?? "/tmp/slvecs.txt", "utf8").trim().split("\n").map((l) => l.split("=")),
);
const h = (k) => "0x" + v[k];
const validator = h("SL_VALIDATOR");
const chainId = h("SL_CHAINID");
const view = BigInt(v.SL_VIEW);
const blockA = h("SL_BLOCKA"), blockB = h("SL_BLOCKB");
const sigA = h("SL_SIGA"), sigB = h("SL_SIGB");
const pubkey = h("SL_PUBKEY");

const provider = new ethers.JsonRpcProvider(RPC);
const wallet = new ethers.Wallet(PK, provider);
const systemWallet = new ethers.Wallet(SYSTEM_PK, provider);

// 1. record the validator's BLS key in the Registry at this view (so the
//    slashing predeploy's `keyAt(validator, view)` returns it). recordKey is
//    access-controlled, so it must be signed by the SYSTEM account (the WRITER).
const reg = new ethers.Contract(REGISTRY, [
  "function recordKey(bytes32,uint64,bytes) external",
  "function keyAt(bytes32,uint64) view returns (bytes)",
  "function recordSettled(uint64) external",
  "function settledView() view returns (uint64)",
], systemWallet);
await (await reg.recordKey(validator, view, pubkey)).wait();
assert(await reg.keyAt(validator, view) === pubkey, "registry keyAt == recorded pubkey");

// Settled-frontier gate (#732): the slashing predeploy only accepts a proof for
// `view <= settledView`. Advance the frontier *to exactly `view`* so the proof
// below (at the frontier) passes, while a proof for `view + 1` (above it) is
// rejected. recordSettled is WRITER-gated, so the SYSTEM account submits it.
await (await reg.recordSettled(view)).wait();
assert((await reg.settledView()) === view, "settledView advanced to the proof view");

// 2. the slashing predeploy at its fixed genesis address.
const sl = new ethers.Contract(SLASHING, [
  "function submitEquivocation(bytes32,bytes,uint64,bytes32,bytes,bytes32,bytes) external",
  "event Slashed(bytes32 indexed validator, uint64 viewNum, bytes32 blockA, bytes32 blockB)",
], wallet);

// 3. a valid equivocation -> emits Slashed(validator, view, blockA, blockB).
const rcpt = await (await sl.submitEquivocation(validator, chainId, view, blockA, sigA, blockB, sigB)).wait();
const ev = rcpt.logs.map((l) => { try { return sl.interface.parseLog(l); } catch { return null; } })
  .find((x) => x && x.name === "Slashed");
assert(!!ev && ev.args.validator === validator && ev.args.viewNum === view, "valid equivocation -> Slashed emitted");

// 4. negatives must revert.
assert(await reverts(() => sl.submitEquivocation(validator, chainId, view, blockA, sigA, blockA, sigA)),
  "same-block (not an equivocation) reverts");
assert(await reverts(() => sl.submitEquivocation(validator, chainId, view, blockA, sigB, blockB, sigA)),
  "swapped sigs (don't match blocks) revert");

// 5. settled-frontier gate (#732): a proof for a view ABOVE the frontier must
//    revert with "view not settled" — even though the registry HAS a key there
//    (we record one at view+1 first), proving the gate, not a missing key, is
//    what rejects it. The watcher resubmits once recordSettled advances.
const above = view + 1n;
await (await reg.recordKey(validator, above, pubkey)).wait(); // key exists at view+1
assert((await sl.submitEquivocation(validator, chainId, above, blockA, sigA, blockB, sigB)
  .then(() => false, (e) => String(e).includes("view not settled"))),
  "view above settledFrontier reverts with 'view not settled'");

// 6. once the frontier advances to cover it, the same above-frontier view is
//    accepted (the gate is the only thing that was blocking it).
await (await reg.recordSettled(above)).wait();
// NOTE: sigA/sigB are over `view`, not `above`, so this would fail signature
// verification — we only assert the gate no longer reverts with "view not settled".
assert(!(await sl.submitEquivocation(validator, chainId, above, blockA, sigA, blockB, sigB)
  .then(() => false, (e) => String(e).includes("view not settled"))),
  "after recordSettled(view+1), the frontier no longer rejects view+1");

console.log("ALL SLASHING EVM TESTS PASSED");

function assert(cond, label) {
  console.log(`${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) process.exitCode = 1;
}
async function reverts(fn) {
  try { await (await fn()).wait(); return false; } catch { return true; }
}
