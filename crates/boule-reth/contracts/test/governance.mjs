// Manual EVM test for Governance.sol against a live reth (NOT a CI test — CI has
// no EL). Validates the contract's **in-EVM BLS-authenticated**, stake-weighted,
// validator-gated approval tally (#729 + #764) on a real EVM. The #764 fix binds
// each approval to the validator's own BLS signature over a domain-separated,
// replay-bound digest, verified in-EVM via BlsVerify against Registry.keyAt — so
// the old forged-quorum attack (name every real validator id and forge a ⅔
// supermajority) is closed. This harness seeds a weight distribution AND each
// validator's BLS key via the system account, then proves:
//   (a) a valid BLS-signed approval by a seated validator counts;
//   (b) a forged / bad BLS signature is rejected (reverts);
//   (c) naming a validator you have NO signature for fails — the forged-quorum
//       attack is closed (an attacker cannot accrue a validator's weight);
//   (d) a non-seated (weightOf==0) caller is rejected (reverts);
//   (e) crossing the ⅔ weight threshold (with valid signatures) emits Approved
//       exactly once carrying the exact command;
//   (f) the same validator voting twice does not double-count.
//
//   # 1. a dev Prague reth (EIP-2537 precompiles) on the generated genesis:
//   export SOLC=~/.solcx/solc-v0.8.24
//   cargo build -p boule-reth            # generates crates/boule-reth/genesis.json
//   cargo build -p boule-consensus --bin bls-sign   # the BLS signer this harness shells out to
//   reth node --chain crates/boule-reth/genesis.json --datadir /tmp/reth-gov --dev \
//     --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   # 2:
//   cd crates/boule-reth/contracts/test && npm i ethers@6 && node governance.mjs
//
// Exits non-zero on any assertion failure.
import { ethers } from "ethers";
import { execFileSync } from "node:child_process";

const RPC = process.env.RPC ?? "http://127.0.0.1:8545";
const GOVERNANCE = "0x0000000000000000000000000000000000000b14";
const REGISTRY = "0x0000000000000000000000000000000000000b12";
// Path to the compiled bls-sign helper (boule-consensus bin). Override with BLS_SIGN.
const BLS_SIGN = process.env.BLS_SIGN ??
  "../../../../target/debug/bls-sign";

// boule's SYSTEM account — the only account Registry.recordWeight/recordKey/
// recordSettled accept (the WRITER gate; see src/system_account.rs). Used to seat
// the weight distribution AND each validator's BLS key.
const SYS_PK = "0x5005ce11b0017e5750575e11acc011710123456789abcdef0123456789abcdef";
// The genesis-funded dev faucet (Hardhat #0) — any funded account can relay an
// approval (#764 makes msg.sender irrelevant: the gate is the validator's BLS
// signature over the digest, not the tx signer).
const PK0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const GOV_ABI = [
  "function approve(bytes32 proposalId, bytes reconfigCommand, bytes32 validator, bytes blsSig) external",
  "function approveDigest(bytes32 proposalId, bytes32 validator) external view returns (bytes32)",
  "function approvals(bytes32 proposalId) external view returns (uint64)",
  "function isApproved(bytes32 proposalId) external view returns (bool)",
  "event Approved(bytes32 indexed proposalId, bytes reconfigCommand)",
];
const REG_ABI = [
  "function recordWeight(bytes32 validator, uint64 newWeight) external",
  "function recordKey(bytes32 validator, uint64 vEff, bytes key) external",
  "function recordSettled(uint64 viewNum) external",
  "function settledView() external view returns (uint64)",
  "function keyAt(bytes32 validator, uint64 viewNum) external view returns (bytes)",
  "function weightOf(bytes32 validator) external view returns (uint64)",
  "function totalWeight() external view returns (uint64)",
];

const provider = new ethers.JsonRpcProvider(RPC);
// NonceManager: the --dev node mines asynchronously, so back-to-back txs from one
// account would otherwise race on the pending nonce.
const wSys = new ethers.NonceManager(new ethers.Wallet(SYS_PK, provider));
const w0 = new ethers.NonceManager(new ethers.Wallet(PK0, provider));
const reg = new ethers.Contract(REGISTRY, REG_ABI, wSys);
const gov = new ethers.Contract(GOVERNANCE, GOV_ABI, w0);

// --- bls-sign helper -----------------------------------------------------
// Each validator is bound to a one-byte key seed; bls-sign derives the boule BLS
// keypair from it and emits the EIP-2537 pubkey / signature the in-EVM BlsVerify
// path consumes. The pubkey seeds Registry.keyAt; the signature is over the
// exact digest the contract reconstructs.
function blsPubkey(seed) {
  const out = execFileSync(BLS_SIGN, ["--seed", String(seed)], { encoding: "utf8" });
  return "0x" + out.match(/^PUBKEY=([0-9a-f]+)$/m)[1];
}
function blsSign(seed, digestHex) {
  const out = execFileSync(BLS_SIGN, ["--seed", String(seed), "--msg", digestHex],
    { encoding: "utf8" });
  return "0x" + out.match(/^SIG=([0-9a-f]+)$/m)[1];
}

function check(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exit(1); }
  console.log("ok:", msg);
}
// Run a call expected to revert; reset `signer`'s managed nonce afterward so a tx
// that never lands on-chain doesn't leave a gap for the next send.
async function reverts(fn, signer) {
  try { await (await fn()).wait(); return false; }
  catch { if (signer) signer.reset(); return true; }
}
function approvedCount(receipt, proposalId) {
  const topic0 = ethers.id("Approved(bytes32,bytes)");
  return receipt.logs.filter(
    (l) => l.address.toLowerCase() === GOVERNANCE.toLowerCase() &&
           l.topics[0] === topic0 && l.topics[1] === proposalId,
  ).length;
}

// proposalId = keccak256 of the (opaque) reconfig command — boule's binding. A
// fresh command per run so reruns start from an untouched proposalId tally.
const cmd = "0x" + Buffer.from("RECFG-add-validator-0xbeef-" + Date.now()).toString("hex");
const proposalId = ethers.keccak256(cmd);

// Distinct validator ids (fresh per run so reruns start from zero weight). Four
// equal-weight (25) seated validators -> our totalWeight contribution 100; the ⅔
// supermajority is weight*3 > total*2, first crossed at the 3rd vote (75). Each
// validator is bound to a distinct BLS key seed. A fifth id is never seated.
const tag = Date.now().toString(16).padStart(16, "0");
const vid = (b) => "0x" + b.repeat(2).padEnd(48, "0") + tag;
const VA = { id: vid("a1"), seed: 0xa1 }; // weight 25
const VB = { id: vid("b2"), seed: 0xb2 }; // weight 25
const VC = { id: vid("c3"), seed: 0xc3 }; // weight 25 (A+B+C = 75 -> crosses ⅔)
const VD = { id: vid("d4"), seed: 0xd4 }; // weight 25 (seated but unused)
const VUNSEATED = { id: vid("ff"), seed: 0xff }; // never seated -> weightOf == 0
const SEATED = [VA, VB, VC, VD];

// --- Seat weights AND BLS keys via the system account --------------------
// Record each validator's BLS key at vEff 0 so keyAt(v, settledView()) returns
// it; settledView starts at 0 (genesis frontier) so no recordSettled is needed,
// but assert it to make the key-view choice explicit.
const total0 = await reg.totalWeight();
for (const v of SEATED) {
  await (await reg.recordWeight(v.id, 25n)).wait();
  await (await reg.recordKey(v.id, 0n, blsPubkey(v.seed))).wait();
}
const total = await reg.totalWeight();
check(total === total0 + 100n, "totalWeight seeded: base + 4*25");
check((await reg.weightOf(VA.id)) === 25n, "weightOf(VA) == 25");
check((await reg.weightOf(VUNSEATED.id)) === 0n, "weightOf(VUNSEATED) == 0 (non-seated)");
check((await reg.settledView()) === 0n, "settledView == 0 (genesis frontier; keyAt reads here)");
check((await reg.keyAt(VA.id, 0n)) === blsPubkey(VA.seed), "keyAt(VA, settledView) == VA's BLS key");

// Sign a valid approval for `v` over the contract's own digest.
async function signFor(v) {
  const digest = await gov.approveDigest(proposalId, v.id);
  return blsSign(v.seed, digest);
}

// --- (d) A non-seated (weightOf==0) caller is rejected -------------------
// Even with a valid signature, an unseated validator's approve reverts on the
// weight gate (and it has no registry key either).
check(await reverts(() => gov.approve(proposalId, cmd, VUNSEATED.id, blsSign(VUNSEATED.seed,
        ethers.keccak256(cmd))), w0),
  "approve as a non-seated validator (weightOf==0) reverts");
check((await gov.approvals(proposalId)) === 0n, "tally still 0 after the rejected approve");

// --- (b) A forged / bad BLS signature is rejected -----------------------
// A seated validator id, but the signature is over the WRONG message (the bare
// command hash, not approveDigest) -> BlsVerify fails -> revert.
check(await reverts(() => gov.approve(proposalId, cmd, VA.id, blsSign(VA.seed,
        ethers.keccak256(cmd))), w0),
  "approve with a signature over the wrong digest reverts (bad signature)");
// A seated validator id, signed by the WRONG key (VB signs VA's digest) -> revert.
check(await reverts(async () => {
        const digest = await gov.approveDigest(proposalId, VA.id);
        return gov.approve(proposalId, cmd, VA.id, blsSign(VB.seed, digest));
      }, w0),
  "approve for VA signed by VB's key reverts (signature must match the validator)");
// Garbage signature bytes -> revert.
check(await reverts(() => gov.approve(proposalId, cmd, VA.id, "0x" + "00".repeat(256)), w0),
  "approve with an all-zero (forged) signature reverts");
check((await gov.approvals(proposalId)) === 0n, "tally still 0 after all forged attempts");

// --- (c) The forged-quorum attack is closed -----------------------------
// An attacker who names every seated validator but holds NONE of their BLS keys
// cannot accrue ANY weight: each approve reverts on signature verification, so a
// ⅔ supermajority can never be forged.
for (const v of SEATED) {
  check(await reverts(() => gov.approve(proposalId, cmd, v.id, "0x" + "11".repeat(256)), w0),
    `forged-quorum: naming ${v.id.slice(0, 6)}… without its signature reverts`);
}
check((await gov.approvals(proposalId)) === 0n,
  "forged-quorum closed: no weight accrued from any unsigned/forged vote");
check((await gov.isApproved(proposalId)) === false, "forged-quorum closed: never approved");

// --- (a)+(f) Valid signed approvals count; double-vote does not double-count
let r = await (await gov.approve(proposalId, cmd, VA.id, await signFor(VA))).wait();
check((await gov.approvals(proposalId)) === 25n, "tally == 25 after VA's valid signed approval");
check((await gov.isApproved(proposalId)) === false, "not approved below threshold (25)");
check(approvedCount(r, proposalId) === 0, "no Approved event below threshold");

r = await (await gov.approve(proposalId, cmd, VA.id, await signFor(VA))).wait();
check((await gov.approvals(proposalId)) === 25n, "tally still 25 after VA votes again");
check(approvedCount(r, proposalId) === 0, "no Approved event from VA's duplicate vote");

r = await (await gov.approve(proposalId, cmd, VB.id, await signFor(VB))).wait();
check((await gov.approvals(proposalId)) === 50n, "tally == 50 after VB");
check((await gov.isApproved(proposalId)) === false, "still not approved at 50 (below ⅔)");

// --- (e) Crossing the ⅔ weight threshold emits Approved exactly once -----
r = await (await gov.approve(proposalId, cmd, VC.id, await signFor(VC))).wait();
check((await gov.approvals(proposalId)) === 75n, "tally == 75 after VC");
check((await gov.isApproved(proposalId)) === true, "approved once signed weight crosses ⅔");
check(approvedCount(r, proposalId) === 1, "Approved emitted exactly once at threshold crossing");
const iface = new ethers.Interface(GOV_ABI);
const ev = r.logs.map((l) => { try { return iface.parseLog(l); } catch { return null; } })
  .find((p) => p && p.name === "Approved");
check(ev && ev.args.reconfigCommand === cmd, "Approved carries the exact reconfig command");

// --- Further approvals after enactment do not re-emit -------------------
r = await (await gov.approve(proposalId, cmd, VD.id, await signFor(VD))).wait();
check(approvedCount(r, proposalId) === 0, "no second Approved after enactment");
check((await gov.approvals(proposalId)) === 75n, "tally unchanged after post-enactment approval");

console.log("ALL GOVERNANCE EVM TESTS PASSED");
