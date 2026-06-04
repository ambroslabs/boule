// Manual EVM test for Param.sol's in-EVM BLS-authenticated weighted-quorum
// authorization (#746 + #764) against a live reth (NOT a CI test — CI has no EL).
// A consensus-parameter update is gated behind a validator-weighted supermajority
// read from the Registry weight surface (#759), AND each approval must carry the
// validator's own BLS signature over a domain-separated, replay-bound digest,
// verified in-EVM via BlsVerify against Registry.keyAt (#764). This closes the
// forged-quorum hole: naming a validator id without its signature accrues no
// weight. Proves:
//   (a) a valid BLS-signed approval by a seated validator counts;
//   (b) a forged / wrong-key signature is rejected (reverts);
//   (c) the forged-quorum attack is closed: naming seated validators with no
//       signature accrues no weight, so no ⅔ supermajority can be forged;
//   (d) a non-seated (weightOf==0) caller is rejected (reverts);
//   (e) crossing ⅔ weight (with valid signatures) emits ParamSubmitted exactly
//       once carrying the exact command;
//   (f) a double-vote by the same validator does not double-count.
//
//   # 1. a dev Prague reth (EIP-2537 precompiles) on the generated genesis:
//   export SOLC=~/.solcx/solc-v0.8.24
//   cargo build -p boule-reth            # generates crates/boule-reth/genesis.json
//   cargo build -p boule-consensus --bin bls-sign
//   reth node --chain crates/boule-reth/genesis.json --datadir /tmp/reth-param --dev \
//     --http --http.addr 127.0.0.1 --http.port 8546 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   # 2:
//   cd crates/boule-reth/contracts/test && npm i ethers@6 && RPC=http://127.0.0.1:8546 node param-auth.mjs
//
// Exits non-zero on any assertion failure.
import { ethers } from "ethers";
import { execFileSync } from "node:child_process";

const RPC = process.env.RPC ?? "http://127.0.0.1:8546";
const PARAM = "0x0000000000000000000000000000000000000b11";
const REGISTRY = "0x0000000000000000000000000000000000000b12";
const BLS_SIGN = process.env.BLS_SIGN ?? "../../../../target/debug/bls-sign";

// boule's SYSTEM account — the only account recordWeight/recordKey/recordSettled
// accept (the Registry WRITER gate). Seats weights AND BLS keys, pays gas.
const SYS_PK = "0x5005ce11b0017e5750575e11acc011710123456789abcdef0123456789abcdef";
// The genesis-funded dev faucet (Hardhat #0) — the relaying caller. #764 makes
// msg.sender irrelevant: the gate is the validator's BLS signature, not the tx
// signer, so a single funded account can relay each validator's signed approval.
const PK0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const PARAM_ABI = [
  "function approve(bytes32 proposalId, bytes paramCommand, bytes32 validator, bytes blsSig) external",
  "function approveDigest(bytes32 proposalId, bytes32 validator) external view returns (bytes32)",
  "function approvals(bytes32 proposalId) external view returns (uint64)",
  "function isApproved(bytes32 proposalId) external view returns (bool)",
  "event ParamSubmitted(bytes paramCommand)",
];
const REG_ABI = [
  "function recordWeight(bytes32 validator, uint64 newWeight) external",
  "function recordKey(bytes32 validator, uint64 vEff, bytes key) external",
  "function settledView() external view returns (uint64)",
  "function keyAt(bytes32 validator, uint64 viewNum) external view returns (bytes)",
  "function weightOf(bytes32 validator) external view returns (uint64)",
  "function totalWeight() external view returns (uint64)",
];

const provider = new ethers.JsonRpcProvider(RPC);
const sys = new ethers.NonceManager(new ethers.Wallet(SYS_PK, provider));
const w0 = new ethers.NonceManager(new ethers.Wallet(PK0, provider));
const reg = new ethers.Contract(REGISTRY, REG_ABI, sys);
const param = new ethers.Contract(PARAM, PARAM_ABI, w0);

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
const SUBMITTED_TOPIC = ethers.id("ParamSubmitted(bytes)");
function submittedCount(receipt) {
  return receipt.logs.filter(
    (l) => l.address.toLowerCase() === PARAM.toLowerCase() && l.topics[0] === SUBMITTED_TOPIC,
  ).length;
}
async function reverts(fn, signer) {
  try { await (await fn()).wait(); return false; }
  catch { if (signer) signer.reset(); return true; }
}

// Four equal-weight seated validators, fresh ids per run. The registry's
// totalWeight already carries a genesis/base contribution (and grows across reruns
// on the same node), so weights are chosen to **dominate** that base: with base B
// and 4 weights W, three approvals cross ⅔ iff 3W·3 > (B+4W)·2 ⇔ W > 2B. Seating
// W = 2·base + 100 guarantees three-of-four crosses and one/two do not, regardless
// of the live base. Each validator is bound to a distinct BLS key seed.
const tag = Date.now().toString(16).padStart(12, "0");
const vid = (nib) => "0x" + (nib.repeat(52) + tag).slice(0, 64);
const base = await reg.totalWeight();
const W = 2n * base + 100n; // > 2·base, so 3 of 4 crosses ⅔ of (base + 4W)
const VA = { id: vid("a"), seed: 0x5a };
const VB = { id: vid("b"), seed: 0x5b };
const VC = { id: vid("c"), seed: 0x5c };
const VD = { id: vid("d"), seed: 0x5d };
const VX = { id: vid("f"), seed: 0x5f }; // never seated -> weightOf == 0
const SEATED = [VA, VB, VC, VD];

// --- Seat weights AND BLS keys via the system account --------------------
for (const v of SEATED) {
  await (await reg.recordWeight(v.id, W)).wait();
  await (await reg.recordKey(v.id, 0n, blsPubkey(v.seed))).wait();
}
check((await reg.weightOf(VA.id)) === W, "VA seated weight == W");
check((await reg.weightOf(VX.id)) === 0n, "VX never seated (weightOf == 0)");
const total = await reg.totalWeight();
check(total === base + 4n * W, "totalWeight == base + 4·W");
// Sanity: the threshold the contract uses (weight·3 > total·2).
const crosses = (w) => w * 3n > total * 2n;
check(!crosses(2n * W), "two validators' weight is below the ⅔ supermajority");
check(crosses(3n * W), "three validators' weight crosses the ⅔ supermajority");
check((await reg.settledView()) === 0n, "settledView == 0 (genesis frontier; keyAt reads here)");
check((await reg.keyAt(VA.id, 0n)) === blsPubkey(VA.seed), "keyAt(VA, settledView) == VA's BLS key");

// proposalId = keccak256 of the (opaque) param command — boule's binding.
const cmd = "0x" + Buffer.from("CPARM-min_block_interval=250ms-" + tag).toString("hex");
const proposalId = ethers.keccak256(cmd);

async function signFor(v) {
  const digest = await param.approveDigest(proposalId, v.id);
  return blsSign(v.seed, digest);
}

// --- (d) A non-seated caller (weightOf == 0) is rejected -----------------
check(await reverts(() => param.approve(proposalId, cmd, VX.id, blsSign(VX.seed,
        ethers.keccak256(cmd))), w0),
  "approve as a non-seated (zero-weight) validator reverts");
check((await param.approvals(proposalId)) === 0n, "tally still 0 after the rejected vote");

// --- (b) Forged / wrong-key signatures are rejected ---------------------
check(await reverts(() => param.approve(proposalId, cmd, VA.id, blsSign(VA.seed,
        ethers.keccak256(cmd))), w0),
  "approve with a signature over the wrong digest reverts (bad signature)");
check(await reverts(async () => {
        const digest = await param.approveDigest(proposalId, VA.id);
        return param.approve(proposalId, cmd, VA.id, blsSign(VB.seed, digest));
      }, w0),
  "approve for VA signed by VB's key reverts (signature must match the validator)");
check(await reverts(() => param.approve(proposalId, cmd, VA.id, "0x" + "00".repeat(256)), w0),
  "approve with an all-zero (forged) signature reverts");
check((await param.approvals(proposalId)) === 0n, "tally still 0 after all forged attempts");

// --- (c) The forged-quorum attack is closed -----------------------------
for (const v of SEATED) {
  check(await reverts(() => param.approve(proposalId, cmd, v.id, "0x" + "11".repeat(256)), w0),
    `forged-quorum: naming ${v.id.slice(0, 6)}… without its signature reverts`);
}
check((await param.approvals(proposalId)) === 0n,
  "forged-quorum closed: no weight accrued from any unsigned/forged vote");
check((await param.isApproved(proposalId)) === false, "forged-quorum closed: never approved");

// --- (a)+(f) Valid signed approvals count; double-vote does not double-count
let r = await (await param.approve(proposalId, cmd, VA.id, await signFor(VA))).wait();
check((await param.approvals(proposalId)) === W, "tally == W after VA's valid signed approval");
check((await param.isApproved(proposalId)) === false, "not approved below ⅔");
check(submittedCount(r) === 0, "no ParamSubmitted below ⅔ weight");

r = await (await param.approve(proposalId, cmd, VA.id, await signFor(VA))).wait();
check((await param.approvals(proposalId)) === W, "tally still W after VA double-vote");
check(submittedCount(r) === 0, "no ParamSubmitted from a double-vote");

r = await (await param.approve(proposalId, cmd, VB.id, await signFor(VB))).wait();
check((await param.approvals(proposalId)) === 2n * W, "tally == 2·W after VB");
check((await param.isApproved(proposalId)) === false, "still not approved at 2·W (below ⅔)");

// --- (e) Crossing ⅔ weight emits ParamSubmitted exactly once ------------
r = await (await param.approve(proposalId, cmd, VC.id, await signFor(VC))).wait();
check((await param.approvals(proposalId)) === 3n * W, "tally == 3·W after VC");
check((await param.isApproved(proposalId)) === true, "approved at ⅔ supermajority");
check(submittedCount(r) === 1, "ParamSubmitted emitted exactly once at ⅔ crossing");
const iface = new ethers.Interface(PARAM_ABI);
const ev = r.logs.map((l) => { try { return iface.parseLog(l); } catch { return null; } })
  .find((p) => p && p.name === "ParamSubmitted");
check(ev && ev.args.paramCommand === cmd, "ParamSubmitted carries the exact param command");

// --- Further approvals after emission do not re-emit --------------------
r = await (await param.approve(proposalId, cmd, VD.id, await signFor(VD))).wait();
check(submittedCount(r) === 0, "no second ParamSubmitted after emission");
check((await param.approvals(proposalId)) === 3n * W, "tally unchanged after post-emit vote");

console.log("ALL PARAM-AUTH EVM TESTS PASSED");
