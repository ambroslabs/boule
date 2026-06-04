// Manual EVM test for Param.sol's weighted-quorum authorization (#746) against a
// live reth (NOT a CI test — CI has no EL). Validates that a consensus-parameter
// update is gated behind a validator-weighted supermajority read from the
// Registry weight surface (#759): approvals below ⅔ weight do NOT emit
// ParamSubmitted; crossing ⅔ weight emits it exactly once carrying the right
// command; a non-seated (weightOf==0) caller is rejected; a double-vote by the
// same validator does not double-count.
//
//   # terminal 1 — a dev reth on the generated genesis (auto-mining):
//   export SOLC=~/.solcx/solc-v0.8.24
//   cargo build -p boule-reth            # generates crates/boule-reth/genesis.json
//   reth node --chain crates/boule-reth/genesis.json --datadir /tmp/reth-param --dev \
//     --http --http.addr 127.0.0.1 --http.port 8546 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   # terminal 2:
//   cd crates/boule-reth/contracts/test && npm i ethers@6 && RPC=http://127.0.0.1:8546 node param-auth.mjs
//
// Exits non-zero on any assertion failure.
import { ethers } from "ethers";

const RPC = process.env.RPC ?? "http://127.0.0.1:8546";
const PARAM = "0x0000000000000000000000000000000000000b11";
const REGISTRY = "0x0000000000000000000000000000000000000b12";
// boule's SYSTEM account — the only account `recordWeight` accepts (the Registry
// WRITER gate). genesis funds it so it can seat validator weights and pay gas.
const SYS_PK = "0x5005ce11b0017e5750575e11acc011710123456789abcdef0123456789abcdef";
// The genesis-funded dev faucet (Hardhat #0) — used as the approving caller. The
// per-validator dedup keys on the bytes32 `validator` ARG, not msg.sender, so a
// single funded account can cast each seated validator's vote (the dumb-carrier
// model: authorization is the on-chain weight, not the tx signer).
const PK0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const PARAM_ABI = [
  "function approve(bytes32 proposalId, bytes paramCommand, bytes32 validator) external",
  "function approvals(bytes32 proposalId) external view returns (uint64)",
  "function isApproved(bytes32 proposalId) external view returns (bool)",
  "event ParamSubmitted(bytes paramCommand)",
];
const REG_ABI = [
  "function recordWeight(bytes32 validator, uint64 newWeight) external",
  "function weightOf(bytes32 validator) external view returns (uint64)",
  "function totalWeight() external view returns (uint64)",
];

const provider = new ethers.JsonRpcProvider(RPC);
const sys = new ethers.Wallet(SYS_PK, provider);
const w0 = new ethers.Wallet(PK0, provider);
const reg = new ethers.Contract(REGISTRY, REG_ABI, sys);
const param = new ethers.Contract(PARAM, PARAM_ABI, w0);

function check(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exit(1); }
  console.log("ok:", msg);
}

const SUBMITTED_TOPIC = ethers.id("ParamSubmitted(bytes)");
function submittedCount(receipt) {
  return receipt.logs.filter(
    (l) => l.address.toLowerCase() === PARAM.toLowerCase() &&
           l.topics[0] === SUBMITTED_TOPIC,
  ).length;
}
async function reverts(fn) {
  try { await (await fn()).wait(); return false; } catch { return true; }
}

// Three seated validators, fresh ids per run so reruns start from totalWeight 0
// for these ids. Weights 40/40/30 => totalWeight 110, ⅔ threshold is >73.33, so
// 40 (one) is below, 80 (two of the 40s) crosses.
const tag = Date.now().toString(16).padStart(12, "0");
// bytes32 validator ids: a per-validator nibble run + the run tag, padded to 64
// hex chars (32 bytes). Distinct ids so reruns start from an untouched tally.
const vid = (nib) => "0x" + (nib.repeat(52) + tag).slice(0, 64);
const VA = vid("a");
const VB = vid("b");
const VC = vid("c");
// A never-seated validator id (weightOf == 0) to prove the gate rejects it.
const VX = vid("f");

await (await reg.recordWeight(VA, 40n)).wait();
await (await reg.recordWeight(VB, 40n)).wait();
await (await reg.recordWeight(VC, 30n)).wait();
check((await reg.weightOf(VA)) === 40n, "VA seated weight == 40");
check((await reg.weightOf(VX)) === 0n, "VX never seated (weightOf == 0)");
const total = await reg.totalWeight();
check(total >= 110n, "totalWeight includes our 110 (plus any genesis weight)");

// proposalId = keccak256 of the (opaque) param command — boule's binding. Fresh
// per run so the tally starts untouched.
const cmd = "0x" + Buffer.from("CPARM-min_block_interval=250ms-" + tag).toString("hex");
const proposalId = ethers.keccak256(cmd);

// 1. A non-seated caller (weightOf == 0) is rejected.
check(await reverts(() => param.approve(proposalId, cmd, VX)),
  "approve as a non-seated (zero-weight) validator reverts");
check((await param.approvals(proposalId)) === 0n, "tally still 0 after the rejected vote");

// 2. First approval (VA, weight 40): below ⅔ (40*3=120 !> 110*2=220) — no emit.
let r = await (await param.approve(proposalId, cmd, VA)).wait();
check((await param.approvals(proposalId)) === 40n, "tally == 40 after VA");
check((await param.isApproved(proposalId)) === false, "not approved below ⅔");
check(submittedCount(r) === 0, "no ParamSubmitted below ⅔ weight");

// 3. Double-vote by VA: must NOT double-count.
r = await (await param.approve(proposalId, cmd, VA)).wait();
check((await param.approvals(proposalId)) === 40n, "tally still 40 after VA double-vote");
check(submittedCount(r) === 0, "no ParamSubmitted from a double-vote");

// 4. Second distinct validator (VB, weight 40): tally 80. 80*3=240 > 110*2=220 —
//    crosses ⅔, emits ParamSubmitted exactly once carrying the exact command.
r = await (await param.approve(proposalId, cmd, VB)).wait();
check((await param.approvals(proposalId)) === 80n, "tally == 80 after VB");
check((await param.isApproved(proposalId)) === true, "approved at ⅔ supermajority");
check(submittedCount(r) === 1, "ParamSubmitted emitted exactly once at ⅔ crossing");
const iface = new ethers.Interface(PARAM_ABI);
const ev = r.logs.map((l) => { try { return iface.parseLog(l); } catch { return null; } })
  .find((p) => p && p.name === "ParamSubmitted");
check(ev && ev.args.paramCommand === cmd, "ParamSubmitted carries the exact param command");

// 5. Further approvals after emission do not re-emit.
r = await (await param.approve(proposalId, cmd, VC)).wait();
check(submittedCount(r) === 0, "no second ParamSubmitted after emission");
check((await param.approvals(proposalId)) === 80n, "tally unchanged after post-emit vote");

console.log("ALL PARAM-AUTH EVM TESTS PASSED");
