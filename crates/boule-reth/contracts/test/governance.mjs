// Manual EVM test for Governance.sol against a live reth (NOT a CI test — CI has
// no EL). Validates the contract's **stake-weighted, validator-gated** approval
// tally (#729) on a real EVM: it reads the Registry's weight surface (#759), so
// this harness first seats a weight distribution via Registry.recordWeight from
// the system account, then proves:
//   (a) approvals whose summed weight is below ⅔·totalWeight do NOT emit Approved;
//   (b) crossing the ⅔ weight threshold emits Approved exactly once, exact cmd;
//   (c) a weightOf==0 (non-seated) caller is rejected (reverts);
//   (d) the same validator voting twice does not double-count.
//
//   # terminal 1 — a dev reth on the generated genesis (auto-mining):
//   cargo build -p boule-reth            # generates crates/boule-reth/genesis.json
//   reth node --chain crates/boule-reth/genesis.json --datadir /tmp/reth-gov --dev \
//     --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   # terminal 2:
//   cd crates/boule-reth/contracts/test && npm i ethers@6 && node governance.mjs
//
// Exits non-zero on any assertion failure.
import { ethers } from "ethers";

const RPC = process.env.RPC ?? "http://127.0.0.1:8545";
const GOVERNANCE = "0x0000000000000000000000000000000000000b14";
const REGISTRY = "0x0000000000000000000000000000000000000b12";

// boule's SYSTEM account — the only account Registry.recordWeight accepts (see
// src/system_account.rs; the contract's WRITER is the matching address). genesis
// funds it so it can pay gas. Used here to seat the weight distribution.
const SYS_PK = "0x5005ce11b0017e5750575e11acc011710123456789abcdef0123456789abcdef";
// The genesis-funded dev faucet (Hardhat #0) — any funded account can call
// Governance.approve (approve is permissionless; the gate is weightOf>0 on the
// passed validator id, not on msg.sender).
const PK0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const GOV_ABI = [
  "function approve(bytes32 proposalId, bytes reconfigCommand, bytes32 validator) external",
  "function approvals(bytes32 proposalId) external view returns (uint64)",
  "function isApproved(bytes32 proposalId) external view returns (bool)",
  "event Approved(bytes32 indexed proposalId, bytes reconfigCommand)",
];
const REG_ABI = [
  "function recordWeight(bytes32 validator, uint64 newWeight) external",
  "function weightOf(bytes32 validator) external view returns (uint64)",
  "function totalWeight() external view returns (uint64)",
];

const provider = new ethers.JsonRpcProvider(RPC);
// Wrap each signer in a NonceManager: the --dev node mines asynchronously, so
// back-to-back txs from one account would otherwise race on the pending nonce.
const wSys = new ethers.NonceManager(new ethers.Wallet(SYS_PK, provider));
const w0 = new ethers.NonceManager(new ethers.Wallet(PK0, provider));
const reg = new ethers.Contract(REGISTRY, REG_ABI, wSys);
const gov = new ethers.Contract(GOVERNANCE, GOV_ABI, w0);

// proposalId = keccak256 of the (opaque) reconfig command — boule's binding.
// A fresh command per run so reruns start from an untouched proposalId tally.
const cmd = "0x" + Buffer.from("RECFG-add-validator-0xbeef-" + Date.now()).toString("hex");
const proposalId = ethers.keccak256(cmd);

// Distinct validator ids (fresh per run so reruns start from zero weight). Four
// equal-weight (25) seated validators -> totalWeight == 100; the ⅔ supermajority
// is weight*3 > 200, i.e. > 66.67, so it is first crossed at the 3rd vote (75),
// not the 2nd (50). A fifth id is never seated (weightOf == 0).
const tag = Date.now().toString(16).padStart(16, "0");
const vid = (b) => "0x" + b.repeat(2).padEnd(48, "0") + tag;
const VA = vid("a1"); // weight 25
const VB = vid("b2"); // weight 25
const VC = vid("c3"); // weight 25  (A+B+C = 75 -> crosses ⅔ of 100)
const VD = vid("d4"); // weight 25  (seated but unused — keeps total at 100)
const VUNSEATED = vid("ff"); // never seated -> weightOf == 0

function check(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exit(1); }
  console.log("ok:", msg);
}
// Run a call expected to revert; reset `signer`'s managed nonce afterward so a
// tx that never lands on-chain doesn't leave a gap for the next send.
async function reverts(fn, signer) {
  try { await (await fn()).wait(); return false; }
  catch { if (signer) signer.reset(); return true; }
}
function approvedCount(receipt) {
  const topic0 = ethers.id("Approved(bytes32,bytes)");
  return receipt.logs.filter(
    (l) => l.address.toLowerCase() === GOVERNANCE.toLowerCase() &&
           l.topics[0] === topic0 &&
           l.topics[1] === proposalId,
  ).length;
}

// --- Seat a weight distribution via the system account ------------------
// Seat four validators at weight 25 each (the committed genesis seeds no
// weights, so totalWeight starts at the genesis base — captured here so the test
// is correct regardless of any deployment-specific base).
const total0 = await reg.totalWeight();
for (const v of [VA, VB, VC, VD]) await (await reg.recordWeight(v, 25n)).wait();
const total = await reg.totalWeight();
check(total === total0 + 100n, "totalWeight seeded: base + 4*25");
check((await reg.weightOf(VA)) === 25n, "weightOf(VA) == 25");
check((await reg.weightOf(VUNSEATED)) === 0n, "weightOf(VUNSEATED) == 0 (non-seated)");

// The contract's threshold is strict: accumulated weight*3 > totalWeight*2.
// (With base==0 and total==100 this is weight > 66.67: 50 below, 75 above.)
const crosses = (w) => BigInt(w) * 3n > total * 2n;
check(!crosses(50), "50 is below the ⅔ supermajority (sanity)");
check(crosses(75), "75 crosses the ⅔ supermajority (sanity)");

// --- (c) A non-seated (weightOf==0) caller is rejected ------------------
check(await reverts(() => gov.approve(proposalId, cmd, VUNSEATED), w0),
  "approve as a non-seated validator (weightOf==0) reverts");
check((await gov.approvals(proposalId)) === 0n, "tally still 0 after the rejected approve");

// --- (a) Below-threshold approvals do NOT emit Approved -----------------
let r = await (await gov.approve(proposalId, cmd, VA)).wait();
check((await gov.approvals(proposalId)) === 25n, "tally == 25 after VA");
check((await gov.isApproved(proposalId)) === false, "not approved below threshold (25)");
check(approvedCount(r) === 0, "no Approved event below threshold");

// --- (d) The same validator voting twice does not double-count ----------
r = await (await gov.approve(proposalId, cmd, VA)).wait();
check((await gov.approvals(proposalId)) === 25n, "tally still 25 after VA votes again");
check(approvedCount(r) === 0, "no Approved event from VA's duplicate vote");

// VB -> 50 accumulated. Still below ⅔ (50*3=150 < 200).
r = await (await gov.approve(proposalId, cmd, VB)).wait();
check((await gov.approvals(proposalId)) === 50n, "tally == 50 after VB");
check((await gov.isApproved(proposalId)) === false, "still not approved at 50 (below ⅔)");
check(approvedCount(r) === 0, "no Approved event at 50");

// --- (b) Crossing the ⅔ weight threshold emits Approved exactly once -----
// VC -> 75 accumulated: 75*3=225 > 200 == ⅔ supermajority crossed.
r = await (await gov.approve(proposalId, cmd, VC)).wait();
check((await gov.approvals(proposalId)) === 75n, "tally == 75 after VC");
check((await gov.isApproved(proposalId)) === true, "approved once weight crosses ⅔");
check(approvedCount(r) === 1, "Approved emitted exactly once at threshold crossing");
const iface = new ethers.Interface(GOV_ABI);
const ev = r.logs.map((l) => { try { return iface.parseLog(l); } catch { return null; } })
  .find((p) => p && p.name === "Approved");
check(ev && ev.args.reconfigCommand === cmd, "Approved carries the exact reconfig command");

// --- Further approvals after enactment do not re-emit -------------------
r = await (await gov.approve(proposalId, cmd, VD)).wait();
check(approvedCount(r) === 0, "no second Approved after enactment");
check((await gov.approvals(proposalId)) === 75n, "tally unchanged after post-enactment approval");

console.log("ALL GOVERNANCE EVM TESTS PASSED");
