// Manual EVM test for Governance.sol against a live reth (NOT a CI test — CI has
// no EL). Validates the contract's approval-tally logic on a real EVM: approvals
// below quorum do NOT emit Approved; crossing quorum emits Approved exactly once;
// a double-approval by the same validator does not double-count.
//
//   # terminal 1 — a dev reth on the generated genesis (auto-mining):
//   cargo build -p boule-reth            # generates crates/boule-reth/genesis.json
//   reth node --chain crates/boule-reth/genesis.json --datadir /tmp/reth-dev --dev \
//     --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   # terminal 2:
//   cd crates/boule-reth/contracts/test && npm i ethers@6 && node governance.mjs
//
// Exits non-zero on any assertion failure.
import { ethers } from "ethers";

const RPC = process.env.RPC ?? "http://127.0.0.1:8545";
const GOVERNANCE = "0x0000000000000000000000000000000000000b14";
// Two accounts act as two distinct approving validators — the MVP tally counts
// distinct addresses. #0 is the genesis-funded account (well-known Hardhat #0);
// #1 (Hardhat #1) is funded from #0 below, since only #0 is in the genesis alloc.
const PK0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PK1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const ABI = [
  "function approve(bytes32 proposalId, bytes reconfigCommand, uint64 quorum) external",
  "function approvals(bytes32 proposalId) external view returns (uint64)",
  "function isApproved(bytes32 proposalId) external view returns (bool)",
  "event Approved(bytes32 indexed proposalId, bytes reconfigCommand)",
];

const provider = new ethers.JsonRpcProvider(RPC);
const w0 = new ethers.Wallet(PK0, provider);
const w1 = new ethers.Wallet(PK1, provider);
const gov0 = new ethers.Contract(GOVERNANCE, ABI, w0);
const gov1 = new ethers.Contract(GOVERNANCE, ABI, w1);

// proposalId = keccak256 of the (opaque) reconfig command — boule's binding.
// A fresh command per run so reruns start from an untouched proposalId tally.
const cmd = "0x" + Buffer.from("RECFG-add-validator-0xbeef-" + Date.now()).toString("hex");
const proposalId = ethers.keccak256(cmd);
const QUORUM = 2;

function check(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exit(1); }
  console.log("ok:", msg);
}

// Count Approved events for our proposalId emitted by a given tx receipt.
function approvedCount(receipt) {
  const topic0 = ethers.id("Approved(bytes32,bytes)");
  return receipt.logs.filter(
    (l) => l.address.toLowerCase() === GOVERNANCE.toLowerCase() &&
           l.topics[0] === topic0 &&
           l.topics[1] === proposalId,
  ).length;
}

// Fund validator 1 from validator 0 (only #0 is seeded in the genesis alloc).
await (await w0.sendTransaction({ to: w1.address, value: ethers.parseEther("1") })).wait();

// 1. First approval (validator 0): below quorum (1 < 2) — no Approved event.
let r = await (await gov0.approve(proposalId, cmd, QUORUM)).wait();
check((await gov0.approvals(proposalId)) === 1n, "tally == 1 after first approval");
check((await gov0.isApproved(proposalId)) === false, "not approved below quorum");
check(approvedCount(r) === 0, "no Approved event below quorum");

// 2. Double-approval by the same validator (0): must NOT double-count.
r = await (await gov0.approve(proposalId, cmd, QUORUM)).wait();
check((await gov0.approvals(proposalId)) === 1n, "tally still 1 after self-double-approve");
check((await gov0.isApproved(proposalId)) === false, "still not approved after double-approve");
check(approvedCount(r) === 0, "no Approved event from double-approve");

// 3. Second distinct validator (1): crosses quorum (2 >= 2) — Approved once.
r = await (await gov1.approve(proposalId, cmd, QUORUM)).wait();
check((await gov0.approvals(proposalId)) === 2n, "tally == 2 after second distinct approval");
check((await gov0.isApproved(proposalId)) === true, "approved at quorum");
check(approvedCount(r) === 1, "Approved emitted exactly once at quorum crossing");
// The carried command must round-trip for boule to re-materialise.
const iface = new ethers.Interface(ABI);
const ev = r.logs.map((l) => { try { return iface.parseLog(l); } catch { return null; } })
  .find((p) => p && p.name === "Approved");
check(ev && ev.args.reconfigCommand === cmd, "Approved carries the exact reconfig command");

// 4. Further approvals after enactment do not re-emit.
r = await (await gov0.approve(proposalId, cmd, QUORUM)).wait();
check(approvedCount(r) === 0, "no second Approved after enactment");
check((await gov0.approvals(proposalId)) === 2n, "tally unchanged after post-enactment approval");

console.log("ALL GOVERNANCE EVM TESTS PASSED");
