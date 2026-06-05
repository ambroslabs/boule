// Manual EVM test for the Staking.sol `withdraw` owner-gate (#821) against a
// live reth (NOT a CI test — CI has no EL). Proves the open-internet
// validator-removal vector is closed: only the genesis-seeded `owner` can emit
// a `Withdraw` event (which boule reads back as a validator-shrinking
// `StakeOp::Unbond`); every other caller reverts and emits nothing, so boule
// never sees a spoofed unbond. `deposit` stays open to anyone (additive-only,
// not a removal vector).
//
// Seed the Staking predeploy's owner to the Hardhat #0 faucet account, so we
// have a funded EOA with a known key acting as the owner:
//
//   cargo build -p boule-reth   # generates crates/boule-reth/genesis.json
//   cargo run -p boule-reth --bin gen-testnet-genesis -- \
//     --chain-id 424242 \
//     --staking-owner 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
//     --validator 11111111111111111111111111111111:<bls48hex>:1 \
//     --prefund 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:1000000000000000000000 \
//     --prefund 0x70997970C51812dc3A010C7d01b50e0d17dc79C8:1000000000000000000000 \
//     --out /tmp/staking-genesis.json
//   reth node --chain /tmp/staking-genesis.json --datadir /tmp/reth-stk --dev \
//     --http --http.addr 127.0.0.1 --http.port 8547 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   cd crates/boule-reth/contracts/test && npm i ethers@6
//   RPC=http://127.0.0.1:8547 node staking-withdraw.mjs
//
// (Any genesis that prefunds both accounts and seeds owner == Hardhat#0 works;
// the --validator above is just to satisfy the non-empty-set guard, #823.)
//
// Exits non-zero on any assertion failure.
import { ethers } from "ethers";

const RPC = process.env.RPC ?? "http://127.0.0.1:8547";
const STAKING = "0x0000000000000000000000000000000000000b0e";

// Hardhat #0 — the genesis-seeded Staking owner in the harness above.
const OWNER_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const OWNER_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
// Hardhat #1 — a funded NON-owner, used to prove the gate reverts everyone else
// (this is the open-internet attacker, gas-funded by the public faucet).
const ATTACKER_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const ABI = [
  "function owner() external view returns (address)",
  "function deposit(bytes32 nodeId) external payable",
  "function withdraw(bytes32 nodeId, uint256 amount) external",
  "event Deposit(bytes32 indexed nodeId, uint256 amount)",
  "event Withdraw(bytes32 indexed nodeId, uint256 amount)",
];

const provider = new ethers.JsonRpcProvider(RPC);
const asOwner = new ethers.Contract(STAKING, ABI, new ethers.Wallet(OWNER_PK, provider));
const asAttacker = new ethers.Contract(STAKING, ABI, new ethers.Wallet(ATTACKER_PK, provider));
const reader = new ethers.Contract(STAKING, ABI, provider);

// The victim validator the attacker tries to remove.
const VICTIM = "0x" + "aa".repeat(32);

function check(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exit(1); }
  console.log("ok:", msg);
}
async function withdrawEvents(receipt) {
  // Count Withdraw logs emitted to this predeploy in a receipt.
  return receipt.logs.filter(
    (l) => l.address.toLowerCase() === STAKING.toLowerCase()
  ).length;
}

// 0. The owner is seeded as expected.
check(
  (await reader.owner()).toLowerCase() === OWNER_ADDR.toLowerCase(),
  "owner() == the genesis-seeded owner (Hardhat #0)"
);

// 1. THE FIX: an unauthorized caller's withdraw reverts — no Withdraw event is
//    emitted, so boule's read path never sees a StakeOp::Unbond for VICTIM.
let attackerWithdrawReverted = false;
try {
  await (await asAttacker.withdraw(VICTIM, 1n)).wait();
} catch {
  attackerWithdrawReverted = true;
}
check(
  attackerWithdrawReverted,
  "withdraw() from a NON-owner reverts (unauthorized) — validator-removal vector closed (#821)"
);

// 2. The owner CAN still unbond (governance action) — emits exactly one
//    Withdraw, which boule reads back as the unbond.
const wRcpt = await (await asOwner.withdraw(VICTIM, 5n)).wait();
check(
  (await withdrawEvents(wRcpt)) === 1,
  "withdraw() from the owner succeeds and emits one Withdraw event"
);

// 3. deposit stays open to anyone (additive-only, not a removal vector): even
//    the non-owner can fund a validator's stake.
const dRcpt = await (await asAttacker.deposit(VICTIM, { value: 3n })).wait();
check(
  dRcpt.status === 1,
  "deposit() from a non-owner succeeds (additive-only, intentionally open)"
);

console.log("ALL STAKING WITHDRAW-GATE EVM TESTS PASSED");
