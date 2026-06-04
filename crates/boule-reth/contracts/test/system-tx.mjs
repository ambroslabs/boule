// Manual EVM test for the boule **system-account tx-submission** path (#732
// registry write-path, step 1) against a live reth (NOT a CI test — CI has no
// EL). Confirms that the fixed, genesis-funded system account can author a
// signed EIP-1559 transaction and get it executed in EVM state via
// `eth_sendRawTransaction` — the exact path src/system_account.rs builds and
// src/transport.rs `send_raw_transaction` submits, here reproduced in JS with
// the same key so the flow is exercised against a real reth.
//
//   # terminal 1 — a dev reth on the generated genesis (auto-mining):
//   cargo build -p boule-reth            # generates crates/boule-reth/genesis.json
//   reth node --chain crates/boule-reth/genesis.json --datadir /tmp/reth-sys --dev \
//     --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   # terminal 2:
//   cd crates/boule-reth/contracts/test && npm i ethers@6 && node system-tx.mjs
//
// Exits non-zero on any assertion failure.
import { ethers } from "ethers";

const RPC = process.env.RPC ?? "http://127.0.0.1:8545";
const REGISTRY = "0x0000000000000000000000000000000000000b12";

// The fixed MVP system account — must equal the constants in
// src/system_account.rs (SYSTEM_ACCOUNT_PRIVATE_KEY / SYSTEM_ACCOUNT_ADDRESS).
// Development key only; see the MVP caveat in that module.
const SYSTEM_PK = "0x5005ce11b0017e5750575e11acc011710123456789abcdef0123456789abcdef";
const SYSTEM_ADDR = "0x2Ae00C96484267e0ed8937426F497404A93aB526";

function check(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exit(1); }
  console.log("ok:", msg);
}

const provider = new ethers.JsonRpcProvider(RPC);
const wallet = new ethers.Wallet(SYSTEM_PK, provider);
check(
  wallet.address.toLowerCase() === SYSTEM_ADDR.toLowerCase(),
  "system key derives to SYSTEM_ACCOUNT_ADDRESS",
);

// The system account is funded in genesis so it can pay gas.
const bal = await provider.getBalance(SYSTEM_ADDR);
check(bal > 0n, "system account is funded (non-zero balance)");

// Build a Registry.recordKey(validator, vEff, key) call — unauthenticated in
// the MVP, so a plain external call from the system account suffices.
const iface = new ethers.Interface([
  "function recordKey(bytes32 validator, uint64 vEff, bytes key) external",
  "function historyLength(bytes32 validator) external view returns (uint256)",
  "function keyAt(bytes32 validator, uint64 viewNum) external view returns (bytes)",
]);
const V = "0x" + "5c".repeat(32);
const KEY = "0x" + "a7".repeat(48);
const calldata = iface.encodeFunctionData("recordKey", [V, 3, KEY]);

const chainId = (await provider.getNetwork()).chainId;
const nonce = await provider.getTransactionCount(SYSTEM_ADDR, "pending");

// Mirror src/system_account.rs::build_system_call: an EIP-1559 tx (type 2),
// signed by the system account, then submitted raw.
const tx = {
  type: 2,
  chainId,
  nonce,
  to: REGISTRY,
  value: 0n,
  data: calldata,
  gasLimit: 500_000n,
  maxFeePerGas: 2_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
};
const raw = await wallet.signTransaction(tx);

// Recover the sender from the signed raw tx — must be the system account.
const parsed = ethers.Transaction.from(raw);
check(parsed.from.toLowerCase() === SYSTEM_ADDR.toLowerCase(), "raw tx recovers system sender");
check(parsed.to.toLowerCase() === REGISTRY.toLowerCase(), "raw tx targets the registry");
check(parsed.chainId === BigInt(chainId), "raw tx is bound to the EVM chainId");

// Submit the raw tx via eth_sendRawTransaction (the new transport method).
const hash = await provider.send("eth_sendRawTransaction", [raw]);
console.log("submitted system tx:", hash);

// Poll for the receipt — reth --dev auto-mines pool txs.
let receipt = null;
for (let i = 0; i < 50 && receipt === null; i++) {
  receipt = await provider.send("eth_getTransactionReceipt", [hash]);
  if (receipt === null) await new Promise((r) => setTimeout(r, 200));
}
check(receipt !== null, "system tx mined");
check(BigInt(receipt.status) === 1n, "system tx receipt status == 1 (success)");

// The call executed in EVM state: the registry now has the recorded key.
const reg = new ethers.Contract(REGISTRY, iface, provider);
check((await reg.historyLength(V)) === 1n, "registry recorded one key for the validator");
check((await reg.keyAt(V, 3)) === KEY, "registry keyAt returns the system-submitted key");

console.log("ALL SYSTEM-TX EVM TESTS PASSED");
