// Manual EVM test for BlsVerify.sol against a live reth (NOT a CI test — CI has
// no EL). Proves the in-EVM BLS verify matches boule's blst: the in-Solidity
// RFC 9380 hash-to-curve equals blst's H, and a real boule signature verifies.
//
//   # 1. ground-truth vectors from boule's blst -> /tmp/vecs.txt:
//   cargo test -p boule-core gen_eip2537_vectors -- --nocapture --ignored \
//     | grep '^VEC_' > /tmp/vecs.txt
//   # 2. a dev Prague reth (EIP-2537 precompiles) on the generated genesis:
//   cargo build -p boule-reth
//   reth node --chain crates/boule-reth/genesis.json --datadir /tmp/reth-dev --dev \
//     --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3 \
//     --disable-discovery --ipcdisable
//   # 3. run (compiles BlsVerify.sol via $SOLC or solc on PATH):
//   cd crates/boule-reth/contracts/test && npm i ethers@6 && node blsverify.mjs
import { ethers } from "ethers";
import { readFileSync, mkdtempSync } from "fs";
import { execFileSync } from "child_process";
import { tmpdir } from "os";
import { join } from "path";

const RPC = process.env.RPC ?? "http://127.0.0.1:8545";
const PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const SOLC = process.env.SOLC ?? "solc";

// Compile ../BlsVerify.sol -> {abi, bin}.
const outDir = mkdtempSync(join(tmpdir(), "blsv-"));
execFileSync(SOLC, ["--abi", "--bin", "-o", outDir, "--overwrite", "../BlsVerify.sol"]);
const abi = JSON.parse(readFileSync(join(outDir, "BlsVerify.abi"), "utf8"));
const bin = "0x" + readFileSync(join(outDir, "BlsVerify.bin"), "utf8").trim();

const vecs = Object.fromEntries(
  readFileSync("/tmp/vecs.txt", "utf8").trim().split("\n").map((l) => l.split("=")),
);

const wallet = new ethers.Wallet(PK, new ethers.JsonRpcProvider(RPC));
const c = await new ethers.ContractFactory(abi, bin, wallet).deploy();
await c.waitForDeployment();
console.log("deployed BlsVerify at", await c.getAddress());

const msg = "0x" + vecs.VEC_MSG;
const pubkey = "0x" + vecs.VEC_PUBKEY_G1;
const sig = "0x" + vecs.VEC_SIG_G2;
const neg = "0x" + vecs.VEC_NEG_G1GEN;

const h = await c.hashToG2(msg);
const hMatch = h.toLowerCase() === ("0x" + vecs.VEC_HMSG_G2).toLowerCase();
console.log("hashToG2 == blst H:", hMatch);
const ok = await c.verify(pubkey, msg, sig, neg);
console.log("verify(valid sig):", ok);
const bad = await c.verify(pubkey, msg + "00", sig, neg);
console.log("verify(tampered msg):", bad);

if (hMatch && ok === true && bad === false) console.log("ALL BLS VERIFY TESTS PASSED");
else { console.error("FAIL"); process.exit(1); }
