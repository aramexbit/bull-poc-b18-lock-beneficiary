// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Mocks.sol";

// ROUND 9 — Team A. K-362b: cancel() smuggled via lock() steps.
// Live escrow v3 etched (bytecode/escrow-v3.hex); deal fabricated with
// vm.store exactly as Round6EscrowTest did (layout verified against live
// mainnet storage of deal #1, 17 Nov 2026).

interface IEscrow {
    function deals(uint256 id) external view returns (address buyer, address seller, address sellToken, uint256 sellAmount, address payToken, uint256 payAmount, uint64 deadline, bool buyerFunded, bool sellerFunded, uint8 status, address sellerPayout, address buyerReceive, uint16 feeBps);
    function cancel(uint256 id) external;
}

contract Round9EscrowTest is Test {
    address constant ESCROW = 0xd961cA37e339E14e0D3478383a252E218fe7aa4a;

    address victim = address(0x2001); // buyer
    address seller = address(0x2005);

    MockERC20 sellToken;

    function setUp() public {
        vm.etch(ESCROW, vm.parseBytes(vm.readFile("bytecode/escrow-v3.hex")));
        vm.store(ESCROW, bytes32(uint256(5)), bytes32(uint256(1))); // reentrancy guard unlocked
        vm.store(ESCROW, bytes32(uint256(0)), bytes32(uint256(2))); // nextId = 2
        sellToken = new MockERC20();
        vm.deal(victim, 100 ether);
        vm.deal(seller, 10 ether);
        vm.warp(1000);
    }

    function dealBase(uint256 id) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, uint256(1)));
    }
    function setDealCore(uint256 id, address _buyer, address _seller, address _sellToken, uint256 _sellAmount, address _payToken, uint256 _payAmount) internal {
        bytes32 b = dealBase(id);
        vm.store(ESCROW, b, bytes32(uint256(uint160(_buyer))));
        vm.store(ESCROW, bytes32(uint256(b) + 1), bytes32(uint256(uint160(_seller))));
        vm.store(ESCROW, bytes32(uint256(b) + 2), bytes32(uint256(uint160(_sellToken))));
        vm.store(ESCROW, bytes32(uint256(b) + 3), bytes32(_sellAmount));
        vm.store(ESCROW, bytes32(uint256(b) + 4), bytes32(uint256(uint160(_payToken))));
        vm.store(ESCROW, bytes32(uint256(b) + 5), bytes32(_payAmount));
    }
    function setDealMeta(uint256 id, uint64 _deadline, bool _bf, bool _sf, uint8 _status, address _payout, address _receive, uint16 _feeBps) internal {
        bytes32 b = dealBase(id);
        uint256 packed6 = uint256(_deadline) | (uint256(_bf ? 1 : 0) << 64) | (uint256(_sf ? 1 : 0) << 72) | (uint256(_status) << 80) | (uint256(uint160(_payout)) << 88);
        vm.store(ESCROW, bytes32(uint256(b) + 6), bytes32(packed6));
        uint256 packed7 = uint256(uint160(_receive)) | (uint256(_feeBps) << 160);
        vm.store(ESCROW, bytes32(uint256(b) + 7), bytes32(packed7));
    }

    // Victim is the BUYER of an open deal, buyerFunded (paid 1 ETH into
    // escrow). A cancel(id) step smuggled into the victim's lock() call
    // executes (lock() has no fn restriction): the deal is cancelled and
    // the victim is REFUNDED their 1 ETH — no theft, only destruction of
    // the deal (griefing). The seller's unfunded side loses nothing either.
    function testK362bLockViaCancelRefundsNoTheft() public {
        uint256 dealId = 2;
        setDealCore(dealId, victim, seller, address(sellToken), 100 ether, address(0), 1 ether);
        setDealMeta(dealId, uint64(block.timestamp + 1 days), true, false, 1, seller, victim, 250);
        // Escrow actually holds the buyer's 1 ETH (as _pull would have put it).
        vm.deal(ESCROW, 1 ether);
        uint256 victimBefore = victim.balance;
        vm.prank(victim);
        IEscrow(ESCROW).cancel(dealId);
        (,,,,,,,,, uint8 status,,,) = IEscrow(ESCROW).deals(dealId);
        assertEq(status, 3, "deal cancelled");
        assertEq(victim.balance, victimBefore + 1 ether, "buyer refunded in full, no loss");
        assertEq(seller.balance, 10 ether, "seller untouched (never funded)");
        emit log_named_uint("K-362b victim loss via cancel smuggle (wei)", 0);
    }

    // A stranger CANNOT cancel someone else's deal before the deadline, so
    // a cancel step smuggled into a victim's lock() only works on deals
    // where the victim is already a party — bounding the griefing.
    function testK362bCancelByStrangerReverts() public {
        uint256 dealId = 2;
        setDealCore(dealId, victim, seller, address(sellToken), 100 ether, address(0), 1 ether);
        setDealMeta(dealId, uint64(block.timestamp + 1 days), true, false, 1, seller, victim, 250);
        address stranger = address(0x9999);
        vm.prank(stranger);
        (bool ok,) = ESCROW.call(abi.encodeWithSelector(IEscrow.cancel.selector, dealId));
        assertFalse(ok, "stranger cancel must revert (NotParty)");
        (,,,,,,,,, uint8 status,,,) = IEscrow(ESCROW).deals(dealId);
        assertEq(status, 1, "deal still open");
    }
}
