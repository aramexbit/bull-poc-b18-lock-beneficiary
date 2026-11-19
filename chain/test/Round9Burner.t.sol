// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Mocks.sol";

// ROUND 9 — Team A. K-361: burner live 0x1B3b… verification.
// Live bytecode fetched from Robinhood Chain (cast code, sha256
// 02d82b2a…, 6685 bytes, re-fetched identically twice) and etched here.
// All 16 src/burner.sol selectors are present in the live dispatcher,
// plus one extra public getter 0xc91b3ff1() returning constant 1000000
// (name unknown — live source is a slightly newer revision than
// src/burner.sol; behaviour below is tested against the LIVE code).
// Live immutables (eth_call, 18 Nov 2026): keeper = 0x5857… (== FEE_SIGNER),
// bull 0x3076…, usdg 0x5fc5…, weth 0x0Bd7…, v3Fee 100, v4Fee 451000,
// v4TickSpacing 4510, v4Hooks 0x0, totalBurned 0, totalEthSpent 0.
// Routers are mocked (etched at the live router addresses); tokens are
// MockERC20 code etched at the live USDG/BULL/WETH addresses.

contract MockWETH {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient weth");
        balanceOf[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "eth send failed");
    }
    receive() external payable {}
}

contract MockRouterV3 {
    address public immutable wethAddr;
    uint256 public lastAmountIn;
    uint256 public lastMinOut;
    constructor(address _weth) { wethAddr = _weth; }
    function WETH9() external view returns (address) { return wethAddr; }
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee; address recipient;
        uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata p) external payable returns (uint256) {
        lastAmountIn = p.amountIn;
        lastMinOut = p.amountOutMinimum;
        require(p.amountOutMinimum <= p.amountIn, "slippage: minOut > amountIn");
        // Like the real SwapRouter, pull the input tokens from the caller
        // (the burner approved the router for max in its constructor).
        MockERC20(p.tokenIn).burn(msg.sender, p.amountIn);
        MockWETH(payable(wethAddr)).mint(p.recipient, p.amountIn);
        return p.amountIn;
    }
}

contract MockUniversalRouter {
    address public immutable bullAddr;
    uint24 public lastFee;
    int24 public lastTickSpacing;
    uint128 public lastMinOut;
    uint128 public lastAmountIn;
    constructor(address _bull) { bullAddr = _bull; }
    struct PoolKey { address currency0; address currency1; uint24 fee; int24 tickSpacing; address hooks; }
    struct ExactInputSingleParams { PoolKey poolKey; bool zeroForOne; uint128 amountIn; uint128 amountOutMinimum; bytes hookData; }
    function execute(bytes calldata, bytes[] calldata inputs, uint256) external payable {
        (bytes memory actions, bytes[] memory params) = abi.decode(inputs[0], (bytes, bytes[]));
        actions; // actions bytes are not decoded; params carry the values
        ExactInputSingleParams memory p = abi.decode(params[0], (ExactInputSingleParams));
        lastFee = p.poolKey.fee;
        lastTickSpacing = p.poolKey.tickSpacing;
        lastAmountIn = p.amountIn;
        lastMinOut = p.amountOutMinimum;
        require(p.amountOutMinimum <= msg.value, "slippage: minBull > ethIn");
        MockERC20(bullAddr).mint(msg.sender, msg.value);
    }
}

interface IBurner {
    function burn(uint256 minEthFromUsdg, uint256 minBullOut) external;
    function keeper() external view returns (address);
    function totalBurned() external view returns (uint256);
    function totalEthSpent() external view returns (uint256);
    function lastBurn() external view returns (uint256);
    function v4Fee() external view returns (uint24);
    function v4TickSpacing() external view returns (int24);
}

contract Round9BurnerTest is Test {
    address constant BURNER = 0x1B3b7abb6553a1bbc9B285E6ab3F2012e88e4d5f;
    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address constant BULL = 0x30768B5482e5dd8a2487cE0BE61E01fA03Af37ff;
    address constant WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    address constant ROUTER_V3 = 0xCaf681a66D020601342297493863E78C959E5cb2;
    address constant UNIVERSAL_ROUTER = 0x8876789976dEcBfCbBbe364623C63652db8C0904;
    address constant DEAD = 0x000000000000000000000000000000000000dEaD;

    address keeper = 0x585770c10434fA6D434b6B27316354f9D1688bd0;
    address stranger = address(0x7777);

    MockWETH wethImpl;
    MockRouterV3 routerImpl;
    MockUniversalRouter urImpl;

    function setUp() public {
        vm.etch(BURNER, vm.parseBytes(vm.readFile("bytecode/burner-1b3b.hex")));
        // Token code etched at the live token addresses (fresh storage).
        MockERC20 usdgImpl = new MockERC20();
        MockERC20 bullImpl = new MockERC20();
        vm.etch(USDG, address(usdgImpl).code);
        vm.etch(BULL, address(bullImpl).code);
        wethImpl = new MockWETH();
        vm.etch(WETH, address(wethImpl).code);
        routerImpl = new MockRouterV3(WETH);
        vm.etch(ROUTER_V3, address(routerImpl).code);
        urImpl = new MockUniversalRouter(BULL);
        vm.etch(UNIVERSAL_ROUTER, address(urImpl).code);
        vm.deal(WETH, 10000 ether);
        vm.deal(BURNER, 0);
        vm.warp(1000);
        // lastBurn is storage slot 2 (totalBurned 0, totalEthSpent 1).
        vm.store(BURNER, bytes32(uint256(2)), bytes32(uint256(1000)));
        assertEq(IBurner(BURNER).lastBurn(), 1000, "lastBurn slot layout confirmed");
        assertEq(IBurner(BURNER).keeper(), keeper, "keeper == FEE_SIGNER (live)");
        assertEq(IBurner(BURNER).v4Fee(), 451000, "live v4Fee is 451000 (45.1%)");
        assertEq(IBurner(BURNER).v4TickSpacing(), 4510, "live v4TickSpacing is 4510");
    }

    function _fundBurnerUsdg(uint256 amt) internal {
        MockERC20(USDG).mint(BURNER, amt);
    }

    function testK361KeeperBurnEndToEnd() public {
        uint256 amt = 1000 ether;
        _fundBurnerUsdg(amt);
        vm.prank(keeper);
        IBurner(BURNER).burn(1, 1);
        assertEq(MockERC20(BULL).balanceOf(DEAD), amt, "BULL sent to dead address");
        assertEq(IBurner(BURNER).totalBurned(), amt, "totalBurned updated");
        assertEq(IBurner(BURNER).totalEthSpent(), amt, "totalEthSpent updated");
        assertEq(MockERC20(USDG).balanceOf(BURNER), 0, "USDG fully swapped");
        assertEq(BURNER.balance, 0, "ETH fully swapped");
        // The exact v4 swap parameters the live burner passes to the router.
        // (Read from the ETCHED copy at the live router address — the
        // deployed mock instance's storage is a different contract.)
        assertEq(MockUniversalRouter(UNIVERSAL_ROUTER).lastFee(), 451000, "v4 swap uses fee 451000");
        assertEq(MockUniversalRouter(UNIVERSAL_ROUTER).lastTickSpacing(), 4510, "v4 swap uses tickSpacing 4510");
        emit log_named_uint("K-361 burned to dead (BULL)", MockERC20(BULL).balanceOf(DEAD) / 1 ether);
    }

    function testK361NonKeeperBefore24hReverts() public {
        _fundBurnerUsdg(1000 ether);
        vm.warp(1000 + 1 hours); // lastBurn + 1h < 24h
        vm.prank(stranger);
        vm.expectRevert();
        IBurner(BURNER).burn(1, 1);
        assertEq(MockERC20(BULL).balanceOf(DEAD), 0, "nothing burned");
        assertEq(MockERC20(USDG).balanceOf(BURNER), 1000 ether, "USDG still in burner");
    }

    // LIVE-VERIFIED NEGATIVE (see note below): the non-keeper path NEVER
    // opens. Forge (etched live bytecode): stranger burn reverts
    // NotAllowed at lastBurn+25h AND at lastBurn+23 days, with USDG
    // funded. Anvil fork of Robinhood Chain (block 117539777, ts
    // 1795019469 = lastBurn + 43.7h): stranger burn(0,0) reverts
    // NotAllowed even with the burner pre-funded with 1 ETH. The "open
    // after 24h" path in src/burner.sol does not behave as documented
    // in the deployed bytecode (which also carries an extra 1e6-constant
    // getter and a storage-slot-3 gate absent from the source). Only the
    // keeper (== FEE_SIGNER, the server key) can ever call burn().
    function testK361NonKeeperAfter24hStillReverts() public {
        _fundBurnerUsdg(1000 ether);
        vm.warp(1000 + 25 hours);
        vm.prank(stranger);
        vm.expectRevert();
        IBurner(BURNER).burn(0, 0);
        assertEq(MockERC20(BULL).balanceOf(DEAD), 0, "nothing burned by a stranger");
        assertEq(MockERC20(USDG).balanceOf(BURNER), 1000 ether, "USDG untouched");
        // And even 23 days later the gate is still closed.
        vm.warp(1000 + 23 days);
        vm.prank(stranger);
        vm.expectRevert();
        IBurner(BURNER).burn(0, 0);
    }

    function testK361KeeperHugeMinsReverts() public {
        // Mins are the keeper's own slippage protection: an impossible
        // minimum reverts the swap, funds stay in the burner, and a retry
        // with sane minimums succeeds. (The old "stranger griefs with huge
        // mins" scenario is moot: strangers cannot call burn() at all —
        // see testK361NonKeeperAfter24hStillReverts.)
        _fundBurnerUsdg(1000 ether);
        vm.prank(keeper);
        (bool ok,) = BURNER.call(abi.encodeWithSelector(IBurner.burn.selector, 100000 ether, 100000 ether));
        assertFalse(ok, "burn with impossible mins reverts");
        assertEq(MockERC20(BULL).balanceOf(DEAD), 0, "nothing burned by the griefed call");
        assertEq(MockERC20(USDG).balanceOf(BURNER), 1000 ether, "funds stay in the burner");
        vm.prank(keeper);
        IBurner(BURNER).burn(1, 1);
        assertEq(MockERC20(BULL).balanceOf(DEAD), 1000 ether, "keeper burn succeeds after griefing");
    }

    function testK361EmptyBurnReverts() public {
        vm.prank(keeper);
        vm.expectRevert();
        IBurner(BURNER).burn(1, 1);
    }

    function testK361KeeperIsFeeSignerNotOwner() public {
        // There is no owner/admin function: the only privileged caller is
        // `keeper` (== FEE_SIGNER, the Bull server key). Anyone else must
        // wait 24h after the last burn. No rescue/sweep function exists in
        // the live bytecode (selector scan: only burn + getters).
        assertEq(IBurner(BURNER).keeper(), 0x585770c10434fA6D434b6B27316354f9D1688bd0, "keeper is the server key");
    }
}
