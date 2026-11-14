// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/ConstantProductPool.sol";

contract ConstantProductPoolTest {
    function testSwapMaintainsOrIncreasesProductInvariant() public {
        FixtureToken token0 = new FixtureToken("A");
        FixtureToken token1 = new FixtureToken("B");
        ConstantProductPoolFixture pool = new ConstantProductPoolFixture(address(token0), address(token1));
        token0.mint(address(this), 20_000);
        token1.mint(address(this), 20_000);
        token0.approve(address(pool), type(uint256).max);
        token1.approve(address(pool), type(uint256).max);
        pool.addLiquidity(10_000, 10_000, 1, block.timestamp);
        uint256 beforeProduct = pool.reserve0() * pool.reserve1();
        pool.swapExact0For1(1_000, 1, block.timestamp);
        uint256 afterProduct = pool.reserve0() * pool.reserve1();
        assert(afterProduct >= beforeProduct);
    }

    function testMinimumOutputRejectsExcessiveSlippage() public {
        FixtureToken token0 = new FixtureToken("A");
        FixtureToken token1 = new FixtureToken("B");
        ConstantProductPoolFixture pool = new ConstantProductPoolFixture(address(token0), address(token1));
        token0.mint(address(this), 10_000);
        token1.mint(address(this), 10_000);
        token0.approve(address(pool), type(uint256).max);
        token1.approve(address(pool), type(uint256).max);
        pool.addLiquidity(5_000, 5_000, 1, block.timestamp);
        (bool ok,) = address(pool).call(abi.encodeCall(pool.swapExact0For1, (1_000, 5_000, block.timestamp)));
        assert(!ok);
        assert(pool.reserve0() == 5_000);
        assert(pool.reserve1() == 5_000);
    }

    function testExpiredLiquidityActionReverts() public {
        FixtureToken token0 = new FixtureToken("A");
        FixtureToken token1 = new FixtureToken("B");
        ConstantProductPoolFixture pool = new ConstantProductPoolFixture(address(token0), address(token1));
        token0.mint(address(this), 100);
        token1.mint(address(this), 100);
        token0.approve(address(pool), 100);
        token1.approve(address(pool), 100);
        (bool ok,) = address(pool).call(abi.encodeCall(pool.addLiquidity, (10, 10, 1, block.timestamp - 1)));
        assert(!ok);
    }

    function testLiquidityProviderCanWithdrawProRata() public {
        FixtureToken token0 = new FixtureToken("A");
        FixtureToken token1 = new FixtureToken("B");
        ConstantProductPoolFixture pool = new ConstantProductPoolFixture(address(token0), address(token1));
        token0.mint(address(this), 100);
        token1.mint(address(this), 100);
        token0.approve(address(pool), 100);
        token1.approve(address(pool), 100);
        uint256 shares = pool.addLiquidity(100, 100, 1, block.timestamp);
        (uint256 amount0, uint256 amount1) = pool.removeLiquidity(shares, 100, 100, block.timestamp);
        assert(amount0 == 100 && amount1 == 100);
        assert(pool.reserve0() == 0 && pool.reserve1() == 0);
    }
}
