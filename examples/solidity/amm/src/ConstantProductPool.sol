// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20AMMFixture {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Minimal educational constant-product pool. Not a production AMM.
contract FixtureToken {
    string public name;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    constructor(string memory tokenName) { name = tokenName; }
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract ConstantProductPoolFixture {
    address public immutable token0;
    address public immutable token1;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidityOf;

    constructor(address first, address second) {
        require(first != second && first != address(0) && second != address(0), "invalid tokens");
        token0 = first;
        token1 = second;
    }

    function addLiquidity(uint256 amount0, uint256 amount1, uint256 minLiquidity, uint256 deadline) external returns (uint256 liquidity) {
        require(block.timestamp <= deadline, "expired");
        require(amount0 > 0 && amount1 > 0, "zero amount");
        if (totalLiquidity == 0) liquidity = amount0 + amount1;
        else {
            uint256 share0 = amount0 * totalLiquidity / reserve0;
            uint256 share1 = amount1 * totalLiquidity / reserve1;
            liquidity = share0 < share1 ? share0 : share1;
        }
        require(liquidity >= minLiquidity && liquidity > 0, "slippage");
        require(IERC20AMMFixture(token0).transferFrom(msg.sender, address(this), amount0), "token0 transfer");
        require(IERC20AMMFixture(token1).transferFrom(msg.sender, address(this), amount1), "token1 transfer");
        reserve0 += amount0;
        reserve1 += amount1;
        totalLiquidity += liquidity;
        liquidityOf[msg.sender] += liquidity;
    }

    function swapExact0For1(uint256 amountIn, uint256 minOut, uint256 deadline) external returns (uint256 amountOut) {
        require(block.timestamp <= deadline, "expired");
        require(amountIn > 0 && reserve0 > 0 && reserve1 > 0, "empty pool");
        uint256 amountInWithFee = amountIn * 997;
        amountOut = amountInWithFee * reserve1 / (reserve0 * 1000 + amountInWithFee);
        require(amountOut >= minOut && amountOut < reserve1, "slippage");
        require(IERC20AMMFixture(token0).transferFrom(msg.sender, address(this), amountIn), "input transfer");
        require(IERC20AMMFixture(token1).transfer(msg.sender, amountOut), "output transfer");
        reserve0 += amountIn;
        reserve1 -= amountOut;
    }

    function removeLiquidity(uint256 liquidity, uint256 min0, uint256 min1, uint256 deadline) external returns (uint256 amount0, uint256 amount1) {
        require(block.timestamp <= deadline, "expired");
        require(liquidity > 0 && liquidityOf[msg.sender] >= liquidity, "liquidity");
        amount0 = liquidity * reserve0 / totalLiquidity;
        amount1 = liquidity * reserve1 / totalLiquidity;
        require(amount0 >= min0 && amount1 >= min1, "slippage");
        liquidityOf[msg.sender] -= liquidity;
        totalLiquidity -= liquidity;
        reserve0 -= amount0;
        reserve1 -= amount1;
        require(IERC20AMMFixture(token0).transfer(msg.sender, amount0), "token0 transfer");
        require(IERC20AMMFixture(token1).transfer(msg.sender, amount1), "token1 transfer");
    }
}
