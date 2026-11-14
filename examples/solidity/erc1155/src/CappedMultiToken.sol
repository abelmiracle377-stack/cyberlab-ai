// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC1155ReceiverFixture {
    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data) external returns (bytes4);
    function onERC1155BatchReceived(address operator, address from, uint256[] calldata ids, uint256[] calldata values, bytes calldata data) external returns (bytes4);
}

/// @notice Educational multi-token fixture, not a complete ERC-1155 implementation.
contract CappedMultiTokenFixture {
    address public immutable owner;
    bool public paused;
    mapping(uint256 => uint256) public maxSupply;
    mapping(uint256 => uint256) public totalSupply;
    mapping(uint256 => mapping(address => uint256)) private balances;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);
    event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values);
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);
    event Paused(bool status);

    constructor() { owner = msg.sender; }

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier whenNotPaused() { require(!paused, "paused"); _; }

    function setCap(uint256 id, uint256 cap) external onlyOwner {
        require(cap >= totalSupply[id], "below supply");
        maxSupply[id] = cap;
    }

    function setPaused(bool status) external onlyOwner {
        paused = status;
        emit Paused(status);
    }

    function balanceOf(address account, uint256 id) external view returns (uint256) {
        require(account != address(0), "zero account");
        return balances[id][account];
    }

    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids) external view returns (uint256[] memory values) {
        require(accounts.length == ids.length, "length mismatch");
        values = new uint256[](accounts.length);
        for (uint256 i; i < accounts.length; ++i) {
            require(accounts[i] != address(0), "zero account");
            values[i] = balances[ids[i]][accounts[i]];
        }
    }

    function setApprovalForAll(address operator, bool approved) external {
        require(operator != msg.sender, "self approval");
        isApprovedForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function mint(address to, uint256 id, uint256 amount, bytes calldata data) external onlyOwner whenNotPaused {
        require(to != address(0) && amount > 0, "invalid mint");
        require(totalSupply[id] + amount <= maxSupply[id], "id cap");
        totalSupply[id] += amount;
        balances[id][to] += amount;
        emit TransferSingle(msg.sender, address(0), to, id, amount);
        _checkSingle(msg.sender, address(0), to, id, amount, data);
    }

    function mintBatch(address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) external onlyOwner whenNotPaused {
        require(to != address(0) && ids.length == amounts.length && ids.length > 0, "invalid batch");
        for (uint256 i; i < ids.length; ++i) {
            require(amounts[i] > 0 && totalSupply[ids[i]] + amounts[i] <= maxSupply[ids[i]], "id cap");
            totalSupply[ids[i]] += amounts[i];
            balances[ids[i]][to] += amounts[i];
        }
        emit TransferBatch(msg.sender, address(0), to, ids, amounts);
        if (to.code.length != 0) {
            bytes4 response = IERC1155ReceiverFixture(to).onERC1155BatchReceived(msg.sender, address(0), ids, amounts, data);
            require(response == IERC1155ReceiverFixture.onERC1155BatchReceived.selector, "unsafe batch receiver");
        }
    }

    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external whenNotPaused {
        require(to != address(0), "zero recipient");
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "not approved");
        require(balances[id][from] >= amount, "insufficient balance");
        balances[id][from] -= amount;
        balances[id][to] += amount;
        emit TransferSingle(msg.sender, from, to, id, amount);
        _checkSingle(msg.sender, from, to, id, amount, data);
    }

    function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) external whenNotPaused {
        require(to != address(0) && ids.length == amounts.length && ids.length > 0, "invalid batch");
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "not approved");
        for (uint256 i; i < ids.length; ++i) {
            require(balances[ids[i]][from] >= amounts[i], "insufficient balance");
            balances[ids[i]][from] -= amounts[i];
            balances[ids[i]][to] += amounts[i];
        }
        emit TransferBatch(msg.sender, from, to, ids, amounts);
        if (to.code.length != 0) {
            bytes4 response = IERC1155ReceiverFixture(to).onERC1155BatchReceived(msg.sender, from, ids, amounts, data);
            require(response == IERC1155ReceiverFixture.onERC1155BatchReceived.selector, "unsafe batch receiver");
        }
    }

    function _checkSingle(address operator, address from, address to, uint256 id, uint256 amount, bytes calldata data) private {
        if (to.code.length != 0) {
            bytes4 response = IERC1155ReceiverFixture(to).onERC1155Received(operator, from, id, amount, data);
            require(response == IERC1155ReceiverFixture.onERC1155Received.selector, "unsafe receiver");
        }
    }
}
