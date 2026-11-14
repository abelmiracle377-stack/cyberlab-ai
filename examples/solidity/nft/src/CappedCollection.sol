// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721ReceiverFixture {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

/// @notice Small teaching fixture, not a complete ERC-721 implementation or production contract.
contract CappedCollectionFixture {
    address public immutable owner;
    uint256 public immutable maxSupply;
    uint256 public totalSupply;
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => address) public getApproved;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    constructor(uint256 cap) {
        require(cap > 0, "zero cap");
        owner = msg.sender;
        maxSupply = cap;
    }

    function mint(address to, uint256 tokenId) public {
        require(msg.sender == owner, "not owner");
        require(to != address(0), "zero recipient");
        require(ownerOf[tokenId] == address(0), "already minted");
        require(totalSupply < maxSupply, "cap reached");
        totalSupply += 1;
        ownerOf[tokenId] = to;
        balanceOf[to] += 1;
        emit Transfer(address(0), to, tokenId);
    }

    function safeMint(address to, uint256 tokenId, bytes calldata data) external {
        mint(to, tokenId);
        if (to.code.length != 0) {
            bytes4 response = IERC721ReceiverFixture(to).onERC721Received(msg.sender, address(0), tokenId, data);
            require(response == IERC721ReceiverFixture.onERC721Received.selector, "unsafe recipient");
        }
    }

    function approve(address approved, uint256 tokenId) external {
        address tokenOwner = ownerOf[tokenId];
        require(msg.sender == tokenOwner, "not token owner");
        getApproved[tokenId] = approved;
        emit Approval(tokenOwner, approved, tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        address tokenOwner = ownerOf[tokenId];
        require(tokenOwner == from, "wrong from");
        require(to != address(0), "zero recipient");
        require(msg.sender == tokenOwner || msg.sender == getApproved[tokenId], "not authorized");
        delete getApproved[tokenId];
        ownerOf[tokenId] = to;
        balanceOf[from] -= 1;
        balanceOf[to] += 1;
        emit Transfer(from, to, tokenId);
    }
}
