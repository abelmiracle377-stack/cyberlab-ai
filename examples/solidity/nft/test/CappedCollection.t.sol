// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/CappedCollection.sol";

contract AcceptingNFTReceiver is IERC721ReceiverFixture {
    uint256 public receivedTokenId;
    function onERC721Received(address, address, uint256 tokenId, bytes calldata) external returns (bytes4) {
        receivedTokenId = tokenId;
        return IERC721ReceiverFixture.onERC721Received.selector;
    }
}

contract NFTMintAttacker {
    function attemptMint(CappedCollectionFixture collection) external returns (bool) {
        (bool ok,) = address(collection).call(abi.encodeCall(collection.mint, (address(this), 99)));
        return ok;
    }
}

contract NFTTransferActor {
    function transfer(CappedCollectionFixture collection, address from, address to, uint256 tokenId) external returns (bool) {
        (bool ok,) = address(collection).call(abi.encodeCall(collection.transferFrom, (from, to, tokenId)));
        return ok;
    }
}

contract CappedCollectionTest {
    function testOwnerCanMintAndSupplyNeverExceedsCap() public {
        CappedCollectionFixture collection = new CappedCollectionFixture(1);
        collection.mint(address(this), 1);
        assert(collection.ownerOf(1) == address(this));
        assert(collection.totalSupply() == 1);
        (bool ok,) = address(collection).call(abi.encodeCall(collection.mint, (address(this), 2)));
        assert(!ok);
        assert(collection.totalSupply() == 1);
    }

    function testNonOwnerCannotMint() public {
        CappedCollectionFixture collection = new CappedCollectionFixture(2);
        NFTMintAttacker attacker = new NFTMintAttacker();
        assert(!attacker.attemptMint(collection));
        assert(collection.totalSupply() == 0);
    }

    function testApprovedAddressCanTransferAndApprovalIsCleared() public {
        CappedCollectionFixture collection = new CappedCollectionFixture(2);
        collection.mint(address(this), 7);
        collection.approve(address(0xBEEF), 7);
        NFTTransferActor approved = new NFTTransferActor();
        collection.approve(address(approved), 7);
        assert(approved.transfer(collection, address(this), address(0xCAFE), 7));
        assert(collection.ownerOf(7) == address(0xCAFE));
        assert(collection.getApproved(7) == address(0));
    }

    function testSafeMintCallsReceiverAfterOwnershipIsRecorded() public {
        CappedCollectionFixture collection = new CappedCollectionFixture(2);
        AcceptingNFTReceiver receiver = new AcceptingNFTReceiver();
        collection.safeMint(address(receiver), 9, "");
        assert(collection.ownerOf(9) == address(receiver));
        assert(receiver.receivedTokenId() == 9);
    }
}
