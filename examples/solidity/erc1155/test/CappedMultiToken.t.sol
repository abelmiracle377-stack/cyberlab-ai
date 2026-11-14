// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/CappedMultiToken.sol";

contract AcceptingMultiTokenReceiver is IERC1155ReceiverFixture {
    uint256 public receivedId;
    uint256 public receivedAmount;
    uint256 public batchLength;

    function onERC1155Received(address, address, uint256 id, uint256 amount, bytes calldata) external returns (bytes4) {
        receivedId = id;
        receivedAmount = amount;
        return IERC1155ReceiverFixture.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata ids, uint256[] calldata, bytes calldata) external returns (bytes4) {
        batchLength = ids.length;
        return IERC1155ReceiverFixture.onERC1155BatchReceived.selector;
    }
}

contract RejectingMultiTokenReceiver is IERC1155ReceiverFixture {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) { return bytes4(0); }
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure returns (bytes4) { return bytes4(0); }
}

contract MultiTokenActor {
    function mint(CappedMultiTokenFixture token, address to, uint256 id, uint256 amount) external returns (bool) {
        (bool ok,) = address(token).call(abi.encodeCall(token.mint, (to, id, amount, "")));
        return ok;
    }
    function transfer(CappedMultiTokenFixture token, address from, address to, uint256 id, uint256 amount) external returns (bool) {
        (bool ok,) = address(token).call(abi.encodeCall(token.safeTransferFrom, (from, to, id, amount, "")));
        return ok;
    }
}

contract CappedMultiTokenTest {
    function testPerIdSupplyCapAndMintAuthority() public {
        CappedMultiTokenFixture token = new CappedMultiTokenFixture();
        token.setCap(1, 10);
        token.mint(address(this), 1, 7, "");
        (bool overCap,) = address(token).call(abi.encodeCall(token.mint, (address(this), 1, 4, "")));
        assert(!overCap);
        MultiTokenActor attacker = new MultiTokenActor();
        assert(!attacker.mint(token, address(attacker), 1, 1));
        assert(token.totalSupply(1) == 7);
    }

    function testBatchMintAndBalanceBatch() public {
        CappedMultiTokenFixture token = new CappedMultiTokenFixture();
        token.setCap(2, 10);
        token.setCap(3, 10);
        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = 2; ids[1] = 3;
        amounts[0] = 4; amounts[1] = 6;
        token.mintBatch(address(this), ids, amounts, "");
        address[] memory accounts = new address[](2);
        accounts[0] = address(this); accounts[1] = address(this);
        uint256[] memory values = token.balanceOfBatch(accounts, ids);
        assert(values[0] == 4 && values[1] == 6);
    }

    function testApprovedOperatorCanTransferAndPauseBlocksTransfers() public {
        CappedMultiTokenFixture token = new CappedMultiTokenFixture();
        token.setCap(5, 10);
        token.mint(address(this), 5, 8, "");
        MultiTokenActor operator = new MultiTokenActor();
        token.setApprovalForAll(address(operator), true);
        assert(operator.transfer(token, address(this), address(0xBEEF), 5, 3));
        assert(token.balanceOf(address(0xBEEF), 5) == 3);
        token.setPaused(true);
        assert(!operator.transfer(token, address(this), address(0xBEEF), 5, 1));
    }

    function testSafeBatchMintCallsReceiverAndTracksIds() public {
        CappedMultiTokenFixture token = new CappedMultiTokenFixture();
        token.setCap(8, 10);
        token.setCap(9, 10);
        AcceptingMultiTokenReceiver receiver = new AcceptingMultiTokenReceiver();
        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = 8; ids[1] = 9;
        amounts[0] = 2; amounts[1] = 3;
        token.mintBatch(address(receiver), ids, amounts, "");
        assert(receiver.batchLength() == 2);
        assert(token.balanceOf(address(receiver), 8) == 2);
    }

    function testRejectingReceiverRollsBackMintState() public {
        CappedMultiTokenFixture token = new CappedMultiTokenFixture();
        token.setCap(11, 5);
        RejectingMultiTokenReceiver receiver = new RejectingMultiTokenReceiver();
        (bool ok,) = address(token).call(abi.encodeCall(token.mint, (address(receiver), 11, 2, "")));
        assert(!ok);
        assert(token.totalSupply(11) == 0);
        assert(token.balanceOf(address(receiver), 11) == 0);
    }
}
