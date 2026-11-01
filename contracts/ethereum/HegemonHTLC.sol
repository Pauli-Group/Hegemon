// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Native-ETH escrow paired with a Hegemon SHA-256 HTLC.
contract HegemonHTLC {
    bytes32 public immutable hashlock;
    address payable public immutable claimant;
    address payable public immutable refundee;
    uint256 public immutable expiry;
    bool public spent;

    event Claimed(bytes32 preimage, address indexed recipient, uint256 amount);
    event Refunded(address indexed recipient, uint256 amount);

    constructor(bytes32 digest, address payable receiver, uint256 deadline) payable {
        require(msg.value > 0, "empty escrow");
        require(receiver != address(0), "zero claimant");
        require(deadline > block.timestamp, "expired deadline");
        hashlock = digest;
        claimant = receiver;
        refundee = payable(msg.sender);
        expiry = deadline;
    }

    function claim(bytes32 preimage) external {
        require(!spent, "spent");
        require(msg.sender == claimant, "claimant only");
        require(block.timestamp < expiry, "claim expired");
        require(sha256(abi.encodePacked(preimage)) == hashlock, "wrong preimage");
        spent = true;
        uint256 amount = address(this).balance;
        emit Claimed(preimage, claimant, amount);
        (bool ok,) = claimant.call{value: amount}("");
        require(ok, "payment failed");
    }

    function refund() external {
        require(!spent, "spent");
        require(msg.sender == refundee, "refundee only");
        require(block.timestamp >= expiry, "refund premature");
        spent = true;
        uint256 amount = address(this).balance;
        emit Refunded(refundee, amount);
        (bool ok,) = refundee.call{value: amount}("");
        require(ok, "payment failed");
    }
}
