// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20HTLC { function balanceOf(address) external view returns (uint256); }
interface IERC721HTLC {
    function ownerOf(uint256) external view returns (address);
    function safeTransferFrom(address, address, uint256) external;
}
interface IERC1155HTLC {
    function balanceOf(address, uint256) external view returns (uint256);
    function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external;
}

/// @notice A single, explicitly funded token escrow for local HTLC swap experiments.
contract TokenHTLC {
    enum Kind { ERC20, ERC721, ERC1155 }
    Kind public immutable kind;
    address public immutable token;
    uint256 public immutable tokenId;
    uint256 public immutable amount;
    bytes32 public immutable hashlock;
    address public immutable claimant;
    address public immutable refundee;
    uint256 public immutable expiry;
    bool public funded;
    bool public spent;
    bool private entered;
    bool private receiving;

    event Funded();
    event Claimed(bytes32 preimage);
    event Refunded();

    modifier guard() {
        require(!entered, "reentrant");
        entered = true;
        _;
        entered = false;
    }

    constructor(Kind assetKind, address asset, uint256 id, uint256 quantity, bytes32 digest, address receiver, uint256 deadline) {
        require(asset.code.length != 0, "token has no code");
        require(receiver != address(0) && receiver != address(this), "invalid claimant");
        require(quantity != 0 && (assetKind != Kind.ERC721 || quantity == 1), "invalid amount");
        require(assetKind != Kind.ERC20 || id == 0, "invalid token id");
        require(deadline > block.timestamp, "expired deadline");
        kind = assetKind; token = asset; tokenId = id; amount = quantity;
        hashlock = digest; claimant = receiver; refundee = msg.sender; expiry = deadline;
    }

    function fund() external guard {
        require(msg.sender == refundee, "refundee only");
        require(!funded && !spent, "already funded");
        require(block.timestamp < expiry, "expired deadline");
        receiving = true;
        if (kind == Kind.ERC20) {
            uint256 beforeBalance = IERC20HTLC(token).balanceOf(address(this));
            uint256 beforeSender = IERC20HTLC(token).balanceOf(refundee);
            _erc20(abi.encodeWithSignature("transferFrom(address,address,uint256)", refundee, address(this), amount));
            require(IERC20HTLC(token).balanceOf(address(this)) == beforeBalance + amount && IERC20HTLC(token).balanceOf(refundee) + amount == beforeSender, "inexact funding");
        } else if (kind == Kind.ERC721) {
            IERC721HTLC(token).safeTransferFrom(refundee, address(this), tokenId);
            require(IERC721HTLC(token).ownerOf(tokenId) == address(this), "not escrowed");
        } else {
            uint256 beforeBalance = IERC1155HTLC(token).balanceOf(address(this), tokenId);
            uint256 beforeSender = IERC1155HTLC(token).balanceOf(refundee, tokenId);
            IERC1155HTLC(token).safeTransferFrom(refundee, address(this), tokenId, amount, "");
            require(IERC1155HTLC(token).balanceOf(address(this), tokenId) == beforeBalance + amount && IERC1155HTLC(token).balanceOf(refundee, tokenId) + amount == beforeSender, "inexact funding");
        }
        receiving = false;
        funded = true;
        emit Funded();
    }

    function claim(bytes32 preimage) external guard {
        require(funded && !spent, "unavailable");
        require(msg.sender == claimant, "claimant only");
        require(block.timestamp < expiry, "claim expired");
        require(sha256(abi.encodePacked(preimage)) == hashlock, "wrong preimage");
        spent = true;
        _pay(claimant);
        emit Claimed(preimage);
    }

    function refund() external guard {
        require(funded && !spent, "unavailable");
        require(msg.sender == refundee, "refundee only");
        require(block.timestamp >= expiry, "refund premature");
        spent = true;
        _pay(refundee);
        emit Refunded();
    }

    function _pay(address recipient) private {
        if (kind == Kind.ERC20) {
            uint256 beforeEscrow = IERC20HTLC(token).balanceOf(address(this));
            uint256 beforeRecipient = IERC20HTLC(token).balanceOf(recipient);
            _erc20(abi.encodeWithSignature("transfer(address,uint256)", recipient, amount));
            require(IERC20HTLC(token).balanceOf(address(this)) + amount == beforeEscrow && IERC20HTLC(token).balanceOf(recipient) == beforeRecipient + amount, "inexact payout");
        } else if (kind == Kind.ERC721) {
            IERC721HTLC(token).safeTransferFrom(address(this), recipient, tokenId);
            require(IERC721HTLC(token).ownerOf(tokenId) == recipient, "inexact payout");
        } else {
            uint256 beforeEscrow = IERC1155HTLC(token).balanceOf(address(this), tokenId);
            uint256 beforeRecipient = IERC1155HTLC(token).balanceOf(recipient, tokenId);
            IERC1155HTLC(token).safeTransferFrom(address(this), recipient, tokenId, amount, "");
            require(IERC1155HTLC(token).balanceOf(address(this), tokenId) + amount == beforeEscrow && IERC1155HTLC(token).balanceOf(recipient, tokenId) == beforeRecipient + amount, "inexact payout");
        }
    }

    function _erc20(bytes memory data) private {
        (bool ok, bytes memory result) = token.call(data);
        require(ok && (result.length == 0 || (result.length == 32 && abi.decode(result, (bool)))), "token transfer failed");
    }

    function onERC721Received(address operator, address from, uint256 id, bytes calldata) external view returns (bytes4) {
        require(receiving && kind == Kind.ERC721 && msg.sender == token && operator == address(this) && from == refundee && id == tokenId, "unexpected token");
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata) external view returns (bytes4) {
        require(receiving && kind == Kind.ERC1155 && msg.sender == token && operator == address(this) && from == refundee && id == tokenId && value == amount, "unexpected token");
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure returns (bytes4) {
        revert("batch unsupported");
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 || interfaceId == 0x4e2312e0;
    }
}
