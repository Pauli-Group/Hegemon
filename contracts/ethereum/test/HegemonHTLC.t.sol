// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "../HegemonHTLC.sol";
interface Vm {
    function deal(address,uint256) external;
    function prank(address) external;
    function warp(uint256) external;
    function expectRevert(bytes calldata) external;
}
contract HegemonHTLCTest {
    Vm constant vm=Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address payable constant alice=payable(address(0xA11CE));
    address payable bob=payable(address(this));
    bytes32 constant secret=bytes32(uint256(123));
    HegemonHTLC escrow;
    receive() external payable {}
    function setUp() public {
        vm.deal(bob,10 ether);
        escrow=new HegemonHTLC{value:1 ether}(sha256(abi.encodePacked(secret)),alice,block.timestamp+100);
    }
    function testClaimPaysExactValue() public {
        uint256 before=alice.balance;
        vm.prank(alice);escrow.claim(secret);
        require(escrow.spent() && address(escrow).balance==0 && alice.balance==before+1 ether);
    }
    function testWrongSecretRejected() public {
        vm.expectRevert(bytes("wrong preimage"));vm.prank(alice);escrow.claim(bytes32(0));
        require(!escrow.spent() && address(escrow).balance==1 ether);
    }
    function testUnauthorizedClaimRejected() public {
        vm.expectRevert(bytes("claimant only"));vm.prank(bob);escrow.claim(secret);
    }
    function testEarlyRefundRejected() public {
        vm.expectRevert(bytes("refund premature"));vm.prank(bob);escrow.refund();
    }
    function testRefundBoundaryPaysOwner() public {
        vm.warp(escrow.expiry());uint256 before=bob.balance;
        vm.prank(bob);escrow.refund();require(bob.balance==before+1 ether);
    }
    function testClaimAtBoundaryRejected() public {
        vm.warp(escrow.expiry());
        vm.expectRevert(bytes("claim expired"));vm.prank(alice);escrow.claim(secret);
    }
    function testUnauthorizedRefundRejected() public {
        vm.warp(escrow.expiry());
        vm.expectRevert(bytes("refundee only"));vm.prank(alice);escrow.refund();
    }
    function testRepeatedClaimRejected() public {
        vm.prank(alice);escrow.claim(secret);
        vm.expectRevert(bytes("spent"));vm.prank(alice);escrow.claim(secret);
    }
    function testClaimAfterRefundRejected() public {
        vm.warp(escrow.expiry());vm.prank(bob);escrow.refund();
        vm.expectRevert(bytes("spent"));vm.prank(alice);escrow.claim(secret);
    }
}
