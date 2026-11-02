// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "../TokenHTLC.sol";
interface TokenVm { function prank(address) external; function warp(uint256) external; function expectRevert(bytes calldata) external; }
contract Sample20 {
    mapping(address=>uint256) public balanceOf;
    mapping(address=>mapping(address=>uint256)) public allowance;
    bool public fee;
    constructor(address owner) { balanceOf[owner]=1000; }
    function setFee(bool value) external { fee=value; }
    function approve(address spender,uint256 value) external returns(bool) { allowance[msg.sender][spender]=value; return true; }
    function transferFrom(address from,address to,uint256 value) external returns(bool) { require(allowance[from][msg.sender]>=value); allowance[from][msg.sender]-=value; _move(from,to,value); return true; }
    function transfer(address to,uint256 value) external returns(bool) { _move(msg.sender,to,value); return true; }
    function _move(address from,address to,uint256 value) internal { balanceOf[from]-=value; balanceOf[to]+=fee ? value-1 : value; }
}
contract Sample721 {
    mapping(uint256=>address) public ownerOf;
    mapping(uint256=>address) public approved;
    constructor(address owner) { ownerOf[42]=owner; }
    function approve(address spender,uint256 id) external { require(msg.sender==ownerOf[id]); approved[id]=spender; }
    function safeTransferFrom(address from,address to,uint256 id) external { require(ownerOf[id]==from && (msg.sender==from || approved[id]==msg.sender)); ownerOf[id]=to; delete approved[id]; if(to.code.length>0) require(TokenHTLC(to).onERC721Received(msg.sender,from,id,"")==TokenHTLC.onERC721Received.selector); }
}
contract Sample1155 {
    mapping(address=>mapping(uint256=>uint256)) private balances;
    mapping(address=>mapping(address=>bool)) public approved;
    constructor(address owner) { balances[owner][7]=100; }
    function balanceOf(address owner,uint256 id) external view returns(uint256) { return balances[owner][id]; }
    function setApprovalForAll(address operator,bool value) external { approved[msg.sender][operator]=value; }
    function safeTransferFrom(address from,address to,uint256 id,uint256 value,bytes calldata data) external { require(msg.sender==from || approved[from][msg.sender]); balances[from][id]-=value; balances[to][id]+=value; if(to.code.length>0) require(TokenHTLC(to).onERC1155Received(msg.sender,from,id,value,data)==TokenHTLC.onERC1155Received.selector); }
}
contract TokenHTLCTest {
    TokenVm constant vm=TokenVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant alice=address(0xA11CE);
    address constant bob=address(0xB0B);
    address constant outsider=address(0xBAD);
    bytes32 constant secret=bytes32(uint256(123));
    Sample20 erc20; Sample721 erc721; Sample1155 erc1155;
    function setUp() public { erc20=new Sample20(bob); erc721=new Sample721(bob); erc1155=new Sample1155(bob); }
    function deploy(TokenHTLC.Kind k,address asset,uint256 id,uint256 amount) internal returns(TokenHTLC e) { bytes32 digest=sha256(abi.encodePacked(secret)); vm.prank(bob); e=new TokenHTLC(k,asset,id,amount,digest,alice,block.timestamp+100); }
    function funded20() internal returns(TokenHTLC e) { e=deploy(TokenHTLC.Kind.ERC20,address(erc20),0,100); vm.prank(bob); erc20.approve(address(e),100); vm.prank(bob); e.fund(); }
    function testERC20Claim() public { TokenHTLC e=funded20(); vm.prank(alice); e.claim(secret); require(erc20.balanceOf(alice)==100 && erc20.balanceOf(address(e))==0 && e.spent()); }
    function testERC20RefundAtExpiry() public { TokenHTLC e=funded20(); vm.warp(e.expiry()); vm.prank(bob); e.refund(); require(erc20.balanceOf(bob)==1000); }
    function testFundingFeeRejected() public { TokenHTLC e=deploy(TokenHTLC.Kind.ERC20,address(erc20),0,100); erc20.setFee(true); vm.prank(bob); erc20.approve(address(e),100); vm.expectRevert(bytes("inexact funding")); vm.prank(bob); e.fund(); require(erc20.balanceOf(bob)==1000 && !e.funded()); }
    function testPayoutFeeRejectedWithoutSpending() public { TokenHTLC e=funded20(); erc20.setFee(true); vm.expectRevert(bytes("inexact payout")); vm.prank(alice); e.claim(secret); require(!e.spent() && erc20.balanceOf(address(e))==100); }
    function testUnauthorizedAndWrongSecret() public { TokenHTLC e=funded20(); vm.expectRevert(bytes("claimant only")); vm.prank(outsider); e.claim(secret); vm.expectRevert(bytes("wrong preimage")); vm.prank(alice); e.claim(bytes32(0)); vm.expectRevert(bytes("refund premature")); vm.prank(bob); e.refund(); }
    function testBoundaryAndRepeat() public { TokenHTLC e=funded20(); vm.warp(e.expiry()); vm.expectRevert(bytes("claim expired")); vm.prank(alice); e.claim(secret); vm.prank(bob); e.refund(); vm.expectRevert(bytes("unavailable")); vm.prank(bob); e.refund(); }
    function testERC721Claim() public { TokenHTLC e=deploy(TokenHTLC.Kind.ERC721,address(erc721),42,1); vm.prank(bob); erc721.approve(address(e),42); vm.prank(bob); e.fund(); require(erc721.ownerOf(42)==address(e)); vm.prank(alice); e.claim(secret); require(erc721.ownerOf(42)==alice); }
    function testERC721Refund() public { TokenHTLC e=deploy(TokenHTLC.Kind.ERC721,address(erc721),42,1); vm.prank(bob); erc721.approve(address(e),42); vm.prank(bob); e.fund(); vm.warp(e.expiry()); vm.prank(bob); e.refund(); require(erc721.ownerOf(42)==bob); }
    function testERC1155Claim() public { TokenHTLC e=deploy(TokenHTLC.Kind.ERC1155,address(erc1155),7,30); vm.prank(bob); erc1155.setApprovalForAll(address(e),true); vm.prank(bob); e.fund(); vm.prank(alice); e.claim(secret); require(erc1155.balanceOf(alice,7)==30 && erc1155.balanceOf(bob,7)==70); }
    function testERC1155Refund() public { TokenHTLC e=deploy(TokenHTLC.Kind.ERC1155,address(erc1155),7,30); vm.prank(bob); erc1155.setApprovalForAll(address(e),true); vm.prank(bob); e.fund(); vm.warp(e.expiry()); vm.prank(bob); e.refund(); require(erc1155.balanceOf(bob,7)==100); }
    function testUnsolicitedNFTRejected() public { TokenHTLC e=deploy(TokenHTLC.Kind.ERC721,address(erc721),42,1); vm.expectRevert(bytes("unexpected token")); vm.prank(bob); erc721.safeTransferFrom(bob,address(e),42); require(erc721.ownerOf(42)==bob); }
}
