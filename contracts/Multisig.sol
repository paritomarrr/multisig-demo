// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "hardhat/console.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MultiSig is AccessControl {
    using ECDSA for bytes32;
    using Address for address;
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 private Withdraw_message = keccak256("WITHDRAWAL");
    // bytes32 private constant WITHDRAWAL_TYPEHASH = keccak256("Withdrawal(address[] tokens,uint256[] amounts,uint256 ethAmount)");

    event Withdrawn(address indexed to, address[] tokens, uint256[] amounts, uint256 ethAmount);

    constructor(address _firstSigner, address _secondSigner){
        _grantRole(SIGNER_ROLE, _firstSigner);
        _grantRole(SIGNER_ROLE, _secondSigner);
    }

    function withdrawal(
        address[] memory _tokens, 
        uint256[] memory _amounts,
        uint256 _ethAmount,
        bytes[] memory _signatures
    ) external onlyRole(SIGNER_ROLE) returns (bool) {
        require(_signatures.length == 2, "Requires two signatures");

        address signer1 = verifySignature(Withdraw_message, _signatures[0]);
        address signer2 = verifySignature(Withdraw_message, _signatures[1]);
        // console.log(signer1, signer2);
        require(hasRole(SIGNER_ROLE, signer1) && hasRole(SIGNER_ROLE, signer2), "Invalid signatures");

        for (uint256 i = 0; i < _tokens.length; i++) {
            IERC20(_tokens[i]).transfer(msg.sender, _amounts[i]);
        }
        
        if (_ethAmount > 0) {
            payable(msg.sender).transfer(_ethAmount);
        }

        emit Withdrawn(msg.sender, _tokens, _amounts, _ethAmount);
        return true;
    }

    function verifySignature(
        bytes32 message,
        bytes memory signature
        ) public pure returns (address) {
            bytes32 hash = MessageHashUtils.toEthSignedMessageHash(message);
            console.logBytes32(hash);
            address recoveredSigner = hash.recover(signature);
            return recoveredSigner;
    }

    function clone(address _firstSigner, address _secondSigner) external returns (address) {
        address cloneAddress = Clones.clone(address(this));
        MultiSig(payable(cloneAddress)).initialize(_firstSigner, _secondSigner);
        return cloneAddress;
    }

    function initialize(address _firstSigner, address _secondSigner) external {
        require(!hasRole(SIGNER_ROLE, _firstSigner) && !hasRole(SIGNER_ROLE, _secondSigner), "Already initialized");
        _grantRole(SIGNER_ROLE, _firstSigner);
        _grantRole(SIGNER_ROLE, _secondSigner);
    }

    receive() external payable {}
}