// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";

contract MultiSig is AccessControl, EIP712 {
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 private constant WITHDRAWAL_TYPEHASH = keccak256("Withdrawal(address[] tokens,uint256[] amounts,uint256 ethAmount)");

    event Withdrawn(address indexed to, address[] tokens, uint256[] amounts, uint256 ethAmount);
    event DebugHash(bytes32 digest);
    event DebugSigners(address signer1, address signer2);

    constructor(address _firstSigner, address _secondSigner)
        EIP712("MultiSig", "1.0")
    {
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

        // Hash the withdrawal data using EIP712 structure
        bytes32 structHash = keccak256(
            abi.encode(WITHDRAWAL_TYPEHASH, _tokens, _amounts, _ethAmount)
        );
        bytes32 digest = _hashTypedDataV4(structHash);

        emit DebugHash(digest);

        address signer1 = ECDSA.recover(digest, _signatures[0]);
        address signer2 = ECDSA.recover(digest, _signatures[1]);

        emit DebugSigners(signer1, signer2);

        require(hasRole(SIGNER_ROLE, signer1) && hasRole(SIGNER_ROLE, signer2), "Invalid signatures");
        require(signer1 != signer2, "Signers 1 and 2 must be different");

        // Transfer the ERC20 tokens
        for (uint256 i = 0; i < _tokens.length; i++) {
            IERC20(_tokens[i]).transfer(msg.sender, _amounts[i]);
        }

        // Transfer ETH if specified
        if (_ethAmount > 0) {
            payable(msg.sender).transfer(_ethAmount);
        }

        emit Withdrawn(msg.sender, _tokens, _amounts, _ethAmount);
        return true;
    }

    function clone(address _firstSigner, address _secondSigner)
        external
        returns (address)
    {
        address cloneAddress = Clones.clone(address(this));
        MultiSig(payable(cloneAddress)).initialize(_firstSigner, _secondSigner);
        return cloneAddress;
    }

    function initialize(address _firstSigner, address _secondSigner) external {
        require(
            !hasRole(SIGNER_ROLE, _firstSigner) &&
                !hasRole(SIGNER_ROLE, _secondSigner),
            "Already initialized"
        );
        _grantRole(SIGNER_ROLE, _firstSigner);
        _grantRole(SIGNER_ROLE, _secondSigner);
    }

    receive() external payable {}
}
