pragma solidity ^0.5.0;

import "./ReportsHandle.sol";
import "./utils/Secp256k1.sol";

// Consider: Avoid inheritting
contract AnonymousAsset is ReportsHandle {
    event StoreCiphertext(bytes ciphertext);

    // Latest encrypted balances in each account
    bytes[] public encryptedBalances;
    // Store lock parameters to avoid form data collision.
    mapping(bytes32 => bytes32) public lockParams;

    constructor(
        bytes memory _initEncState,
        bytes memory _report,
        bytes memory _sig
    ) ReportsHandle(_report, _sig) public {
        encryptedBalances.push(_initEncState);

        emit StoreCiphertext(_initEncState);
    }

    // _message: a message signed by enclave private key
    function stateTransition(
        bytes memory _ciphertext1,
        bytes memory _ciphertext2,
        bytes32 _lockParam,
        bytes memory _enclaveSig,
        bytes32 _message
    ) public {
        require(lockParams[_lockParam] == 0, "The state has already been modified.");
        address enclaveAddr = Secp256k1.recover(_message, _enclaveSig);
        require(EnclaveAddress[enclaveAddr] == enclaveAddr, "Invalid enclave signature.");

        lockParams[_lockParam] = _lockParam;

        encryptedBalances.push(_ciphertext1);
        encryptedBalances.push(_ciphertext2);

        emit StoreCiphertext(_ciphertext1);
        emit StoreCiphertext(_ciphertext2);
    }

    function register(bytes memory _report, bytes memory _sig) public {
        handleReport(_report, _sig);
    }
}
