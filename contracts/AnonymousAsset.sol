pragma solidity ^0.5.0;

import "./ReportsHandle.sol";
import "./utils/Secp256k1.sol";

// Consider: Avoid inheritting
contract AnonymousAsset is ReportsHandle {
    event StoreCiphertext(bytes ciphertext);

    // Encrypted states
    mapping(uint256 => bytes[]) private _ciphertexts;
    // Store lock parameters to avoid form data collision.
    mapping(uint256 => mapping (bytes32 => bytes32)) private _lockParams;

    constructor(
        bytes memory _report,
        bytes memory _sig
    ) ReportsHandle(_report, _sig) public { }

    // Register a new TEE participant.
    function register(bytes memory _report, bytes memory _sig) public {
        handleReport(_report, _sig);
    }

    // emurate deploying new contracts and storing ciphertexts.
    function initEncState(uint256 _stateId, bytes memory _initEncState, bytes32 _lockParam) public {
        require(_ciphertexts[_stateId].length == 0, "The state id has been already initialized.");

        _lockParams[_stateId][_lockParam] = _lockParam;
        _ciphertexts[_stateId].push(_initEncState);

        emit StoreCiphertext(_initEncState);
    }

    // _message: a message signed by enclave private key
    function stateTransition(
        uint256 _stateId,
        bytes memory _ciphertext1,
        bytes memory _ciphertext2,
        bytes32 _lockParam1,
        bytes32 _lockParam2,
        bytes memory _enclaveSig,
        bytes32 _message
    ) public {
        require(_ciphertexts[_stateId].length != 0, "The state id has not been initialized yet.");
        require(_lockParams[_stateId][_lockParam1] == 0, "The state has already been modified.");
        require(_lockParams[_stateId][_lockParam2] == 0, "The state has already been modified.");
        address inpEnclaveAddr = Secp256k1.recover(_message, _enclaveSig);
        require(enclaveAddress[inpEnclaveAddr] == inpEnclaveAddr, "Invalid enclave signature.");

        _lockParams[_stateId][_lockParam1] = _lockParam1;
        _lockParams[_stateId][_lockParam2] = _lockParam2;
        _ciphertexts[_stateId].push(_ciphertext1);
        _ciphertexts[_stateId].push(_ciphertext2);

        emit StoreCiphertext(_ciphertext1);
        emit StoreCiphertext(_ciphertext2);
    }
}
