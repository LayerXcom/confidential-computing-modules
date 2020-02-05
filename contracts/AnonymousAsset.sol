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
        bytes memory _reportSig
    ) ReportsHandle(_report, _reportSig) public { }

    // Register a new TEE participant.
    function register(bytes memory _report, bytes memory _reportSig) public {
        handleReport(_report, _reportSig);
    }

    // emurate deploying new contracts and storing ciphertexts.
    function initState(
        uint256 _stateId,
        bytes memory _ciphertext,
        bytes32 _lockParam,
        bytes memory _enclaveSig
    ) public {
        require(_ciphertexts[_stateId].length == 0, "The state id has been already initialized.");
        require(_lockParams[_stateId][_lockParam] == 0, "The state has already been modified.");
        address inpEnclaveAddr = Secp256k1.recover(_lockParam, _enclaveSig);
        require(enclaveAddress[inpEnclaveAddr] == inpEnclaveAddr, "Invalid enclave signature.");

        _lockParams[_stateId][_lockParam] = _lockParam;
        _ciphertexts[_stateId].push(_ciphertext);

        emit StoreCiphertext(_ciphertext);
    }

    // _message: a message signed by enclave private key
    function stateTransition(
        uint256 _stateId,
        bytes memory _ciphertext1,
        bytes memory _ciphertext2,
        bytes32 _lockParam1,
        bytes32 _lockParam2,
        bytes memory _enclaveSig
    ) public {
        require(_ciphertexts[_stateId].length != 0, "The state id has not been initialized yet.");
        require(_lockParams[_stateId][_lockParam1] == 0, "The state has already been modified.");
        require(_lockParams[_stateId][_lockParam2] == 0, "The state has already been modified.");
        address inpEnclaveAddr = Secp256k1.recover(_lockParam1, _enclaveSig);
        require(enclaveAddress[inpEnclaveAddr] == inpEnclaveAddr, "Invalid enclave signature.");

        _lockParams[_stateId][_lockParam1] = _lockParam1;
        _lockParams[_stateId][_lockParam2] = _lockParam2;
        _ciphertexts[_stateId].push(_ciphertext1);
        _ciphertexts[_stateId].push(_ciphertext2);

        emit StoreCiphertext(_ciphertext1);
        emit StoreCiphertext(_ciphertext2);
    }
}
