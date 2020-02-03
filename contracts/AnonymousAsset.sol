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

    function stateTransition(
        bytes memory _encState1,
        bytes memory _encState2,
        bytes32 _lockParam,
        uint8 _secp256k1_prefix,
        uint256 _secp256k1_x
    ) public {
        require(lockParams[_lockParam] == 0, "The state has already been modified.");
        lockParams[_lockParam] = _lockParam;

        encryptedBalances.push(_encState1);
        encryptedBalances.push(_encState2);

        emit StoreCiphertext(_encState1);
        emit StoreCiphertext(_encState2);
    }

    function register(bytes memory _report, bytes memory _sig) public {
        require(isEqualMrEnclave(_report, _sig), "mrenclave included in the report is not correct.");

        // TODO: Store public key and nonce from _report
    }
}
