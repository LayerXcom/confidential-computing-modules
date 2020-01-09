pragma solidity ^0.5.0;

import "./ReportsHandle.sol";

// Consider: Avoid inheritting
contract AnonymousAsset is ReportsHandle {
    event StoreCiphertext(bytes ciphertext);

    // Latest encrypted balances in each account
    bytes[] public encryptedBalances;

    constructor(
        bytes memory _initEncState,
        bytes memory _report,
        bytes memory _sig
    ) ReportsHandle(_report, _sig) public {
        encryptedBalances.push(_initEncState);

        emit StoreCiphertext(_initEncState);
    }

    function transfer(
        bytes memory _encState1,
        bytes memory _encState2,
        bytes memory _report,
        bytes memory _sig
    ) public {
        require(isEqualMrEnclave(_report, _sig), "mrenclave included in the report is not correct.");
        encryptedBalances.push(_encState1);
        encryptedBalances.push(_encState2);

        emit StoreCiphertext(_encState1);
        emit StoreCiphertext(_encState2);
    }
}
