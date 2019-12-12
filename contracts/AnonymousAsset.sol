pragma solidity ^0.5.0;

import "./ReportsHandle.sol";

// Consider: Avoid inheritting
contract AnonymousAsset is ReportsHandle {
    event Transfer(bytes _updateBalance1, bytes _updateBalance2);

    // Latest encrypted balances in each account
    bytes[] public encryptedBalances;

    constructor(
        bytes memory _initBalance,
        bytes memory _report,
        bytes memory _sig
    ) ReportsHandle(_report, _sig) public {
        // require(isEqualMrEnclave(_report, _sig), "mrenclave included in the report is not correct.");
        encryptedBalances.push(_initBalance);
    }

    function transfer(
        bytes memory _updateBalance1,
        bytes memory _updateBalance2,
        bytes memory _report,
        bytes memory _sig
    ) public {
        // require(isEqualMrEnclave(_report, _sig), "mrenclave included in the report is not correct.");
        encryptedBalances.push(_updateBalance1);
        encryptedBalances.push(_updateBalance2);

        emit Transfer(_updateBalance1, _updateBalance2);
    }

    // function getBalances(uint offset, uint len) public view returns (bytes4[] memory) {
    //     return encryptedBalances.bytes4_range(offset, len);
    // }

    // function getAllBalances() public view returns (bytes4[] memory) {
    //     return encryptedBalances;
    // }

    // function getBalancesLength() public view returns (uint256) {
    //     return encryptedBalances.length;
    // }
}
