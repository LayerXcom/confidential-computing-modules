pragma solidity ^0.5.0;

import "./reportsHandle.sol";

// Consider: Avoid inheritting
contract AnonymousERC20 is ReportsHandle {
    // Latest encrypted balances in each account
    bytes4[] public encryptedBalances;

    function transfer(bytes4 _updateBalance, bytes memory _report, bytes memory _sig) public {
        require(isEqualMrEnclave(_report, _sig), "mrenclave included in the report is not correct.");
        encryptedBalances.push(_updateBalance);
    }

    function getAllBalances() public view returns(bytes4[] memory) {
        return encryptedBalances;
    }

    function getBalancesLength() public view returns(uint256) {
        return encryptedBalances.length;
    }
}
