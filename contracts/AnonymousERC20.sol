pragma solidity ^0.5.0;

contract AnonymousERC20 {
    // Latest encrypted balances in each account
    bytes4[] public encryptedBalances;

    function transfer(bytes4 _updateBalance, bytes memory _report) public {
        // require(verifyReport(_report), "Invalid report");
        encryptedBalances.push(_updateBalance);
    }

    function getAllBalances() public view returns(bytes4[] memory) {
        return encryptedBalances;
    }

    function getBalancesLength() public view returns(uint256) {
        return encryptedBalances.length;
    }
}
