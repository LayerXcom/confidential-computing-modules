// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.4;

import "./AnonifyWithTreeKem.sol";
import "./AnonifyWithEnclaveKey.sol";

contract DeployAnonify {
    address private _anonifyAddress;

    event DeployedAnonify(address addr);

    constructor() {}

    function deployAnonifyWithTreeKem() public {
        AnonifyWithTreeKem anonify = new AnonifyWithTreeKem();
        _anonifyAddress = address(anonify);

        emit DeployedAnonify(_anonifyAddress);
    }

    function deployAnonifyWithEnclaveKey() public {
        AnonifyWithEnclaveKey anonify = new AnonifyWithEnclaveKey();
        _anonifyAddress = address(anonify);

        emit DeployedAnonify(_anonifyAddress);
    }

    function getAnonifyAddress() public view returns (address) {
        return _anonifyAddress;
    }
}
