// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.4;

import "./Anonify.sol";

contract DeployAnonify {
    address private _anonifyAddress;

    event DeployedAnonify(address addr);

    constructor() {}

    function deploy() public {
        Anonify anonify = new Anonify();
        address anonifyAddr = address(anonify);
        _anonifyAddress = anonifyAddr;

        emit DeployedAnonify(_anonifyAddress);
    }

    function getAnonifyAddress() public view returns (address) {
        return _anonifyAddress;
    }
}
