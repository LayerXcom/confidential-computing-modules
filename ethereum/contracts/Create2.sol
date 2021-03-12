// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.4;

import "./Anonify.sol";

contract DeployAnonify {
    constructor() {}

    function deploy(bytes32 _salt) public {
        new Anonify{salt: _salt}();
    }
}
