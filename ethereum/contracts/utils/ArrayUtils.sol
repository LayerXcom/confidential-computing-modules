pragma solidity ^0.5.0;

library ArrayUtils {
    function bytes4_range(bytes4[] memory self, uint offset, uint len) internal pure returns (bytes4[] memory res) {
        res = new bytes4[](len);
        uint j = offset;
        for (uint i = 0; i < res.length; i++) {
            res[i] = self[j];
            j++;
        }
    }
}
