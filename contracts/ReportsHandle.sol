pragma solidity ^0.5.0;

import "./utils/SafeMath.sol";
import "./utils/SolRsaVerify.sol";
import "./utils/Base64.sol";
import "./utils/BytesUtils.sol";
import "./utils/Secp256k1.sol";

contract ReportsHandle {
    using SafeMath for uint256;

    // extracted data from REPORT
    // struct ReportData {
    //     bytes32 mrenclave;
    //     address enclaveAddress;
    //     bytes32 reportNonce;
    // }

    // A cryptographic hash of the measurement.
    // Different builds/versions of an enclave will result in a different MRENCLAVE value.
    bytes32 private _mrEnclave;

    // Compact formatted secp256k1 public key. The size is 33 bytes.
    mapping(address => address) public enclaveAddress;
    // Nonce data which is included `reportdata` field and used to prevent from replay attacks.
    // The size is 31 bytes because `reportdata` field is 64 bytes size. We use it for Enclave Public key to rest of the field.
    // This Report Nonce is not actually needed because the existing check of enclave public key provides replay protection features.
    // We, however, check additional replay checks because the size of `reportdata` is fixed to 64 bytes size,
    // so we have the left over of 31 bytes data field.
    // We may remove this feature for perfomance.
    mapping(bytes32 => bytes32) private _reportNonce;

    // this is the modulus and the exponent of intel's certificate, you can extract it using:
    // `openssl x509 -noout -modulus -in AttestationReportSigningCert.pem` and `openssl x509 -in AttestationReportSigningCert.pem -text`.
    bytes constant internal RSA_EXP = hex"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
    bytes constant internal RSA_MOD = hex"A97A2DE0E66EA6147C9EE745AC0162686C7192099AFC4B3F040FAD6DE093511D74E802F510D716038157DCAF84F4104BD3FED7E6B8F99C8817FD1FF5B9B864296C3D81FA8F1B729E02D21D72FFEE4CED725EFE74BEA68FBC4D4244286FCDD4BF64406A439A15BCB4CF67754489C423972B4A80DF5C2E7C5BC2DBAF2D42BB7B244F7C95BF92C75D3B33FC5410678A89589D1083DA3ACC459F2704CD99598C275E7C1878E00757E5BDB4E840226C11C0A17FF79C80B15C1DDB5AF21CC2417061FBD2A2DA819ED3B72B7EFAA3BFEBE2805C9B8AC19AA346512D484CFC81941E15F55881CC127E8F7AA12300CD5AFB5742FA1D20CB467A5BEB1C666CF76A368978B5";
    uint constant internal WORD_SIZE = 32;

    // Set new mrenclave value and enclave address
    constructor(bytes memory _report, bytes memory _reportSig) public {
        (bytes32 inpMrEnclave, address inpEnclaveAddr, bytes32 reportNonce) = extractFromReport(_report, _reportSig);
        require(_mrEnclave == 0, "mrenclave included in the report is not correct.");

        _mrEnclave = inpMrEnclave;
        _reportNonce[reportNonce] = reportNonce;
        enclaveAddress[inpEnclaveAddr] = inpEnclaveAddr;
    }

    // Check mrenclave value and report signature and then set new enclave address.
    function handleReport(bytes memory _report, bytes memory _reportSig) public {
        (bytes32 inpMrEnclave, address inpEnclaveAddr, bytes32 reportNonce) = extractFromReport(_report, _reportSig);
        require(_mrEnclave == inpMrEnclave, "mrenclave included in the report is not correct.");

        _reportNonce[reportNonce] = reportNonce;
        enclaveAddress[inpEnclaveAddr] = inpEnclaveAddr;
    }

    function extractFromReport(bytes memory _report, bytes memory _reportSig) internal view returns (bytes32, address, bytes32) {
        require(verifyReportSig(_report, _reportSig) == 0, "Invalid report's signature");
        bytes memory quote = extractQuote(_report);
        // See https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf, P.23.
        bytes32 mrEnclave = BytesUtils.toBytes32(extractElement(quote, 112, 32), 0);
        address inpEnclaveAddr = BytesUtils.toAddress(extractElement(quote, 368, 20), 0);
        bytes32 reportNonce = BytesUtils.toBytes32(extractElement(quote, 388, 32), 0);
        require(enclaveAddress[inpEnclaveAddr] == address(0), "The enclave public key has already been registered.");
        require(_reportNonce[reportNonce] == 0, "The report nonce has already been used.");

        return (mrEnclave, inpEnclaveAddr, reportNonce);
    }

    function extractQuote(bytes memory _report) internal pure returns(bytes memory) {
        uint256 i = 0;
        // find the word "Body" in the report, so that we can extract "isvEnclaveQuoteBody" field data.
        while(i < _report.length && !(
            _report[i] == 0x42 &&
            _report[i+1] == 0x6f &&
            _report[i+2] == 0x64 &&
            _report[i+3] == 0x79
        )) {
            i++;
        }

        require(i < _report.length, "isvEnclaveQuoteBody not found in report");
        // Add the length of 'Body":"' to find where the quote starts
        i = i + 7;

        // 576 bytes is the length of the quote
        bytes memory quoteBody = extractElement(_report, i, 576);
        return Base64.decode(quoteBody);
    }

    function verifyReportSig(bytes memory _report, bytes memory _reportSig) internal view returns(uint256) {
        return SolRsaVerify.pkcs1Sha256VerifyRaw(_report, _reportSig, RSA_EXP, RSA_MOD);
    }

    function extractElement(bytes memory src, uint offset, uint len) internal pure returns (bytes memory) {
        bytes memory o = new bytes(len);
        uint srcptr;
        uint destptr;
        assembly {
            srcptr := add(add(src,32), offset)
            destptr := add(o,32)
        }
        copy(srcptr, destptr, len);
        return o;
    }

    // Borrowed from https://ethereum.stackexchange.com/a/50528/24704
    function bytesToAddress(bytes memory bys) internal pure returns (address addr) {
        assembly {
          addr := mload(add(bys,20))
        }
    }

    // Borrowed from https://github.com/ethereum/solidity-examples/blob/cb43c26d17617d7dad34936c34dd8f423453c1cf/src/unsafe/Memory.sol#L57
    // Copy 'len' bytes from memory address 'src', to address 'dest'.
    // This function does not check the or destination, it only copies the bytes.
    function copy(uint src, uint dest, uint len) internal pure {
        // Copy word-length chunks while possible
        for (; len >= WORD_SIZE; len -= WORD_SIZE) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += WORD_SIZE;
            src += WORD_SIZE;
        }

        // Copy remaining bytes
        uint mask = 256 ** (WORD_SIZE - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }
}
