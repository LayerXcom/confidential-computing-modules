// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.4;

/**
 * @title Base64 encoding and decoding
 * Solidity port of the original Javascript below
 */

/**
 * Copyright (C) 1999 Masanao Izumo <iz at onicos.co.jp>
 * Version: 1.0
 * LastModified: Dec 25 1999
 * This library is free.  You can redistribute it and/or modify it.
 * Source: http://code.google.com/p/gflot/source/browse/trunk/flot/base64.js
 */

library Base64 {

//    bytes constant base64EncodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    function init_base64DecodeChars() internal pure returns (int8[128] memory base64DecodeChars){
        base64DecodeChars = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1];
    }

//    function encode(bytes memory source) internal pure returns (bytes memory out){
//        uint i=0;
//        uint o=0;
//        uint len = source.length;
//        uint8 c1;
//        uint8 c2;
//        uint8 c3;
//        out = new bytes(source.length*2);
//        while(i<len){
//            c1 = uint8(source[i++]) & 0xff;
//            if(i==len) {
//                out[o++] = base64EncodeChars[c1 / 2 ** 2];
//                out[o++] = base64EncodeChars[(c1 & 0x3) * 2 ** 4];
//                out[o++] = "=";
//                out[o++] = "=";
//                break;
//            }
//            c2 = uint8(source[i++]);
//            if(i==len) {
//                out[o++] = base64EncodeChars[c1 / 2 ** 2];
//                out[o++] = base64EncodeChars[((c1 & 0x3) * 2 ** 4) | ((c2 & 0xF0) / 2 ** 4)];
//                out[o++] = base64EncodeChars[(c2 & 0xF) * 2 ** 2];
//                out[o++] = "=";
//                break;
//            }
//            c3 = uint8(source[i++]);
//            out[o++] = base64EncodeChars[c1 / 2 ** 2];
//            out[o++] = base64EncodeChars[((c1 & 0x3) * 2 ** 4) | ((c2 & 0xF0) / 2 ** 4)];
//            out[o++] = base64EncodeChars[((c2 & 0xF) * 2 ** 2) | ((c3 & 0xC0) / 2 ** 6)];
//            out[o++] = base64EncodeChars[c3 & 0x3F];
//        }
//    }

    function decode(bytes memory source) internal pure returns (bytes memory out){
        uint i=0;
        uint o=0;
        uint len = source.length;
        int8 c1;
        int8 c2;
        int8 c3;
        int8 c4;
        out = new bytes(source.length);

        int8[128] memory base64DecodeChars = init_base64DecodeChars();

        while(i<len){
            do {
                c1 = base64DecodeChars[uint8(source[i++]) & 0xff];
            } while(i < len && c1 == -1);
            if(c1 == -1)
                break;

            do {
                c2 = base64DecodeChars[uint8(source[i++]) & 0xff];
            } while(i < len && c2 == -1);
            if(c2 == -1)
                break;

            out[o++] = bytes1((c1 * 2 ** 2) | ((c2 & 0x30) / 2 ** 4));

            do {
                c3 = int8(source[i++]) & int8(0xff);
                if(c3 == 61)
                    return out;
                c3 = base64DecodeChars[uint8(c3)];
            } while(i < len && c3 == -1);
            if(c3 == -1)
                break;

            out[o++] = bytes1(((c2 & 0xF) * 2 ** 4) | ((c3 & 0x3C) / 2 ** 2));

            do {
                c4 = int8(source[i++]) & int8(0xff);
                if(c4 == 61)
                    return out;
                c4 = base64DecodeChars[uint8(c4)];
            } while(i < len && c4 == -1);
            if(c4 == -1)
                break;

            out[o++] = bytes1(((c3 & 0x03) << 6) | c4);
        }
        return out;
    }
}
