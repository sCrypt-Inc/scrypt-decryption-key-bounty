import { expect } from 'chai';

import path = require("path");
const fs = require("fs");

import { Point } from '@noble/secp256k1';
import { poseidonEncrypt, formatSharedKey } from './util/poseidonEncryption';


import { sha256 } from "scryptlib";

import { bigIntToArray } from './util/misc';

const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;



describe("MainCircuit", function () {
    this.timeout(1000 * 1000 * 10);

    let da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
    let Qa: Point = Point.fromPrivateKey(da);
    let QaxArray = bigIntToArray(64, 4, Qa.x);
    let QayArray = bigIntToArray(64, 4, Qa.y);

    let w = [
        7420945844419229570368892522814573138227394292607063488308687224223382555664n,
        6631730760218555070702873444110831041714716292710921550576501660944825308907n
    ];
    let d = [123n, 456n, 789n];
    let edNonce = 12345n;
    let ed = poseidonEncrypt(d, w, edNonce);

    let db: bigint = 90388020393783788847120091912026443124559466591761394939671630294477859800601n;
    let Qb: Point = Point.fromPrivateKey(db);

    let Qs: Point = Qb.multiply(da);

    let dbArray = bigIntToArray(64, 4, db);
    let QbxArray = bigIntToArray(64, 4, Qb.x);
    let QbyArray = bigIntToArray(64, 4, Qb.y);
    let QsxArray = bigIntToArray(64, 4, Qs.x);
    let QsyArray = bigIntToArray(64, 4, Qs.y);

    let nonce = 1234n;
    let ew = poseidonEncrypt(w, formatSharedKey(QsxArray), nonce);
    
    let QaHex = Qa.toHex(false).slice(2);  // Slice away "04" at the beggining from uncompressed encoding.
    let QbHex = Qb.toHex(false).slice(2);
    
    let nonceHex = nonce.toString(16);
    nonceHex =  "0".repeat(64 - nonceHex.length) + nonceHex;
    
    let ewHex = '';
    for (var i = 0; i < ew.length; i++) {
        let partStr = ew[i].toString(16);
        ewHex += "0".repeat(64 - partStr.length) + partStr;
    }
    let Hpub = sha256(QaHex + QbHex + nonceHex + ewHex);
    let Hpub0 = BigInt('0x' + Hpub.substring(0, 32));
    let Hpub1 = BigInt('0x' + Hpub.substring(32, 64));

    let circuit: any;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_main_allpublic.circom"));
    });

    it('Testing main circuit with correct inputs',
        async function () {
            let witness = await circuit.calculateWitness(
                {
                    "w": w,
                    "d": d,
                    "db": dbArray,
                    "Qs": [QsxArray, QsyArray],
                    "edNonce": edNonce,
                    "ed": ed,
                    "Qa": [QaxArray, QayArray],
                    "Qb": [QbxArray, QbyArray],
                    "nonce": nonce,
                    "ew": ew,
                    "Hpub": [Hpub0, Hpub1]
                }
            );
            await circuit.checkConstraints(witness);
        }
    );

    it('Testing main circuit with wrong solution',
        async function () {
            let wWrong = [124322n, 2319123n];

            let witnessCalcSucceeded = true;
            try {
                // Witness generation should fail.
                let witness = await circuit.calculateWitness(
                    {
                        "w": wWrong,
                        "d": d,
                        "db": dbArray,
                        "Qs": [QsxArray, QsyArray],
                        "edNonce": edNonce,
                        "ed": ed,
                        "Qa": [QaxArray, QayArray],
                        "Qb": [QbxArray, QbyArray],
                        "nonce": nonce,
                        "ew": ew,
                        "Hpub": [Hpub0, Hpub1]
                    }
                );
            } catch (e) {
                witnessCalcSucceeded = false;
            }
            expect(witnessCalcSucceeded).to.equal(false);
        }
    );

    it('Testing main circuit with Qs != db * Qa',
        async function () {
        
            let randPriv: bigint = 37192864923864928634293846263598265893468791234710n;
            let QsWrong = Point.fromPrivateKey(randPriv);

            let QsWrongxArray = bigIntToArray(64, 4, QsWrong.x);
            let QsWrongyArray = bigIntToArray(64, 4, QsWrong.y);

            let witnessCalcSucceeded = true;
            try {
                // Witness generation should fail.
                let witness = await circuit.calculateWitness(
                    {
                        "w": w,
                        "d": d,
                        "db": dbArray,
                        "Qs": [QsWrongxArray, QsWrongyArray],
                        "edNonce": edNonce,
                        "ed": ed,
                        "Qa": [QaxArray, QayArray],
                        "Qb": [QbxArray, QbyArray],
                        "nonce": nonce,
                        "ew": ew,
                        "Hpub": [Hpub0, Hpub1]
                    }
                );
            } catch (e) {
                witnessCalcSucceeded = false;
            }
            expect(witnessCalcSucceeded).to.equal(false);
        }
    );

    it('Testing main circuit with Qb != db * G',
        async function () {
        
            let randPriv: bigint = 123781927462385736487953469857609124837219078043573n;
            let QbWrong = Point.fromPrivateKey(randPriv);

            let QbWrongxArray = bigIntToArray(64, 4, QbWrong.x);
            let QbWrongyArray = bigIntToArray(64, 4, QbWrong.y);

            let witnessCalcSucceeded = true;
            try {
                // Witness generation should fail.
                let witness = await circuit.calculateWitness(
                    {
                        "w": w,
                        "d": d,
                        "db": dbArray,
                        "Qs": [QsxArray, QsyArray],
                        "edNonce": edNonce,
                        "ed": ed,
                        "Qa": [QaxArray, QayArray],
                        "Qb": [QbWrongxArray, QbWrongyArray],
                        "nonce": nonce,
                        "ew": ew,
                        "Hpub": [Hpub0, Hpub1]
                    }
                );
            } catch (e) {
                witnessCalcSucceeded = false;
            }
            expect(witnessCalcSucceeded).to.equal(false);
        }
    );

});
