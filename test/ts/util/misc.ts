import path = require("path");
import { execSync } from 'child_process';

import { ScryptType } from "scryptlib";


// Build module for precalculating millera1b1:
process.chdir(path.join(__dirname, '..', '..', 'bn256-miller-precalc'));
console.log(execSync("go build").toString());
const bn256MillerPrecalcBin = path.join(__dirname, '..', '..', 'bn256-miller-precalc', 'bn256-miller-precalc');
process.chdir(path.join(__dirname, '..', '..', '..'));

function bigIntToArray(n: number, k: number, x: bigint) {
    let mod: bigint = 1n;
    for (var idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    let ret: bigint[] = [];
    var x_temp: bigint = x;
    for (var idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}

function bigIntToHexStrFixedLen(val: bigint, len: number) : string {
    let partStr = val.toString(16);
    return "0".repeat(len-partStr.length) + partStr;
}

function vKeyToSCryptType(vKey: any, ContractTypes: Record<string, typeof ScryptType>) {
    let cmd = [bn256MillerPrecalcBin,
               BigInt(vKey.vk_alpha_1[0]).toString(16),
               BigInt(vKey.vk_alpha_1[1]).toString(16),
               BigInt(vKey.vk_beta_2[0][0]).toString(16),
               BigInt(vKey.vk_beta_2[0][1]).toString(16),
               BigInt(vKey.vk_beta_2[1][0]).toString(16),
               BigInt(vKey.vk_beta_2[1][1]).toString(16)
            ].join(" ");
    let output = execSync(cmd).toString().trim().split(/\s+/);

    let millerb1a1 = new ContractTypes.FQ12({
        x: new ContractTypes.FQ6({
            x: new ContractTypes.FQ2({
                x: BigInt(output[0]),
                y: BigInt(output[1])
            }),
            y: new ContractTypes.FQ2({
                x: BigInt(output[2]),
                y: BigInt(output[3])
            }),
            z: new ContractTypes.FQ2({
                x: BigInt(output[4]),
                y: BigInt(output[5])
            })
        }),
        y: new ContractTypes.FQ6({
            x: new ContractTypes.FQ2({
                x: BigInt(output[6]),
                y: BigInt(output[7])
            }),
            y: new ContractTypes.FQ2({
                x: BigInt(output[8]),
                y: BigInt(output[9])
            }),
            z: new ContractTypes.FQ2({
                x: BigInt(output[10]),
                y: BigInt(output[11])
            })
        })
    });
    let gamma = new ContractTypes.G2Point({
        x: new ContractTypes.FQ2({
            x: BigInt(vKey.vk_gamma_2[0][0]),
            y: BigInt(vKey.vk_gamma_2[0][1])
        }),
        y: new ContractTypes.FQ2({
            x: BigInt(vKey.vk_gamma_2[1][0]),
            y: BigInt(vKey.vk_gamma_2[1][1])
        })
    });
    let delta = new ContractTypes.G2Point({
        x: new ContractTypes.FQ2({
            x: BigInt(vKey.vk_delta_2[0][0]),
            y: BigInt(vKey.vk_delta_2[0][1])
        }),
        y: new ContractTypes.FQ2({
            x: BigInt(vKey.vk_delta_2[1][0]),
            y: BigInt(vKey.vk_delta_2[1][1])
        })
    });
    
    let gamma_abc: any[] = [];
    vKey.IC.forEach((e: string[]) => {
       gamma_abc.push(new ContractTypes.G1Point({
            x: BigInt(e[0]),
            y: BigInt(e[1])
       })) 
    });
    return new ContractTypes.VerifyingKey({
        millerb1a1: millerb1a1,
        gamma: gamma,
        delta: delta,
        gamma_abc: gamma_abc
    })
}

function proofToSCryptType(proof: any, ContractTypes: Record<string, typeof ScryptType>) {
   let a = new ContractTypes.G1Point({
        x: BigInt(proof.pi_a[0]),
        y: BigInt(proof.pi_a[1])
   });
    
    let b = new ContractTypes.G2Point({
        x: new ContractTypes.FQ2({
            x: BigInt(proof.pi_b[0][0]),
            y: BigInt(proof.pi_b[0][1])
        }),
        y: new ContractTypes.FQ2({
            x: BigInt(proof.pi_b[1][0]),
            y: BigInt(proof.pi_b[1][1])
        })
    });

   let c = new ContractTypes.G1Point({
        x: BigInt(proof.pi_c[0]),
        y: BigInt(proof.pi_c[1])
   });
   
   return new ContractTypes.Proof({
        a: a,
        b: b,
        c: c
   });
}

export {
    bigIntToArray,
    bigIntToHexStrFixedLen,
    proofToSCryptType,
    vKeyToSCryptType    
}
