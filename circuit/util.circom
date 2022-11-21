pragma circom 2.0.2;

template BitArr2Num(n) {
    // Assume BE input.
    assert (n > 0);

    signal input in[n];
    signal output out;

    var sum = 0;
    for (var i = 0; i < n; i++) {
      assert (in[i] == 0 || in[i] == 1);
      sum += 2 ** i * in[n - 1 - i];
    }

    out <== sum;
}

template ConcatBitArr(inSize) {
    signal input b0[inSize];
    signal input b1[inSize];
    signal output out[inSize * 2];
    
    for (var j = 0; j < inSize; j++) {
        out[j] <== b0[j];
    }
    for (var j = 0; j < inSize; j++) {
        out[j + inSize] <== b1[j];
    }
}

template Num2BitsMultipleReverse(nNums, nBits) {
    signal input in[nNums];
    signal output out[nNums][nBits];

    for (var i = 0; i < nNums; i++) {
        var lc1=0;
        var e2=1;
        for (var j = 0; j < nBits; j++) {
            out[i][nBits - 1 - j] <-- (in[i] >> j) & 1;
            out[i][nBits - 1 - j] * (out[i][nBits - 1 - j] - 1 ) === 0;
            lc1 += out[i][nBits - 1 - j] * e2;
            e2 = e2+e2;
        }
        lc1 === in[i];
    }
}

template Point2Bits() {
    signal input in[2][4];
    signal output out[512];

    component bits0 = Num2Bits(64);
    component bits1 = Num2Bits(64);
    component bits2 = Num2Bits(64);
    component bits3 = Num2Bits(64);
    component bits4 = Num2Bits(64);
    component bits5 = Num2Bits(64);
    component bits6 = Num2Bits(64);
    component bits7 = Num2Bits(64);
    
    bits0.in <== in[0][0];
    bits1.in <== in[0][1];
    bits2.in <== in[0][2];
    bits3.in <== in[0][3];
    bits4.in <== in[1][0];
    bits5.in <== in[1][1];
    bits6.in <== in[1][2];
    bits7.in <== in[1][3];
    
    for (var i = 0; i < 64; i++) {
        out[i] <== bits3.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 64] <== bits2.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 128] <== bits1.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 192] <== bits0.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 256] <== bits7.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 320] <== bits6.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 384] <== bits5.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 448] <== bits4.out[63 - i];
    }
    
}

template FromatSharedKey() {
    signal input pointX[4];
    signal output ks[2];
    
    component bits0 = Num2Bits(64);
    component bits1 = Num2Bits(64);
    component bits2 = Num2Bits(64);
    component bits3 = Num2Bits(64);
    
    bits0.in <== pointX[0];
    bits1.in <== pointX[1];
    bits2.in <== pointX[2];
    bits3.in <== pointX[3];
    
    component bitsKs0 = ConcatBitArr(64);
    component bitsKs1 = ConcatBitArr(64);
    
    for (var i = 0; i < 64; i++) {
        bitsKs0.b0[i] <== bits0.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        bitsKs0.b1[i] <== bits1.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        bitsKs1.b0[i] <== bits2.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        bitsKs1.b1[i] <== bits3.out[63 - i];
    }
    
    component numKs0 = BitArr2Num(128);
    component numKs1 = BitArr2Num(128);
    
    for (var i = 0; i < 128; i++) {
        numKs0.in[i] <== bitsKs0.out[i];
    }
    for (var i = 0; i < 128; i++) {
        numKs1.in[i] <== bitsKs1.out[i];
    }

    ks[0] <== numKs0.out;
    ks[1] <== numKs1.out;
}
