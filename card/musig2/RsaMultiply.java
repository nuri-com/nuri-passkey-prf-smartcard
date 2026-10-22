// SPDX-License-Identifier: MIT
// Independently authored from 2ab = (a+b)^2 - a^2 - b^2.
package nuri.musig2;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

/** Exact products and pseudo-Mersenne reduction via the RSA coprocessor.
 * All square inputs are <=257 bits, hence squares <2^514 <2^768-1.
 * No provider fallback, EEPROM scratch, or secret-dependent loop bounds.
 */
final class RsaMultiply {
    private final RSAPublicKey key;
    private final Cipher rsa;
    private final byte[] input;
    private final byte[] squares;
    private final byte[] work;
    private static final byte[] TWO = {2};
    // Big endian, c = 2^256 - modulus; c < 2^129 for both moduli.
    private static final byte[] CN = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
        0x45,0x51,0x23,0x19,0x50,(byte)0xb7,0x5f,(byte)0xc4,
        0x40,0x2d,(byte)0xa1,0x73,0x2f,(byte)0xc9,(byte)0xbe,(byte)0xbf};
    private static final byte[] CP = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,1,0,0,3,(byte)0xd1};

    RsaMultiply() {
        input = JCSystem.makeTransientByteArray((short)96, JCSystem.CLEAR_ON_DESELECT);
        squares = JCSystem.makeTransientByteArray((short)288, JCSystem.CLEAR_ON_DESELECT);
        work = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
        key = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)768, false);
        Util.arrayFillNonAtomic(input,(short)0,(short)96,(byte)0xff);
        key.setModulus(input,(short)0,(short)96);
        key.setExponent(TWO,(short)0,(short)1);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        clear();
        rsa.init(key,Cipher.MODE_ENCRYPT);
        input[95]=3;
        square((short)0);
        short bad=0;
        for(short i=0;i<95;i++) bad |= squares[i];
        if(bad!=0 || squares[95]!=9) javacard.framework.ISOException.throwIt((short)0x6f31);
        clear();
        // (m-1)^2 = 1: exercises full-width carries, both reduction constants,
        // and canonical subtraction through exactly the installed provider path.
        byte[] kat = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        selfTest(false,kat); selfTest(true,kat);
    }
    private void selfTest(boolean field, byte[] kat) {
        byte[] c=field?CP:CN;
        for(short i=0;i<32;i++) kat[i]=(byte)(255-(c[i]&255));
        multiply(kat,(short)0,kat,(short)0,kat,(short)0,field);
        short bad=0;
        for(short i=0;i<31;i++) bad |= kat[i];
        bad |= (short)(kat[31]^1);
        Util.arrayFillNonAtomic(kat,(short)0,(short)32,(byte)0);
        clear();
        if(bad!=0) javacard.framework.ISOException.throwIt((short)0x6f31);
    }
    private void square(short offset) {
        if(rsa.doFinal(input,(short)0,(short)96,squares,offset)!=96)
            javacard.framework.ISOException.throwIt((short)0x6f32);
    }
    // Product of two 32-byte big-endian integers at squares[224..287].
    private void product(byte[] a, short ao, byte[] b, short bo) {
        Util.arrayFillNonAtomic(input,(short)0,(short)64,(byte)0);
        Util.arrayCopyNonAtomic(a,ao,input,(short)64,(short)32);
        square((short)0);
        Util.arrayCopyNonAtomic(b,bo,input,(short)64,(short)32);
        square((short)96);
        short carry=0;
        for(short i=31;i>=0;i--) {
            short v=(short)((a[(short)(ao+i)]&255)+(b[(short)(bo+i)]&255)+carry);
            input[(short)(64+i)]=(byte)v; carry=(short)(v>>8);
        }
        input[63]=(byte)carry;
        square((short)192);
        // The difference is nonnegative and <=513 bits. Subtract both squares
        // in a single pass; borrow can be 0,1,2 (v >= -512).
        short borrow=0;
        for(short i=95;i>=31;i--) {
            short v=(short)((squares[(short)(192+i)]&255)-(squares[i]&255)
                -(squares[(short)(96+i)]&255)-borrow);
            squares[(short)(192+i)]=(byte)v; borrow=(short)(-(v>>8));
        }
        carry=(short)(squares[223]&1);
        for(short i=224;i<288;i++) {
            short v=(short)(squares[i]&255);
            squares[i]=(byte)((v>>1)|(carry<<7)); carry=(short)(v&1);
        }
    }
    void multiply(byte[] a, short ao, byte[] b, short bo, byte[] out, short oo, boolean field) {
        // Output may overlap inputs. Only this method initializes the RSA engine.
        try {
            rsa.init(key,Cipher.MODE_ENCRYPT);
            product(a,ao,b,bo);
            Util.arrayCopyNonAtomic(squares,(short)224,work,(short)0,(short)64);
            reduce(field);
            Util.arrayCopyNonAtomic(work,(short)32,out,oo,(short)32);
        } finally { clear(); }
    }
    private void reduce(boolean field) {
        byte[] c=field?CP:CN;
        fold(c); fold(c);
        // T1 <2^385+2^256; H1 <2^129+1.
        // T2 <2^258+2^256+2^129, so H2 <=5 fits one byte.
        tinyFold(c); tinyFold(c);
        // After first tiny fold high<=1; if high=1 its low<5c.
        // After second there is no high word: overflow case is <6c<2^256;
        // no-overflow case was already <2^256. One subtraction is enough.
        short borrow=0;
        for(short i=31;i>=0;i--) {
            short modulus=(short)(255-(c[i]&255));
            if(i==31) modulus++;
            short v=(short)((work[(short)(32+i)]&255)-modulus-borrow);
            work[(short)(64+i)]=(byte)v; borrow=(short)((v>>15)&1);
        }
        short mask=(short)(borrow-1);
        for(short i=0;i<32;i++) work[(short)(32+i)]=(byte)
            ((work[(short)(32+i)]&~mask)|(work[(short)(64+i)]&mask));
    }
    private void fold(byte[] c) {
        product(work,(short)0,c,(short)0);
        short carry=0;
        for(short i=63;i>=0;i--) {
            short low=i>=32?(short)(work[i]&255):0;
            short v=(short)((squares[(short)(224+i)]&255)+low+carry);
            work[i]=(byte)v; carry=(short)(v>>8);
        }
    }
    private void tinyFold(byte[] c) {
        short high=(short)(work[31]&255), carry=0;
        for(short i=31;i>=0;i--) {
            short v=(short)((work[(short)(32+i)]&255)+high*(c[i]&255)+carry);
            work[(short)(32+i)]=(byte)v; carry=(short)((v>>8)&255);
        }
        work[31]=(byte)carry;
    }
    void clear() {
        Util.arrayFillNonAtomic(input,(short)0,(short)96,(byte)0);
        Util.arrayFillNonAtomic(squares,(short)0,(short)288,(byte)0);
        Util.arrayFillNonAtomic(work,(short)0,(short)128,(byte)0);
    }
}
