import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorSystem;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import javacard.framework.*;
import javacard.security.*;
import nuri.musig2.NuriMuSig2v019;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.util.Arrays;

/** Simulator-only security boundary tests; no production fault hooks. */
public final class PinHardeningTest {
    private static final AID AID = AIDUtil.create("4E5552494D554701");
    private static final byte[] PIN = {49,50,51,52}; // synthetic fixture only
    private static final X9ECParameters C = SECNamedCurves.getByName("secp256k1");
    private static final byte[] G = C.getG().getEncoded();
    private static int checks;

    public static void main(String[] args) throws Exception {
        pinPolicy(); retries(); installPolicy(); sessionBinding(); errorsBurn();
        points(); fieldMath(); blindedAndFault(); exceptionCleanup(); keygenTransaction();
        System.out.println("MUSIG2_JCARDSIM_PIN_HARDENING_OK checks=" + checks);
    }
    private static Simulator fresh(byte[] app) {
        Simulator s = new Simulator();
        if (app == null) s.installApplet(AID, NuriMuSig2v019.class);
        else s.installApplet(AID, NuriMuSig2v019.class, app, (short)0, (byte)app.length);
        require(s.selectApplet(AID), "select");
        return s;
    }
    private static Simulator keyed() {
        Simulator s = fresh(null);
        ok(s, 0x21, PIN); auth(s); ok(s, 4, null);
        return s;
    }
    private static void pinPolicy() throws Exception {
        Simulator s = fresh(null);
        require(Arrays.equals(ok(s, 0x22, null), new byte[]{1,0,5}), "mandatory unset default");
        sw(s, 0x40, null, 0x6982); sw(s, 0x41, new byte[231], 0x6982);
        sw(s, 4, null, 0x6982);
        ok(s, 0x21, PIN);
        sw(s, 0x40, null, 0x6982); // SET_PIN is not VERIFY
        auth(s); ok(s, 4, null);
        sw(s, 0x21, PIN, 0x6985); auth(s);
        byte[] pub = ok(s, 3, null);
        sw(s, 4, null, 0x6989); auth(s);
        require(Arrays.equals(pub, ok(s, 3, null)), "one-shot key unchanged");
        sw(s, 0x41, new byte[231], 0x6984); auth(s);
        ok(s, 0x40, null);
        s.selectApplet(AID); // select() itself must log out even without deselect callback
        sw(s, 0x40, null, 0x6982); auth(s);
        sw(s, 0x41, new byte[231], 0x6984); auth(s);
        ok(s, 0x40, null); s.reset(); s.selectApplet(AID);
        sw(s, 0x41, new byte[231], 0x6982); auth(s);
        sw(s, 0x41, new byte[231], 0x6984);
        clean(true);
    }
    private static void retries() throws Exception {
        Simulator s = keyed();
        for (int left = 4; left >= 0; left--) {
            sw(s, 0x20, new byte[]{57,57,57,57}, left == 0 ? 0x6983 : 0x63C0 | left);
            require(ok(s, 0x22, null)[2] == left, "retry count " + left);
            sw(s, 0x40, null, 0x6982);
            s.reset(); s.selectApplet(AID);
        }
        sw(s, 0x20, PIN, 0x6983);
        require(ok(s, 0x22, null)[2] == 0, "blocked remains blocked after reset");
        clean(true);
        s = keyed(); sw(s, 0x20, new byte[]{57,57,57,57}, 0x63C4); auth(s);
        require(ok(s, 0x22, null)[2] == 5, "successful verify restores retries");
    }
    private static void installPolicy() {
        Simulator s = fresh(new byte[]{0,0,2,1,0});
        require(Arrays.equals(ok(s,0x22,null), new byte[]{0,0,5}), "explicit demo install policy");
        ok(s,4,null); byte[] n = ok(s,0x40,null); ok(s,0x41,payload(n));
        s = fresh(new byte[]{0,0,6,0,4,49,50,51,52});
        require(Arrays.equals(ok(s,0x22,null), new byte[]{1,1,5}), "install personalization");
        sw(s,4,null,0x6982); auth(s); ok(s,4,null);
        for (byte[] bad : new byte[][] {
            {0}, {0,0,2,2,0}, {0,0,2,1,1}, {0,0,2,1,0,0}, {0,0,1,0},
            {0,0,6,0,4,49,50,51,65}, {0,0,2,0,0}
        }) {
            boolean rejected = false;
            try { fresh(bad); } catch (RuntimeException expected) { rejected = true; }
            require(rejected,"malformed install rejected");
        }
    }
    private static void sessionBinding() throws Exception {
        Simulator s = keyed();
        byte[] first = ok(s,0x40,null), p1 = payload(first);
        byte[] second = ok(s,0x40,null), p2 = payload(second);
        require(!Arrays.equals(Arrays.copyOfRange(first,66,70), Arrays.copyOfRange(second,66,70)), "counter advances");
        sw(s,0x41,p1,0x6984); clean(true); auth(s);
        sw(s,0x41,p2,0x6984); auth(s); // stale token error burns replacement too
        byte[] p = payload(ok(s,0x40,null));
        ok(s,0x20,PIN); // successful repeat VERIFY must not destroy live nonce session
        ok(s,0x41,p); clean(true);
        sw(s,0x41,p,0x6984); auth(s);
        p = payload(ok(s,0x40,null));
        ((byte[])field("sessionCounter"))[0] ^= 1;
        sw(s,0x41,p,0x6984); clean(true);
    }
    private static void errorsBurn() throws Exception {
        Simulator s = keyed();
        for (int ins : new int[]{0x41,0x7f,0x20}) {
            byte[] p = payload(ok(s,0x40,null));
            if (ins == 0x41) sw(s,ins,new byte[97],0x6700);
            else if (ins == 0x20) sw(s,ins,new byte[]{57,57,57,57},0x63C4);
            else sw(s,ins,null,0x6d00);
            clean(true); auth(s); sw(s,0x41,p,0x6984); auth(s);
        }
        byte[] p = payload(ok(s,0x40,null)); p[64] = 2;
        sw(s,0x41,p,0x6a80); clean(true);
    }
    private static void points() throws Exception {
        Simulator s = keyed();
        for (int which = 0; which < 5; which++) {
            byte[] p = payload(ok(s,0x40,null));
            if (which == 0) Arrays.fill(p,134,166,(byte)0); // R y=0: off curve
            if (which == 1) Arrays.fill(p,199,231,(byte)0); // P y=0: off curve
            if (which == 2) p[101] = 2; // compressed prefix forbidden
            if (which == 3) { // x == field prime, not a canonical field element
                byte[] prime = hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
                System.arraycopy(prime,0,p,102,32);
            }
            if (which == 4) p[64] = 1; // valid points, wrong R parity
            sw(s,0x41,p,0x6a80); clean(true); auth(s);
        }
    }
    private static void fieldMath() throws Exception {
        keyed();
        nuri.musig2.Scalar256 math = (nuri.musig2.Scalar256)field("scalar");
        BigInteger prime = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16);
        BigInteger max = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
        BigInteger[] boundary = {BigInteger.ZERO,BigInteger.ONE,prime.subtract(BigInteger.ONE),prime,prime.add(BigInteger.ONE),max};
        java.util.Random random = new java.util.Random(0x50323536L);
        for (int i=0;i<164;i++) {
            BigInteger a = i<36 ? boundary[i/6] : new BigInteger(256,random);
            BigInteger b = i<36 ? boundary[i%6] : new BigInteger(256,random);
            byte[] aa = fixed(a), bb = fixed(b), out = new byte[32];
            math.fieldMultiply(aa,(short)0,bb,(short)0,out,(short)0);
            require(num(out).equals(a.multiply(b).mod(prime)),"field multiply oracle");
            math.fieldAdd(aa,(short)0,bb,(short)0,bb,(short)0);
            require(num(bb).equals(a.add(b).mod(prime)),"field add alias oracle");
            math.mulMod(aa,(short)0,fixed(b),(short)0,out,(short)0);
            require(num(out).equals(a.multiply(b).mod(C.getN())),"field mode restores scalar modulus");
        }
        clean(true);
    }
    private static byte[] fixed(BigInteger n) {byte[] raw=n.toByteArray(),out=new byte[32];int len=Math.min(raw.length,32);System.arraycopy(raw,raw.length-len,out,32-len,len);return out;}
    private static void blindedAndFault() throws Exception {
        Simulator s = keyed();
        byte[] p = payload(ok(s,0x40,null));
        BigInteger n = C.getN();
        BigInteger k1 = num((byte[])field("nonceK1")), k2 = num((byte[])field("nonceK2"));
        byte[] sk = new byte[32]; ((ECPrivateKey)field("masterKey")).getS(sk,(short)0);
        BigInteger want = k1.add(k2.multiply(BigInteger.valueOf(3)))
            .add(num(sk).multiply(BigInteger.valueOf(10))).mod(n);
        ProbeRng probe = new ProbeRng((RandomData)field("rng"), false, false);
        set("rng",probe);
        byte[] partial = ok(s,0x41,p);
        require(num(partial).equals(want), "blinding preserves exact partial scalar");
        require(probe.calls == 4, "independent random blind per secret product per pass");
        require(C.getG().multiply(num(partial)).equals(C.getG().multiply(want)), "blinded point equation");
        clean(true);
        p = payload(ok(s,0x40,null));
        probe = new ProbeRng((RandomData)field("rng"), true, false); set("rng",probe);
        sw(s,0x41,p,0x6988);
        require(probe.calls == 4, "forced mismatch reached both complete computations");
        clean(true); auth(s); sw(s,0x41,p,0x6984);
    }
    private static void exceptionCleanup() throws Exception {
        Simulator s = keyed(); ok(s,0x40,null);
        RandomData original = (RandomData)field("rng");
        set("rng",new ProbeRng(original,false,true));
        require(tx(s,0x40,null).sw != 0x9000,"RNG exception refused");
        clean(true); set("rng",original); auth(s);
        KeyAgreement engine = (KeyAgreement)field("keyAgreement");
        set("keyAgreement",new BadEngine(engine));
        sw(s,0x40,null,0x6a81); clean(true);
        set("keyAgreement",engine); auth(s); ok(s,0x40,null);
        // An exception during secret arithmetic also clears Scalar256 scratch.
        set("rng",new ProbeRng(original,false,true));
        require(tx(s,0x41,payloadFromState()).sw != 0x9000,"finalize RNG exception refused");
        clean(true);
    }
    private static void keygenTransaction() throws Exception {
        Simulator s = fresh(null); ok(s,0x21,PIN); auth(s);
        ECPrivateKey original = (ECPrivateKey)field("masterKey");
        final int[] depth = {-1};
        ECPrivateKey failing = (ECPrivateKey)Proxy.newProxyInstance(PinHardeningTest.class.getClassLoader(),
            new Class<?>[]{ECPrivateKey.class}, (obj,method,args) -> {
                if (method.getName().equals("setS")) {
                    depth[0] = JCSystem.getTransactionDepth();
                    method.invoke(original,args);
                    TransactionException.throwIt(TransactionException.BUFFER_FULL);
                }
                try { return method.invoke(original,args); }
                catch (InvocationTargetException e) { throw e.getCause(); }
            });
        set("masterKey",failing);
        require(tx(s,4,null).sw != 0x9000,"key-set interruption fails closed");
        require(depth[0] == 1,"persistent key set runs inside transaction");
        require(JCSystem.getTransactionDepth() == 0,"failure aborts transaction");
        require(!(Boolean)field("keyGenerated"),"one-shot flag not committed on failure");
        sw(s,3,null,0x6986); clean(true);
        set("masterKey",original); auth(s); byte[] pub = ok(s,4,null);
        sw(s,4,null,0x6989); auth(s);
        require(Arrays.equals(pub,ok(s,3,null)),"successful transaction permanently locks keygen");
    }
    private static final class ProbeRng extends RandomData {
        final RandomData base; final boolean fault, fail; int calls;
        ProbeRng(RandomData b, boolean f, boolean x) {base=b;fault=f;fail=x;}
        public void generateData(byte[] b,short o,short l) {
            calls++;
            if (fail) { Arrays.fill(b,o,o+l,(byte)0x55); CryptoException.throwIt(CryptoException.ILLEGAL_USE); }
            base.generateData(b,o,l);
            if (fault && calls == 3) {
                try { ((byte[])field("result"))[0] ^= 1; }
                catch (Exception e) { throw new RuntimeException(e); }
            }
        }
        public short nextBytes(byte[] b,short o,short l) { generateData(b,o,l);return (short)(o+l); }
        public void setSeed(byte[] b,short o,short l) {base.setSeed(b,o,l);}
        public byte getAlgorithm() {return base.getAlgorithm();}
    }
    private static final class BadEngine extends KeyAgreement {
        final KeyAgreement base; BadEngine(KeyAgreement b){base=b;}
        public void init(PrivateKey k){base.init(k);}
        public byte getAlgorithm(){return base.getAlgorithm();}
        public short generateSecret(byte[] b,short o,short l,byte[] out,short oo){
            Arrays.fill(out,oo,oo+32,(byte)0x55);return 32;
        }
    }
    private static void clean(boolean nonces) throws Exception {
        for (String name : new String[]{"tempBuffer","scratch32_1","scratch32_2","scratch32_3",
            "scratch32_4","scratch32_5","blind","maskedKey","result","checkResult"})
            require(zero((byte[])field(name)),"erased " + name);
        require(!((ECPrivateKey)field("tempPrivKey")).isInitialized(),"temporary EC key cleared");
        Object scalar = field("scalar"); Field scratch = scalar.getClass().getDeclaredField("scratch");
        scratch.setAccessible(true); require(zero((byte[])scratch.get(scalar)),"scalar scratch erased");
        if (nonces) {
            for (String name : new String[]{"nonceK1","nonceK2","pubK1","pubK2","nonceSession"})
                require(zero((byte[])field(name)),"erased " + name);
            require(!((boolean[])field("sessionFlags"))[0],"ready flag burned");
        }
    }
    private static Object applet(){return SimulatorSystem.instance().lookupApplet(AID).getApplet();}
    private static Object field(String n) throws Exception {Field f=NuriMuSig2v019.class.getDeclaredField(n);f.setAccessible(true);return f.get(applet());}
    private static void set(String n,Object v) throws Exception {Field f=NuriMuSig2v019.class.getDeclaredField(n);f.setAccessible(true);f.set(applet(),v);}
    private static byte[] payloadFromState() throws Exception {byte[] n=new byte[70];System.arraycopy((byte[])field("nonceSession"),0,n,66,4);return payload(n);}
    private static byte[] payload(byte[] nonces){byte[] p=new byte[231];p[31]=2;p[63]=3;p[96]=5;System.arraycopy(nonces,66,p,97,4);System.arraycopy(G,0,p,101,65);System.arraycopy(G,0,p,166,65);return p;}
    private static byte[] hex(String h){byte[] b=new byte[h.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(h.substring(2*i,2*i+2),16);return b;}
    private static BigInteger num(byte[] b){return new BigInteger(1,b);}
    private static boolean zero(byte[] b){for(byte x:b)if(x!=0)return false;return true;}
    private static void require(boolean b,String m){checks++;if(!b)throw new AssertionError(m);}
    private static void auth(Simulator s){ok(s,0x20,PIN);}
    private static final class Response {byte[] data;int sw;Response(byte[] b){sw=((b[b.length-2]&255)<<8)|(b[b.length-1]&255);data=Arrays.copyOf(b,b.length-2);}}
    private static Response tx(Simulator s,int ins,byte[] data){
        int l=data==null?0:data.length;byte[] a=new byte[l==0?5:l+6];a[1]=(byte)ins;
        if(l>0){a[4]=(byte)l;System.arraycopy(data,0,a,5,l);a[a.length-1]=0;}
        return new Response(s.transmitCommand(a));
    }
    private static byte[] ok(Simulator s,int ins,byte[] d){Response r=tx(s,ins,d);require(r.sw==0x9000,"INS "+Integer.toHexString(ins)+" SW "+Integer.toHexString(r.sw));return r.data;}
    private static void sw(Simulator s,int ins,byte[] d,int wanted){Response r=tx(s,ins,d);require(r.sw==wanted,"INS "+Integer.toHexString(ins)+" expected "+Integer.toHexString(wanted)+" got "+Integer.toHexString(r.sw));require(r.data.length==0,"error has no response data");}
}
