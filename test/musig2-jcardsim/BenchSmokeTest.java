// SPDX-License-Identifier: MIT
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import nuri.musig2.MuSig2Bench;

/** Temporary benchmark protocol smoke test; never accesses hardware. */
public final class BenchSmokeTest {
    public static void main(String[] args) {
        Simulator sim = new Simulator();
        sim.installApplet(AIDUtil.create("4E5552494D55473401"), MuSig2Bench.class);
        if (!sim.selectApplet(AIDUtil.create("4E5552494D55473401")))
            throw new AssertionError("benchmark select");
        for (int op=0; op<=10; op++) {
            byte[] response=sim.transmitCommand(new byte[] {(byte)0x80,0x70,(byte)op,3,0});
            if(response.length!=34 || response[32]!=(byte)0x90 || response[33]!=0)
                throw new AssertionError("benchmark op="+op+" response="+java.util.Arrays.toString(response));
        }
        System.out.println("BenchSmokeTest: all 11 operations pass (3 repetitions each)");
    }
}
