// SPDX-License-Identifier: MIT
package test.vault;

import com.licel.jcardsim.smartcardio.CardSimulator;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import javax.smartcardio.CommandAPDU;

/** Test-only stdin transport to a simulator; never connects PC/SC or a real card. */
public final class VaultApduBridge {
    public static void main(String[] args) throws Exception {
        // Pinned jCardSim prints native Signature construction diagnostics to
        // System.out. Keep simulator diagnostics off the hex-only wire channel.
        java.io.PrintStream protocolOut = System.out;
        System.setOut(System.err);
        CardSimulator sim = NuriVaultSimTest.install();
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, "US-ASCII"));
        String line;
        while ((line = input.readLine()) != null) {
            byte[] response = sim.transmitCommand(new CommandAPDU(NuriVaultSimTest.hex(line))).getBytes();
            StringBuilder hex = new StringBuilder();
            for (byte value : response) hex.append(String.format("%02x", value & 0xFF));
            protocolOut.println(hex.toString());
            protocolOut.flush();
        }
    }
}
