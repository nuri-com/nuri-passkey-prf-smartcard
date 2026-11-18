// SPDX-License-Identifier: MIT
package test.sc;

import com.licel.jcardsim.smartcardio.CardSimulator;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import javax.smartcardio.CommandAPDU;

/** Hex-line stdin/stdout APDU bridge to NuriSecureChannelApplet in jCardSim. */
public final class ScApduBridge {
    public static void main(String[] args) throws Exception {
        PrintStream protocolOut = System.out;
        System.setOut(System.err);
        CardSimulator sim = NuriScSimTest.install();
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, "US-ASCII"));
        String line;
        while ((line = input.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            byte[] response = sim.transmitCommand(new CommandAPDU(NuriScSimTest.hex(line))).getBytes();
            StringBuilder hex = new StringBuilder(response.length * 2);
            for (byte b : response) hex.append(String.format("%02x", b & 0xFF));
            protocolOut.println(hex.toString());
            protocolOut.flush();
        }
    }
}
