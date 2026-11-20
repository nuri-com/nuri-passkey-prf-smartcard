import AppKit
import Foundation
import SwiftUI

struct InventoryCard: Decodable {
    let reader: String
    let protocolName: String
    let cardSerial: String
    let atr: String?
    let chip: String?
    let applets: [String]

    enum CodingKeys: String, CodingKey {
        case reader
        case protocolName = "protocol"
        case cardSerial = "card_serial"
        case atr, chip, applets
    }
}

struct PivCardInfo: Decodable, Equatable {
    let reader: String
    let protocolName: String
    let cardSerial: String
    let pivVersion: String
    let chuidGuid: String
    let pinTriesLeft: Int
    let authHash: String
    let fingerprintSupported: Bool
    let fingerprintCount: Int
    let fingerprintBackend: String

    enum CodingKeys: String, CodingKey {
        case reader
        case protocolName = "protocol"
        case cardSerial = "card_serial"
        case pivVersion = "piv_version"
        case chuidGuid = "chuid_guid"
        case pinTriesLeft = "pin_tries_left"
        case authHash = "auth_hash"
        case fingerprintSupported = "fingerprint_supported"
        case fingerprintCount = "fingerprint_count"
        case fingerprintBackend = "fingerprint_backend"
    }
}

struct CardInfo: Identifiable, Equatable {
    let reader: String
    let protocolName: String
    let cardSerial: String
    let atr: String?
    let chip: String?
    let applets: [String]

    var pivVersion: String?
    var chuidGuid: String?
    var pinTriesLeft: Int?
    var authHash: String?
    var fingerprintSupported: Bool?
    var fingerprintCount: Int?
    var fingerprintBackend: String?

    var id: String { "\(cardSerial)|\(reader)" }

    var supportsPiv: Bool { applets.contains("PIV") }
    var supportsNuriAuth: Bool { applets.contains("NuriAuth") }
    var hasFingerprintSensor: Bool {
        applets.contains("Feitian-FP") || (chip ?? "").contains("IDEX TrustedBio")
    }
    var supportsFeitianFingerprint: Bool { fingerprintSupported == true }

    init(inventory: InventoryCard, piv: PivCardInfo?) {
        self.reader = inventory.reader
        self.protocolName = inventory.protocolName
        self.cardSerial = inventory.cardSerial
        self.atr = inventory.atr
        self.chip = inventory.chip
        self.applets = inventory.applets
        if let piv = piv {
            self.pivVersion = piv.pivVersion
            self.chuidGuid = piv.chuidGuid
            self.pinTriesLeft = piv.pinTriesLeft
            self.authHash = piv.authHash
            self.fingerprintSupported = piv.fingerprintSupported
            self.fingerprintCount = piv.fingerprintCount
            self.fingerprintBackend = piv.fingerprintBackend
        } else {
            self.pivVersion = nil
            self.chuidGuid = nil
            self.pinTriesLeft = nil
            self.authHash = nil
            self.fingerprintSupported = nil
            self.fingerprintCount = nil
            self.fingerprintBackend = nil
        }
    }
}

struct FingerprintResult: Decodable {
    let ok: Bool
    let event: String?
    let error: String?
    let instruction: String?
    let current: Int?
    let maximum: Int?
    let templateCount: Int?
    let authorized: Bool?

    enum CodingKeys: String, CodingKey {
        case ok, event, error, instruction, current, maximum, authorized
        case templateCount = "template_count"
    }
}

struct ChangePinResult: Decodable {
    let ok: Bool
    let error: String?
    let pinTriesLeft: Int?

    enum CodingKeys: String, CodingKey {
        case ok, error
        case pinTriesLeft = "pin_tries_left"
    }
}

final class CardViewModel: ObservableObject {
    @Published var cards: [CardInfo] = []
    @Published var selectedCardId: String = ""
    @Published var pairedHashes: Set<String> = []
    @Published var ctkVisibleHashes: Set<String> = []

    @Published var oldPin: String = ""
    @Published var newPin: String = ""
    @Published var confirmPin: String = ""
    @Published var uvPin: String = ""
    @Published var uvPolicy: String = "and"

    @Published var busy: Bool = false
    @Published var statusText: String = "Scanning connected smartcards..."
    @Published var statusIsError: Bool = false

    let username: String = NSUserName()
    let repoPath: String

    init() {
        if let configured = Bundle.main.object(forInfoDictionaryKey: "NuriRepoPath") as? String,
           FileManager.default.fileExists(atPath: configured + "/scripts/card-piv-setup.py") {
            self.repoPath = configured
        } else {
            self.repoPath = NSHomeDirectory() + "/Developer/nuri-passkey-prf-smartcard"
        }
    }

    var selectedCard: CardInfo? {
        cards.first(where: { $0.id == selectedCardId }) ?? cards.first
    }

    var pythonPath: String {
        let venv = repoPath + "/.build/card-v1-python/bin/python3"
        if FileManager.default.isExecutableFile(atPath: venv) { return venv }
        for cand in ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"] {
            if FileManager.default.isExecutableFile(atPath: cand) { return cand }
        }
        return "/usr/bin/python3"
    }

    private func scanCards() -> [CardInfo] {
        let invScript = repoPath + "/scripts/card-readers.py"
        let pivScript = repoPath + "/scripts/card-piv-setup.py"
        let py = pythonPath

        let invOut = Self.runCommand(executable: py, args: [invScript, "--json"])
        let pivOut = Self.runCommand(executable: py, args: [pivScript, "--list-piv"])

        var inventory: [InventoryCard] = []
        if invOut.code == 0, let data = invOut.stdout.data(using: .utf8),
           let parsed = try? JSONDecoder().decode([InventoryCard].self, from: data) {
            inventory = parsed
        }

        var pivBySerial: [String: PivCardInfo] = [:]
        if pivOut.code == 0, let data = pivOut.stdout.data(using: .utf8),
           let parsed = try? JSONDecoder().decode([PivCardInfo].self, from: data) {
            for card in parsed { pivBySerial[card.cardSerial] = card }
        }

        // Prefer the full physical-card inventory; fall back to PIV-only if needed.
        if inventory.isEmpty {
            return pivBySerial.values.map { piv in
                CardInfo(
                    inventory: InventoryCard(
                        reader: piv.reader,
                        protocolName: piv.protocolName,
                        cardSerial: piv.cardSerial,
                        atr: nil,
                        chip: nil,
                        applets: ["PIV"]
                    ),
                    piv: piv
                )
            }
        }
        return inventory.map { CardInfo(inventory: $0, piv: pivBySerial[$0.cardSerial]) }
    }

    func refresh() {
        busy = true
        statusIsError = false
        statusText = "Scanning readers..."
        let user = username

        DispatchQueue.global(qos: .userInitiated).async {
            let decodedCards = self.scanCards()
            let listOut = Self.runCommand(executable: "/usr/sbin/sc_auth", args: ["list", "-u", user])
            let idOut = Self.runCommand(executable: "/usr/sbin/sc_auth", args: ["identities"])

            let paired = Self.extractHashes(from: listOut.stdout)
            let ctkVisible = Self.extractHashes(from: idOut.stdout)

            DispatchQueue.main.async {
                self.busy = false
                self.cards = decodedCards
                self.pairedHashes = paired
                self.ctkVisibleHashes = ctkVisible
                if !decodedCards.contains(where: { $0.id == self.selectedCardId }) {
                    self.selectedCardId = decodedCards.first?.id ?? ""
                }
                if decodedCards.isEmpty {
                    self.statusIsError = true
                    self.statusText = "No smartcard detected. Insert card and click Refresh."
                } else {
                    self.statusIsError = false
                    self.statusText = "Found \(decodedCards.count) card(s)."
                }
            }
        }
    }

    func changePin() {
        guard let card = selectedCard, card.supportsPiv else {
            statusIsError = true
            statusText = "Selected card has no PIV applet."
            return
        }
        guard !oldPin.isEmpty else {
            statusIsError = true
            statusText = "Enter current PIN (default is 123456)."
            return
        }
        guard (6...8).contains(newPin.count), newPin.allSatisfy({ $0.isASCII }) else {
            statusIsError = true
            statusText = "New PIN must be 6–8 ASCII characters."
            return
        }
        guard newPin == confirmPin else {
            statusIsError = true
            statusText = "New PIN and confirmation do not match."
            return
        }
        guard oldPin != newPin else {
            statusIsError = true
            statusText = "New PIN must be different from current PIN."
            return
        }

        let py = pythonPath
        let script = repoPath + "/scripts/card-piv-setup.py"
        let reader = card.reader
        let payload = "\(oldPin)\n\(newPin)\n"

        busy = true
        statusIsError = false
        statusText = "Changing PIN on card \(card.cardSerial)..."

        DispatchQueue.global(qos: .userInitiated).async {
            let res = Self.runCommand(
                executable: py,
                args: [script, "--reader", reader, "--change-pin-stdin"],
                stdinText: payload
            )
            var ok = false
            var msg = res.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            if let data = res.stdout.data(using: .utf8),
               let parsed = try? JSONDecoder().decode(ChangePinResult.self, from: data) {
                ok = parsed.ok
                if !ok { msg = parsed.error ?? "PIN change failed" }
            }
            DispatchQueue.main.async {
                self.busy = false
                if ok {
                    self.oldPin = ""
                    self.newPin = ""
                    self.confirmPin = ""
                    self.statusIsError = false
                    self.statusText = "PIN updated on card \(card.cardSerial)!"
                    self.refresh()
                } else {
                    self.statusIsError = true
                    self.statusText = msg.isEmpty ? "PIN change failed." : msg
                    self.refreshKeepStatus()
                }
            }
        }
    }

    func pairSelectedCard() {
        guard let card = selectedCard, card.supportsPiv, let hash = card.authHash, !hash.isEmpty else {
            statusIsError = true
            statusText = "Selected card has no usable PIV auth hash."
            return
        }
        runScAuthAdmin(action: "pair", hash: hash, serial: card.cardSerial)
    }

    func unpairSelectedCard() {
        guard let card = selectedCard, card.supportsPiv, let hash = card.authHash, !hash.isEmpty else {
            statusIsError = true
            statusText = "Selected card has no usable PIV auth hash."
            return
        }
        runScAuthAdmin(action: "unpair", hash: hash, serial: card.cardSerial)
    }

    func fingerprintAction(_ action: String) {
        guard let card = selectedCard, card.hasFingerprintSensor else {
            statusIsError = true
            statusText = "Selected card has no fingerprint sensor."
            return
        }
        guard card.supportsFeitianFingerprint else {
            statusIsError = true
            statusText = "Fingerprint sensor on this card is not yet supported by the app."
            return
        }
        guard action == "match" || action == "enroll" else { return }
        let py = pythonPath
        let script = repoPath + "/scripts/card_fingerprint.py"
        busy = true
        statusIsError = false
        statusText = action == "match"
            ? "Touch an enrolled finger on card \(card.cardSerial)..."
            : "Touch and lift the same new finger 12 times. Follow progress below."

        DispatchQueue.global(qos: .userInitiated).async {
            let res = Self.runCommandLines(
                executable: py,
                args: [script, "--reader", card.reader, "--" + action]
            ) { line in
                guard let data = line.data(using: .utf8),
                      let event = try? JSONDecoder().decode(FingerprintResult.self, from: data) else { return }
                DispatchQueue.main.async {
                    if event.event == "touch", let current = event.current, let maximum = event.maximum {
                        self.statusText = current == maximum
                            ? "Enrollment complete: \(current)/\(maximum) touches."
                            : "Touch \(current)/\(maximum) captured. Lift, then touch again."
                    } else if let instruction = event.instruction {
                        self.statusText = instruction
                    }
                }
            }
            DispatchQueue.main.async {
                self.busy = false
                let lines = res.stdout.split(separator: "\n")
                let final = lines.last.flatMap { line in
                    try? JSONDecoder().decode(FingerprintResult.self, from: Data(line.utf8))
                }
                if res.code == 0 {
                    self.statusIsError = false
                    self.statusText = action == "match"
                        ? "Fingerprint MATCH on card \(card.cardSerial)."
                        : "New fingerprint enrolled on card \(card.cardSerial)."
                    self.refreshKeepStatus()
                } else {
                    self.statusIsError = true
                    self.statusText = final?.error ?? (res.stderr.isEmpty ? "Fingerprint operation failed." : res.stderr)
                }
            }
        }
    }

    func uvAction(_ action: String) {
        guard let card = selectedCard, card.supportsNuriAuth else {
            statusIsError = true
            statusText = "Selected card has no NuriAuth applet."
            return
        }
        let needsPin = action == "register" || action == "pin" || action == "and"
        if needsPin && !(4...12).contains(uvPin.count) || needsPin && !uvPin.allSatisfy({ $0.isASCII && $0.isNumber }) {
            statusIsError = true
            statusText = "NuriAuth PIN must be 4–12 ASCII digits."
            return
        }
        let script = repoPath + "/scripts/nuri_uv.py"
        var args = [script, "--reader", card.reader]
        switch action {
        case "register": args += ["--set-pin-stdin", "--initial-policy", uvPolicy]
        case "pin": args += ["--pin-check-stdin"]
        case "and": args += ["--and-check-stdin"]
        case "finger": args += ["--finger-check"]
        default: return
        }
        busy = true
        statusIsError = false
        statusText = action == "register" ? "Registering NuriAuth \(uvPolicy.uppercased()) policy..." : "Checking on-card authorization..."
        DispatchQueue.global(qos: .userInitiated).async {
            let res = Self.runCommandLines(executable: self.pythonPath, args: args, stdinText: needsPin ? self.uvPin + "\n" : nil) { line in
                guard let data = line.data(using: .utf8),
                      let event = try? JSONDecoder().decode(FingerprintResult.self, from: data),
                      let instruction = event.instruction else { return }
                DispatchQueue.main.async { self.statusText = instruction }
            }
            DispatchQueue.main.async {
                self.busy = false
                self.uvPin = ""
                let final = res.stdout.split(separator: "\n").last.flatMap {
                    try? JSONDecoder().decode(FingerprintResult.self, from: Data($0.utf8))
                }
                if res.code == 0 {
                    self.statusIsError = false
                    self.statusText = action == "register" ? "NuriAuth policy registered." : "NuriAuth AUTHORIZED — protected client returned OK."
                } else {
                    self.statusIsError = true
                    self.statusText = final?.error ?? "Authorization denied: satisfy the configured PIN/fingerprint policy."
                }
            }
        }
    }

    private func runScAuthAdmin(action: String, hash: String, serial: String) {
        guard Self.isValidUsername(username), Self.isValidHexHash(hash) else {
            statusIsError = true
            statusText = "Invalid username or card certificate hash."
            return
        }
        guard action == "pair" || action == "unpair" else { return }

        busy = true
        statusIsError = false
        statusText = action == "pair"
            ? "Approve macOS admin prompt to register card \(serial)..."
            : "Approve macOS admin prompt to unpair card \(serial)..."

        let cmd = "/usr/sbin/sc_auth \(action) -u \(username) -h \(hash)"
        let appleScript = "do shell script \"\(cmd)\" with administrator privileges"

        DispatchQueue.global(qos: .userInitiated).async {
            let res = Self.runCommand(executable: "/usr/bin/osascript", args: ["-e", appleScript])
            DispatchQueue.main.async {
                self.busy = false
                if res.code == 0 {
                    self.statusIsError = false
                    self.statusText = action == "pair"
                        ? "Card \(serial) registered for Mac login & sudo!"
                        : "Card \(serial) unpaired from this Mac."
                    self.refreshKeepStatus()
                } else {
                    let err = res.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                    self.statusIsError = true
                    self.statusText = err.contains("User canceled")
                        ? "Cancelled."
                        : (err.isEmpty ? "sc_auth \(action) failed." : err)
                }
            }
        }
    }

    private func refreshKeepStatus() {
        let user = username
        DispatchQueue.global(qos: .userInitiated).async {
            let decoded = self.scanCards()
            let listOut = Self.runCommand(executable: "/usr/sbin/sc_auth", args: ["list", "-u", user])
            let idOut = Self.runCommand(executable: "/usr/sbin/sc_auth", args: ["identities"])
            let paired = Self.extractHashes(from: listOut.stdout)
            let ctk = Self.extractHashes(from: idOut.stdout)
            DispatchQueue.main.async {
                self.cards = decoded
                self.pairedHashes = paired
                self.ctkVisibleHashes = ctk
                if !decoded.contains(where: { $0.id == self.selectedCardId }) {
                    self.selectedCardId = decoded.first?.id ?? ""
                }
            }
        }
    }

    private static func isValidUsername(_ s: String) -> Bool {
        !s.isEmpty && s.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." }
    }

    private static func isValidHexHash(_ s: String) -> Bool {
        s.count == 40 && s.allSatisfy { ("0"..."9").contains($0) || ("A"..."F").contains($0) || ("a"..."f").contains($0) }
    }

    private static func extractHashes(from text: String) -> Set<String> {
        var out = Set<String>()
        let pattern = try! NSRegularExpression(pattern: "\\b[0-9A-Fa-f]{40}\\b")
        let range = NSRange(text.startIndex..., in: text)
        for match in pattern.matches(in: text, range: range) {
            if let r = Range(match.range, in: text) {
                out.insert(String(text[r]).uppercased())
            }
        }
        return out
    }

    private static func runCommandLines(
        executable: String,
        args: [String],
        stdinText: String? = nil,
        onLine: @escaping (String) -> Void
    ) -> (code: Int32, stdout: String, stderr: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        let outPipe = Pipe()
        let errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe
        if let stdinText = stdinText {
            let inPipe = Pipe()
            p.standardInput = inPipe
            if let data = stdinText.data(using: .utf8) { inPipe.fileHandleForWriting.write(data) }
            inPipe.fileHandleForWriting.closeFile()
        }
        do {
            try p.run()
            var all = Data()
            var pending = Data()
            while true {
                let chunk = try outPipe.fileHandleForReading.read(upToCount: 4096) ?? Data()
                if chunk.isEmpty { break }
                all.append(chunk)
                pending.append(chunk)
                while let newline = pending.firstIndex(of: 0x0A) {
                    let line = pending.prefix(upTo: newline)
                    if let text = String(data: line, encoding: .utf8), !text.isEmpty { onLine(text) }
                    pending.removeSubrange(...newline)
                }
            }
            if !pending.isEmpty, let text = String(data: pending, encoding: .utf8) { onLine(text) }
            p.waitUntilExit()
            let err = errPipe.fileHandleForReading.readDataToEndOfFile()
            return (p.terminationStatus, String(data: all, encoding: .utf8) ?? "", String(data: err, encoding: .utf8) ?? "")
        } catch {
            return (1, "", error.localizedDescription)
        }
    }

    private static func runCommand(
        executable: String,
        args: [String],
        stdinText: String? = nil
    ) -> (code: Int32, stdout: String, stderr: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        let outPipe = Pipe()
        let errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe
        if let stdinText = stdinText {
            let inPipe = Pipe()
            p.standardInput = inPipe
            if let data = stdinText.data(using: .utf8) {
                inPipe.fileHandleForWriting.write(data)
            }
            inPipe.fileHandleForWriting.closeFile()
        }
        do {
            try p.run()
            p.waitUntilExit()
        } catch {
            return (1, "", error.localizedDescription)
        }
        let outStr = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let errStr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return (p.terminationStatus, outStr, errStr)
    }
}

struct ContentView: View {
    @StateObject private var vm = CardViewModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Nuri Card — Mac Setup")
                        .font(.title2.bold())
                    Text("Change PIV PIN & register card for macOS login / sudo")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Button("Refresh") { vm.refresh() }
                    .disabled(vm.busy)
            }

            Divider()

            // Card Selector
            GroupBox("Connected Smartcard") {
                VStack(alignment: .leading, spacing: 8) {
                    if vm.cards.isEmpty {
                        Text("No smartcard found")
                            .foregroundColor(.secondary)
                    } else {
                        Picker("Card", selection: $vm.selectedCardId) {
                            ForEach(vm.cards) { card in
                                Text("\(card.cardSerial) — \(card.reader)")
                                    .tag(card.id)
                            }
                        }
                        .labelsHidden()
                        .onChange(of: vm.selectedCardId) { _ in
                            vm.oldPin = ""
                            vm.newPin = ""
                            vm.confirmPin = ""
                            if let c = vm.selectedCard {
                                vm.statusIsError = false
                                vm.statusText = "Selected card \(c.cardSerial) (\(c.reader))."
                            }
                        }

                        if let c = vm.selectedCard {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Reader: \(c.reader)")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                Text("Protocol: \(c.protocolName) · ATR: \(c.atr ?? "-")")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                Text("Chip: \(c.chip ?? "unknown")")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                Text("Applets: \(c.applets.isEmpty ? "none" : c.applets.joined(separator: ", "))")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                    .lineLimit(2)
                                Text("Fingerprint sensor: \(c.hasFingerprintSensor ? (c.supportsFeitianFingerprint ? "Feitian (supported)" : "IDEX (not yet supported in app)") : "none")")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                if c.supportsPiv, let tries = c.pinTriesLeft {
                                    let isPaired = vm.pairedHashes.contains((c.authHash ?? "").uppercased())
                                    HStack(spacing: 10) {
                                        Label("PIV PIN tries: \(tries)/5", systemImage: "key.fill")
                                            .font(.caption)
                                            .foregroundColor(tries <= 2 ? .red : .secondary)
                                        Spacer()
                                        Label(
                                            isPaired ? "Registered for \(vm.username)" : "Not registered",
                                            systemImage: isPaired ? "checkmark.seal.fill" : "exclamationmark.circle"
                                        )
                                        .font(.caption.bold())
                                        .foregroundColor(isPaired ? .green : .orange)
                                    }
                                } else {
                                    Text("PIV: not present on this card")
                                        .font(.caption2)
                                        .foregroundColor(.orange)
                                }
                            }
                        }
                    }
                }
                .padding(6)
            }

            // Change PIV PIN
            GroupBox("1. Change PIV PIN") {
                VStack(alignment: .leading, spacing: 8) {
                    if let c = vm.selectedCard, !c.supportsPiv {
                        Text("This card has no PIV applet; PIV PIN change is disabled.")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                    SecureField("Current PIN (default: 123456)", text: $vm.oldPin)
                        .textFieldStyle(.roundedBorder)
                    SecureField("New PIN (6–8 characters)", text: $vm.newPin)
                        .textFieldStyle(.roundedBorder)
                    SecureField("Confirm New PIN", text: $vm.confirmPin)
                        .textFieldStyle(.roundedBorder)
                    HStack {
                        Text("PUK default: 12345678")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                        Spacer()
                        Button("Change PIN") { vm.changePin() }
                            .buttonStyle(.borderedProminent)
                            .disabled(vm.busy || vm.selectedCard == nil || !(vm.selectedCard?.supportsPiv ?? false))
                    }
                }
                .padding(6)
            }

            // Register / Unpair with Mac
            GroupBox("2. Register Card with This Mac") {
                VStack(alignment: .leading, spacing: 8) {
                    if let c = vm.selectedCard {
                        if c.supportsPiv {
                            let hash = c.authHash ?? ""
                            let isPaired = vm.pairedHashes.contains(hash.uppercased())
                            Text("Card \(c.cardSerial) · Auth Hash: \(hash.isEmpty ? "Not provisioned" : hash)")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                                .textSelection(.enabled)
                            HStack {
                                if isPaired {
                                    Button("Unpair from Mac", role: .destructive) {
                                        vm.unpairSelectedCard()
                                    }
                                    .disabled(vm.busy)
                                } else {
                                    Button("Register for Mac Login & sudo") {
                                        vm.pairSelectedCard()
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .disabled(vm.busy || hash.isEmpty)
                                }
                                Spacer()
                                if vm.busy {
                                    ProgressView().scaleEffect(0.7)
                                }
                            }
                        } else {
                            Text("This card has no PIV applet; macOS registration is disabled.")
                                .font(.caption)
                                .foregroundColor(.orange)
                        }
                    } else {
                        Text("Select a card above first.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .padding(6)
            }

            if let c = vm.selectedCard, c.hasFingerprintSensor {
                GroupBox("3. Fingerprints — Match on Card") {
                    VStack(alignment: .leading, spacing: 8) {
                        if c.supportsFeitianFingerprint {
                            Text("\(c.fingerprintCount ?? 0) enrolled template(s) · images and templates never leave the card")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        } else {
                            Text("Fingerprint sensor detected on \(c.chip ?? "this card"); this app cannot control it yet.")
                                .font(.caption)
                                .foregroundColor(.orange)
                        }
                        HStack {
                            Button("Match Finger") { vm.fingerprintAction("match") }
                                .buttonStyle(.borderedProminent)
                                .disabled(vm.busy || !c.supportsFeitianFingerprint)
                            Button("Enroll New Finger (12 touches)") { vm.fingerprintAction("enroll") }
                                .disabled(vm.busy || !c.supportsFeitianFingerprint)
                        }
                        Text("Enrollment preserves existing fingers/applets. Match here tests the sensor; it does not unlock PIV or macOS.")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    .padding(6)
                }
            }

            if let c = vm.selectedCard, c.supportsNuriAuth {
                GroupBox("4. NuriAuth — PIN / Fingerprint Policy") {
                    VStack(alignment: .leading, spacing: 8) {
                        SecureField("NuriAuth PIN (separate from PIV)", text: $vm.uvPin)
                            .textFieldStyle(.roundedBorder)
                        HStack {
                            Picker("Initial policy", selection: $vm.uvPolicy) {
                                Text("PIN OR finger").tag("or")
                                Text("PIN AND finger").tag("and")
                            }
                            .labelsHidden()
                            Button("Register Policy") { vm.uvAction("register") }
                                .disabled(vm.busy)
                        }
                        HStack {
                            Button("PIN Check") { vm.uvAction("pin") }.disabled(vm.busy)
                            Button("Finger Check") { vm.uvAction("finger") }.disabled(vm.busy)
                            Button("PIN + Finger Check") { vm.uvAction("and") }
                                .buttonStyle(.borderedProminent)
                                .disabled(vm.busy)
                        }
                        Text("Checks call a protected on-card client. Registration is one-time; AND requires both in one power session.")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    .padding(6)
                }
            }

            // Status bar
            HStack(spacing: 6) {
                Image(systemName: vm.statusIsError ? "xmark.octagon.fill" : "info.circle.fill")
                    .foregroundColor(vm.statusIsError ? .red : .accentColor)
                Text(vm.statusText)
                    .font(.caption)
                    .foregroundColor(vm.statusIsError ? .red : .primary)
                    .lineLimit(3)
            }
            .padding(.top, 2)
        }
        .padding(18)
        .frame(width: 470)
        .onAppear {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
            vm.refresh()
        }
    }
}

@main
struct NuriCardSetupApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentSize)
    }
}
