import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Machine Learning on Blockchain (MLOB)
 * Single-file Java prototype for an engineering sensor-data security system.
 *
 * Requirements: Java 17+
 * Run:
 *   javac MlobConsole.java
 *   java MlobConsole
 *
 * All generated files are stored in the ./mlob_data directory.
 */
public class MlobConsole {
    private static final Scanner SC = new Scanner(System.in);
    private static final Path ROOT = Paths.get("mlob_data");
    private static final Path OFFCHAIN = ROOT.resolve("offchain");
    private static final Path ASSETS = ROOT.resolve("assets.tsv");
    private static final Path CHAIN = ROOT.resolve("blockchain.tsv");
    private static final Path AUDIT = ROOT.resolve("audit.log");
    private static String role = "Admin";

    public static void main(String[] args) {
        try {
            Files.createDirectories(OFFCHAIN);
            initializeFiles();
            System.out.println("=== MLOB: Machine Learning on Blockchain ===");
            System.out.println("Engineering data security prototype");
            while (true) {
                showMenu();
                int choice = readInt("Choose: ");
                try {
                    switch (choice) {
                        case 1 -> generateDataset();
                        case 2 -> registerAsset();
                        case 3 -> listAssets();
                        case 4 -> verifyAssets();
                        case 5 -> analyzeDataset();
                        case 6 -> approveModel();
                        case 7 -> showBlockchain();
                        case 8 -> verifyBlockchain();
                        case 9 -> showAuditLog();
                        case 10 -> switchRole();
                        case 0 -> {
                            System.out.println("MLOB closed.");
                            return;
                        }
                        default -> System.out.println("Invalid option.");
                    }
                } catch (Exception e) {
                    System.out.println("Operation failed: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("Startup failed: " + e.getMessage());
        }
    }

    private static void showMenu() {
        System.out.println("\nUser role: " + role);
        System.out.println("1. Generate sample sensor dataset");
        System.out.println("2. Register dataset on blockchain");
        System.out.println("3. List registered assets");
        System.out.println("4. Verify file integrity");
        System.out.println("5. Detect sensor anomalies");
        System.out.println("6. Approve ML model version");
        System.out.println("7. View blockchain");
        System.out.println("8. Verify blockchain");
        System.out.println("9. View audit log");
        System.out.println("10. Switch user role");
        System.out.println("0. Exit");
    }

    private static void initializeFiles() throws Exception {
        if (!Files.exists(ASSETS))
            Files.writeString(ASSETS, "id\tfilename\tstored_path\tsha256\tregistered_at\n");
        if (!Files.exists(CHAIN)) {
            String genesis = hash("MLOB-GENESIS");
            Files.writeString(CHAIN, "0\tGENESIS\t" + genesis + "\t" +
                    LocalDateTime.now() + "\n");
        }
    }

    private static void generateDataset() throws IOException {
        requireRole("Admin", "Analyst");
        Path file = ROOT.resolve("engineering_sensor_data.csv");
        StringBuilder csv = new StringBuilder("timestamp,temperature,vibration,pressure\n");
        Random random = new Random(42);
        for (int i = 1; i <= 50; i++) {
            double temperature = 65 + random.nextDouble() * 12;
            double vibration = 2 + random.nextDouble() * 1.2;
            double pressure = 95 + random.nextDouble() * 10;
            if (i == 12) temperature = 115;
            if (i == 27) vibration = 9.5;
            if (i == 39) pressure = 150;
            csv.append("T").append(i).append(",")
               .append(String.format(Locale.US, "%.2f", temperature)).append(",")
               .append(String.format(Locale.US, "%.2f", vibration)).append(",")
               .append(String.format(Locale.US, "%.2f", pressure)).append("\n");
        }
        Files.writeString(file, csv, StandardCharsets.UTF_8);
        audit("GENERATE_DATASET", file.getFileName().toString());
        System.out.println("Dataset created: " + file.toAbsolutePath());
    }

    private static void registerAsset() throws Exception {
        requireRole("Admin", "Analyst");
        System.out.print("Enter dataset file path: ");
        String input = SC.nextLine().trim();
        Path source = Paths.get(input).toAbsolutePath().normalize();
        if (!Files.isRegularFile(source))
            throw new FileNotFoundException("File does not exist: " + source);

        String id = UUID.randomUUID().toString();
        String safeName = source.getFileName().toString().replaceAll("[^a-zA-Z0-9._-]", "_");
        Path destination = OFFCHAIN.resolve(id + "_" + safeName);
        Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING);
        String digest = sha256(destination);
        String row = id + "\t" + safeName + "\t" + destination + "\t" + digest +
                     "\t" + LocalDateTime.now() + "\n";
        Files.writeString(ASSETS, row, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        addBlock("ASSET_REGISTERED", id + "|" + safeName + "|" + digest);
        audit("REGISTER_ASSET", id);
        System.out.println("Asset registered. ID: " + id);
        System.out.println("SHA-256: " + digest);
    }

    private static void listAssets() throws IOException {
        List<String> lines = Files.readAllLines(ASSETS);
        if (lines.size() <= 1) {
            System.out.println("No assets registered.");
            return;
        }
        System.out.println("\nRegistered assets:");
        for (int i = 1; i < lines.size(); i++) {
            String[] p = lines.get(i).split("\t", -1);
            if (p.length >= 5)
                System.out.println(p[0] + " | " + p[1] + " | " + p[4]);
        }
    }

    private static void verifyAssets() throws Exception {
        requireRole("Admin", "Analyst", "Auditor");
        List<String> lines = Files.readAllLines(ASSETS);
        int checked = 0;
        for (int i = 1; i < lines.size(); i++) {
            String[] p = lines.get(i).split("\t", -1);
            if (p.length < 5) continue;
            Path file = Paths.get(p[2]);
            checked++;
            boolean exists = Files.isRegularFile(file);
            boolean valid = exists && sha256(file).equals(p[3]);
            System.out.println(p[1] + " -> " +
                    (valid ? "INTEGRITY OK" : "WARNING: MISSING OR MODIFIED"));
            if (!valid) addBlock("INTEGRITY_FAILURE", p[0] + "|" + p[1]);
        }
        if (checked == 0) System.out.println("No registered assets to verify.");
        audit("VERIFY_ASSETS", "checked=" + checked);
    }

    private static void analyzeDataset() throws Exception {
        requireRole("Admin", "Analyst");
        System.out.print("CSV path (press Enter for sample dataset): ");
        String input = SC.nextLine().trim();
        Path file = input.isEmpty() ? ROOT.resolve("engineering_sensor_data.csv")
                                    : Paths.get(input).toAbsolutePath().normalize();
        if (!Files.isRegularFile(file))
            throw new FileNotFoundException("Generate the sample dataset or enter a valid CSV path.");

        List<String> lines = Files.readAllLines(file);
        if (lines.size() < 2) throw new IOException("Dataset is empty.");
        int anomalies = 0, validRows = 0;
        System.out.println("\nAnomaly report (rule-based baseline):");
        for (int i = 1; i < lines.size(); i++) {
            String[] p = lines.get(i).split(",");
            if (p.length < 4) continue;
            try {
                double temp = Double.parseDouble(p[1].trim());
                double vibration = Double.parseDouble(p[2].trim());
                double pressure = Double.parseDouble(p[3].trim());
                validRows++;
                List<String> reasons = new ArrayList<>();
                if (temp > 90 || temp < 0) reasons.add("temperature");
                if (vibration > 5 || vibration < 0) reasons.add("vibration");
                if (pressure > 125 || pressure < 70) reasons.add("pressure");
                if (!reasons.isEmpty()) {
                    anomalies++;
                    System.out.println("Row " + (i + 1) + " [" + p[0] + "] -> " + reasons);
                }
            } catch (NumberFormatException ignored) {
                System.out.println("Skipping invalid numeric row " + (i + 1));
            }
        }
        System.out.println("Valid rows: " + validRows + " | Anomalies: " + anomalies);
        addBlock("ANOMALY_ANALYSIS", "file=" + file.getFileName() +
                 "|rows=" + validRows + "|anomalies=" + anomalies);
        audit("ANOMALY_ANALYSIS", "anomalies=" + anomalies);
    }

    private static void approveModel() throws Exception {
        requireRole("Admin");
        System.out.print("Enter model name: ");
        String name = SC.nextLine().trim();
        if (name.isEmpty()) throw new IllegalArgumentException("Model name is required.");
        System.out.print("Enter model version (e.g. 1.0): ");
        String version = SC.nextLine().trim();
        if (version.isEmpty()) throw new IllegalArgumentException("Version is required.");
        addBlock("MODEL_VERSION_APPROVED", name + "|" + version);
        audit("MODEL_APPROVED", name + "|" + version);
        System.out.println("Model version recorded on blockchain.");
    }

    private static void showBlockchain() throws IOException {
        System.out.println("\nIndex | Event | Hash | Timestamp");
        for (String line : Files.readAllLines(CHAIN)) {
            String[] p = line.split("\t", -1);
            if (p.length >= 4)
                System.out.println(p[0] + " | " + p[1] + " | " +
                        p[2].substring(0, Math.min(16, p[2].length())) + "... | " + p[3]);
        }
    }

    private static void verifyBlockchain() throws Exception {
        requireRole("Admin", "Auditor");
        List<String> lines = Files.readAllLines(CHAIN);
        String previousHash = "";
        boolean valid = true;
        for (int i = 0; i < lines.size(); i++) {
            String[] p = lines.get(i).split("\t", -1);
            if (p.length != 4) { valid = false; break; }
            String index = p[0], event = p[1], storedHash = p[2], timestamp = p[3];
            String expected = hash(index + "|" + event + "|" + timestamp + "|" + previousHash);
            if (i == 0) expected = hash("MLOB-GENESIS");
            if (!storedHash.equals(expected)) { valid = false; break; }
            previousHash = storedHash;
        }
        System.out.println(valid ? "BLOCKCHAIN VALID" : "BLOCKCHAIN TAMPERING DETECTED");
        audit("VERIFY_BLOCKCHAIN", valid ? "valid" : "invalid");
    }

    private static void addBlock(String event, String data) throws Exception {
        List<String> lines = Files.readAllLines(CHAIN);
        String previousHash = "";
        if (!lines.isEmpty()) {
            String[] last = lines.get(lines.size() - 1).split("\t", -1);
            if (last.length >= 3) previousHash = last[2];
        }
        int index = lines.size();
        String timestamp = LocalDateTime.now().toString();
        String blockHash = hash(index + "|" + event + "|" + timestamp + "|" +
                                previousHash + "|" + data);
        // Store event data inside the event field in encoded form to keep TSV structure safe.
        String safeEvent = event + ":" + Base64.getEncoder().encodeToString(
                data.getBytes(StandardCharsets.UTF_8));
        blockHash = hash(index + "|" + safeEvent + "|" + timestamp + "|" + previousHash);
        Files.writeString(CHAIN, index + "\t" + safeEvent + "\t" + blockHash + "\t" +
                timestamp + "\n", StandardCharsets.UTF_8, StandardOpenOption.APPEND);
    }

    private static void switchRole() {
        System.out.println("1. Admin  2. Analyst  3. Auditor  4. Guest");
        int n = readInt("Select role: ");
        role = switch (n) {
            case 1 -> "Admin";
            case 2 -> "Analyst";
            case 3 -> "Auditor";
            case 4 -> "Guest";
            default -> role;
        };
        System.out.println("Current role: " + role);
    }

    private static void showAuditLog() throws IOException {
        requireRole("Admin", "Auditor");
        if (!Files.exists(AUDIT)) {
            System.out.println("No audit entries.");
            return;
        }
        Files.readAllLines(AUDIT).forEach(System.out::println);
    }

    private static void audit(String action, String details) throws IOException {
        String line = LocalDateTime.now() + "\t" + role + "\t" + action +
                      "\t" + details.replace("\n", " ") + "\n";
        Files.writeString(AUDIT, line, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    private static void requireRole(String... allowed) {
        for (String a : allowed) if (role.equals(a)) return;
        throw new SecurityException("Access denied for role: " + role);
    }

    private static int readInt(String prompt) {
        System.out.print(prompt);
        String value = SC.nextLine().trim();
        try { return Integer.parseInt(value); }
        catch (NumberFormatException e) { return -1; }
    }

    private static String sha256(Path file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = in.read(buffer)) != -1) md.update(buffer, 0, count);
        }
        return HexFormat.of().formatHex(md.digest());
    }

    private static String hash(String value) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(
                md.digest(value.getBytes(StandardCharsets.UTF_8)));
    }
}
