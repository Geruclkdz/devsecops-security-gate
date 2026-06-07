package pl.edu.devsecops.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.Random;

/**
 * UWAGA: Ten plik zawiera CELOWE podatności bezpieczeństwa.
 * Służy wyłącznie do demonstracji działania security gate w pipeline.
 *
 * Zawarte podatności (zgodnie z OWASP Top 10):
 *   1. SQL Injection (CWE-89)
 *   2. Hardcoded credentials (CWE-798)
 *   3. Słabe hashowanie hasła (MD5) (CWE-327)
 *   4. Niezabezpieczony zapis do pliku (CWE-73)
 *   5. Słaby generator losowości dla celów bezpieczeństwa (CWE-330)
 */
public class VulnerableApp {

    // PODATNOŚĆ #2: Hardcoded credentials (CWE-798)
    // Semgrep: java.lang.security.hardcoded-password
    private static final String DB_PASSWORD = "admin123";
    private static final String DB_USER = "root";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";

    /**
     * PODATNOŚĆ #1: SQL Injection (CWE-89)
     * Użytkownik może wstrzyknąć ' OR '1'='1 i uzyskać dostęp do całej bazy.
     * Semgrep: java.lang.security.audit.sqli.jdbc-sqli
     */
    public String getUserByName(String username) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // Niebezpieczne: bezpośrednie wstrzyknięcie parametru do zapytania
        String query = "SELECT * FROM users WHERE name = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);
        return rs.next() ? rs.getString("name") : null;
    }

    /**
     * PODATNOŚĆ #3: Słabe hashowanie — MD5 jest kryptograficznie złamany (CWE-327)
     * Semgrep: java.lang.security.audit.crypto.use-of-md5
     */
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /**
     * PODATNOŚĆ #4: Path traversal — użytkownik może zapisać plik w dowolnym miejscu (CWE-73)
     * Semgrep: java.lang.security.audit.path-traversal.path-traversal-file-write
     */
    public void writeToFile(String filename, String content) throws Exception {
        // Niebezpieczne: filename nie jest walidowany — można podać "../../etc/passwd"
        FileWriter fw = new FileWriter("/tmp/" + filename);
        fw.write(content);
        fw.close();
    }

    /**
     * PODATNOŚĆ #5: java.util.Random nie nadaje się do celów kryptograficznych (CWE-330)
     * Dla tokenów bezpieczeństwa należy używać SecureRandom.
     * Semgrep: java.lang.security.audit.crypto.weak-random
     */
    public String generateToken() {
        Random random = new Random();
        return String.valueOf(random.nextLong());
    }
}
