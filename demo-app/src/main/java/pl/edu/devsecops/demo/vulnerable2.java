package pl.edu.devsecops.demo;

import java.net.URL;

public class vulnerable2 {
    // 1. SQL Injection
    public String buildQuery(String username) {
        return "SELECT * FROM users WHERE username = '" + username + "'";
    }

    // 2. Hardcoded secret
    private static final String PASSWORD = "Admin123!";

    // 3. SSRF
    public void fetch(String url) throws Exception {
        new URL(url).openStream().close();
    }
}

