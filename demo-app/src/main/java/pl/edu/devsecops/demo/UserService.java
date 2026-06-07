package pl.edu.devsecops.demo;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Bezpieczna implementacja serwisu użytkowników.
 * Wersja bez podatności — do demonstracji że pipeline PRZEPUSZCZA czysty kod.
 */
public class UserService {

    // Bezpieczny generator losowości
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generuje kryptograficznie bezpieczny token sesji.
     */
    public String generateSessionToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Prosta walidacja username — tylko litery i cyfry.
     */
    public boolean isValidUsername(String username) {
        return username != null && username.matches("^[a-zA-Z0-9]{3,20}$");
    }
}
