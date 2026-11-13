package dev.gilberto.gestaousuarios.auth;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Hash BCrypt fictício gerado uma única vez na inicialização, comparado quando o e-mail não
 * existe para igualar o custo de uma tentativa inválida (mitiga enumeração por tempo).
 */
@Component
public class HashFicticio {

    private final String hash;

    public HashFicticio(PasswordEncoder passwordEncoder, SecureRandom secureRandom) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        this.hash = passwordEncoder.encode(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    public String valor() {
        return hash;
    }
}
