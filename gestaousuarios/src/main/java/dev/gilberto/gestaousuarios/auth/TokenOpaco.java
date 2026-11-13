package dev.gilberto.gestaousuarios.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Utilitário puro para refresh tokens opacos: geração aleatória e hash para persistência.
 */
public final class TokenOpaco {

    private static final int TAMANHO_BYTES = 32;

    private TokenOpaco() {
    }

    /** Gera 32 bytes aleatórios em Base64 URL-safe sem padding (43 caracteres). */
    public static String gerar(SecureRandom rnd) {
        byte[] bytes = new byte[TAMANHO_BYTES];
        rnd.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** SHA-256 do valor em UTF-8, em hexadecimal minúsculo (64 caracteres). */
    public static String hash(String claro) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(claro.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível na JVM", e);
        }
    }
}
