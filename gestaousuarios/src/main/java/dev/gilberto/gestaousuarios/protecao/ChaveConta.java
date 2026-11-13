package dev.gilberto.gestaousuarios.protecao;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Chave de conta para os contadores de força bruta: SHA-256 hex do e-mail normalizado.
 * O e-mail em claro nunca é mantido no mapa nem em log.
 */
public final class ChaveConta {

    private ChaveConta() {
    }

    /** Normaliza (trim + minúsculas) e devolve o SHA-256 em hexadecimal minúsculo (64 caracteres). */
    public static String de(String email) {
        String normalizado = email.trim().toLowerCase(Locale.ROOT);
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(normalizado.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível", e);
        }
    }
}
