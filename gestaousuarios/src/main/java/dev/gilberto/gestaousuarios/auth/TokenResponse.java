package dev.gilberto.gestaousuarios.auth;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Par de tokens devolvido no login e no refresh.
 *
 * @param accessToken    JWT de acesso
 * @param refreshToken   refresh token opaco (valor em claro, exibido uma única vez)
 * @param tokenType      sempre {@code Bearer}
 * @param expiraEm       validade do access token, em segundos
 * @param refreshExpiraEm validade do refresh token, em segundos
 */
public record TokenResponse(
        @Schema(description = "JWT de acesso (curta duração), enviado em Authorization: Bearer",
                example = "eyJhbGciOiJIUzI1NiJ9...")
        String accessToken,
        @Schema(description = "Refresh token opaco e rotativo; exibido uma única vez e de uso único",
                example = "q3J1x...")
        String refreshToken,
        @Schema(description = "Tipo do token; sempre Bearer", example = "Bearer")
        String tokenType,
        @Schema(description = "Validade do access token, em segundos", example = "900")
        long expiraEm,
        @Schema(description = "Validade do refresh token, em segundos", example = "604800")
        long refreshExpiraEm) {

    /** Nunca expõe os tokens. */
    @Override
    public String toString() {
        return "TokenResponse[accessToken=****, refreshToken=****, tokenType=" + tokenType
                + ", expiraEm=" + expiraEm + ", refreshExpiraEm=" + refreshExpiraEm + "]";
    }
}
