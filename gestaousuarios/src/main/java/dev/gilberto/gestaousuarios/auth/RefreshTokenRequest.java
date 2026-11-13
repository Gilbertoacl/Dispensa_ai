package dev.gilberto.gestaousuarios.auth;

import jakarta.validation.constraints.NotBlank;

/** Corpo de {@code /v1/auth/refresh} e {@code /v1/auth/logout}. */
public record RefreshTokenRequest(
        @NotBlank(message = "{refresh.obrigatorio}")
        String refreshToken
) {

    /** Nunca expõe o valor do token. */
    @Override
    public String toString() {
        return "RefreshTokenRequest[refreshToken=****]";
    }
}
