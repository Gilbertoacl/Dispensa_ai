package dev.gilberto.gestaousuarios.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/**
 * Propriedades do JWT de acesso ({@code dispensaai.security.jwt.*}).
 *
 * @param secret           segredo HMAC; a regra de produção fica no {@code JwtSecretValidator}
 * @param accessExpiration validade do access token em segundos (600 a 900)
 */
@Validated
@ConfigurationProperties(prefix = "dispensaai.security.jwt")
public record JwtProperties(
        @NotBlank String secret,
        @DefaultValue("900") @Min(600) @Max(900) long accessExpiration) {

    /** Nunca expõe o segredo. */
    @Override
    public String toString() {
        return "JwtProperties[secret=****, accessExpiration=" + accessExpiration + "]";
    }
}
