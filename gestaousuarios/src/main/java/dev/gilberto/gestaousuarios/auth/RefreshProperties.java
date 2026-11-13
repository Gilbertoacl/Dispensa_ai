package dev.gilberto.gestaousuarios.auth;

import java.time.Duration;

import org.hibernate.validator.constraints.time.DurationMax;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotNull;

/**
 * Propriedades do refresh token ({@code dispensaai.security.refresh.*}).
 *
 * @param expiration validade do refresh token (7 a 30 dias)
 */
@Validated
@ConfigurationProperties(prefix = "dispensaai.security.refresh")
public record RefreshProperties(
        @DefaultValue("7d") @NotNull @DurationMin(days = 7) @DurationMax(days = 30) Duration expiration) {
}
