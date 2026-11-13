package dev.gilberto.gestaousuarios.protecao;

import java.time.Duration;

import org.hibernate.validator.constraints.time.DurationMax;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

/**
 * Propriedades do limite de taxa por IP ({@code dispensaai.security.ratelimit.*}).
 *
 * @param maxRequests máximo de requisições por janela (1 a 10000)
 * @param window      janela fixa (1 segundo a 1 hora)
 */
@Validated
@ConfigurationProperties(prefix = "dispensaai.security.ratelimit")
public record RateLimitProperties(
        @DefaultValue("20") @Min(1) @Max(10000) int maxRequests,
        @DefaultValue("1m") @NotNull @DurationMin(seconds = 1) @DurationMax(hours = 1) Duration window) {
}
