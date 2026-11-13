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
 * Propriedades do bloqueio temporário por força bruta ({@code dispensaai.security.lockout.*}).
 *
 * @param maxAttempts limiar de falhas dentro da janela (1 a 100)
 * @param window      janela de contagem das falhas (1 minuto a 24 horas)
 * @param duration    duração do bloqueio temporário (1 minuto a 24 horas)
 */
@Validated
@ConfigurationProperties(prefix = "dispensaai.security.lockout")
public record LockoutProperties(
        @DefaultValue("5") @Min(1) @Max(100) int maxAttempts,
        @DefaultValue("15m") @NotNull @DurationMin(minutes = 1) @DurationMax(hours = 24) Duration window,
        @DefaultValue("15m") @NotNull @DurationMin(minutes = 1) @DurationMax(hours = 24) Duration duration) {
}
