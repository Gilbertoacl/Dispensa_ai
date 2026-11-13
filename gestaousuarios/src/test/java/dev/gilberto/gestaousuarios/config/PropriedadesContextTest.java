package dev.gilberto.gestaousuarios.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import dev.gilberto.gestaousuarios.auth.RefreshProperties;

/**
 * Valida os intervalos de {@code access-expiration} (600..900 s) e {@code refresh.expiration}
 * (7..30 dias) na inicialização (R1.8).
 */
class PropriedadesContextTest {

    private static final String SEGREDO = "it-only-secret-0123456789-0123456789-abcdef";

    @Configuration
    @EnableConfigurationProperties({JwtProperties.class, RefreshProperties.class})
    static class Config {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(Config.class)
            .withPropertyValues("dispensaai.security.jwt.secret=" + SEGREDO);

    private static String mensagemCompleta(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            sb.append(c.getMessage()).append('\n');
        }
        return sb.toString();
    }

    private void falhaCitando(String valorPropriedade, String chave, String... citacoes) {
        runner.withPropertyValues(valorPropriedade).run(ctx -> {
            assertThat(ctx).hasFailed();
            String msg = mensagemCompleta(ctx.getStartupFailure());
            assertThat(msg).containsIgnoringCase(chave);
            assertThat(msg).doesNotContain(SEGREDO);
        });
    }

    @Test
    void accessExpiration599Falha() {
        falhaCitando("dispensaai.security.jwt.access-expiration=599", "accessExpiration");
    }

    @Test
    void accessExpiration901Falha() {
        falhaCitando("dispensaai.security.jwt.access-expiration=901", "accessExpiration");
    }

    @Test
    void accessExpirationNosLimitesSobe() {
        runner.withPropertyValues("dispensaai.security.jwt.access-expiration=600")
                .run(ctx -> assertThat(ctx).hasNotFailed());
        runner.withPropertyValues("dispensaai.security.jwt.access-expiration=900")
                .run(ctx -> assertThat(ctx).hasNotFailed());
    }

    @Test
    void refreshExpiration6DiasFalha() {
        falhaCitando("dispensaai.security.refresh.expiration=6d", "expiration");
    }

    @Test
    void refreshExpiration31DiasFalha() {
        falhaCitando("dispensaai.security.refresh.expiration=31d", "expiration");
    }

    @Test
    void refreshExpirationNosLimitesSobe() {
        runner.withPropertyValues("dispensaai.security.refresh.expiration=7d").run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx.getBean(RefreshProperties.class).expiration()).isEqualTo(Duration.ofDays(7));
        });
        runner.withPropertyValues("dispensaai.security.refresh.expiration=30d")
                .run(ctx -> assertThat(ctx).hasNotFailed());
    }

    @Test
    void padroesSaoValidos() {
        runner.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx.getBean(JwtProperties.class).accessExpiration()).isEqualTo(900L);
            assertThat(ctx.getBean(RefreshProperties.class).expiration()).isEqualTo(Duration.ofDays(7));
        });
    }
}
