package dev.gilberto.gestaousuarios.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;

/**
 * Valida o {@link JwtSecretValidator} na inicialização do contexto (R12.1 a R12.3).
 */
class JwtSecretValidatorContextTest {

    private static final String SEGREDO_DEV = "dev-only-secret-change-me-0123456789abcdef";
    private static final String SEGREDO_FORTE = "prod-strong-secret-0123456789-0123456789-abcdef";

    @Configuration
    @EnableConfigurationProperties(JwtProperties.class)
    @Import(JwtSecretValidator.class)
    static class Config {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(Config.class);

    @Test
    void prodComSegredoDevFalhaSemVazarSegredo() {
        runner.withPropertyValues("spring.profiles.active=prod", "dispensaai.security.jwt.secret=" + SEGREDO_DEV)
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    Throwable causa = ctx.getStartupFailure();
                    while (causa.getCause() != null) {
                        causa = causa.getCause();
                    }
                    assertThat(causa).isInstanceOf(IllegalStateException.class)
                            .hasMessage(Mensagens.get("jwt.segredo.invalido.producao"));
                    assertThat(causa.getMessage()).doesNotContain(SEGREDO_DEV);
                    assertThat(ctx.getStartupFailure().toString()).doesNotContain(SEGREDO_DEV);
                });
    }

    @Test
    void prodComSegredoCurtoFalha() {
        runner.withPropertyValues("spring.profiles.active=prod", "dispensaai.security.jwt.secret=curto")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void prodSemSegredoFalha() {
        runner.withPropertyValues("spring.profiles.active=prod").run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void prodComSegredoForteSobe() {
        runner.withPropertyValues("spring.profiles.active=prod", "dispensaai.security.jwt.secret=" + SEGREDO_FORTE)
                .run(ctx -> assertThat(ctx).hasNotFailed());
    }

    @Test
    void devComSegredoDevSobe() {
        runner.withPropertyValues("spring.profiles.active=dev", "dispensaai.security.jwt.secret=" + SEGREDO_DEV)
                .run(ctx -> assertThat(ctx).hasNotFailed());
    }

    @Test
    void testComSegredoDevSobe() {
        runner.withPropertyValues("spring.profiles.active=test", "dispensaai.security.jwt.secret=" + SEGREDO_DEV)
                .run(ctx -> assertThat(ctx).hasNotFailed());
    }
}
