package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.time.Instant;
import java.util.UUID;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/** Propriedade do User-Agent persistido pelo {@link RefreshToken} real. */
class RefreshTokenUserAgentPropertyTest {

    private static RefreshToken criar(String userAgent) {
        Instant agora = Instant.parse("2025-01-01T00:00:00Z");
        return new RefreshToken(UUID.randomUUID(), UUID.randomUUID(), "h".repeat(64), UUID.randomUUID(),
                agora, agora.plusSeconds(3600), userAgent, "127.0.0.1");
    }

    // Feature: endurecimento-autenticacao, Property 23: User-Agent persistido é limitado a 255 caracteres
    // Validates: Requirements 16.10
    @Property(tries = 200)
    void userAgentPersistidoEhLimitadoA255(@ForAll("userAgents") String userAgent) {
        assertThatCode(() -> criar(userAgent)).doesNotThrowAnyException();
        RefreshToken token = criar(userAgent);

        if (userAgent == null) {
            assertThat(token.getUserAgent()).isNull();
        } else {
            assertThat(token.getUserAgent()).hasSizeLessThanOrEqualTo(255);
            assertThat(token.getUserAgent()).isEqualTo(
                    userAgent.length() > 255 ? userAgent.substring(0, 255) : userAgent);
        }
    }

    @Provide
    Arbitrary<String> userAgents() {
        Arbitrary<String> texto = Arbitraries.strings().ofMinLength(0).ofMaxLength(2000);
        return Arbitraries.oneOf(texto, Arbitraries.just((String) null));
    }
}
