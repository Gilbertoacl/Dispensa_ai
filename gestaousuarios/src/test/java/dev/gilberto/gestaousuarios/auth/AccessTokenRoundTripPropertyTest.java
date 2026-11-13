package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

import dev.gilberto.gestaousuarios.config.JwtProperties;
import dev.gilberto.gestaousuarios.testsupport.RelogioFalso;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;

class AccessTokenRoundTripPropertyTest {

    private static final SecretKey KEY = new SecretKeySpec(
            "0123456789-0123456789-0123456789-xx".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    private static final JwtEncoder ENCODER = new NimbusJwtEncoder(new ImmutableSecret<>(KEY));
    private static final JwtDecoder DECODER = NimbusJwtDecoder.withSecretKey(KEY)
            .macAlgorithm(MacAlgorithm.HS256).build();

    // Feature: endurecimento-autenticacao, Property 1: Round-trip do access token
    // Validates: Requirements 1.2, 1.7
    @Property(tries = 100)
    void roundTripPreservaSubPerfilTvIssEJanelaDeValidade(@ForAll Perfil perfil, @ForAll long hi, @ForAll long lo,
            @ForAll @IntRange(min = 0, max = 1_000_000) int tv,
            @ForAll @IntRange(min = 600, max = 900) int duracao) {
        // Relógio fixo no instante atual: o NimbusJwtDecoder valida exp contra o relógio do sistema
        RelogioFalso relogio = new RelogioFalso(Instant.now());
        Instant emissao = relogio.instant();
        TokenService service = new TokenService(ENCODER, new JwtProperties("segredo", duracao), relogio);

        UUID id = new UUID(hi, lo);
        Usuario u = mock(Usuario.class);
        when(u.getId()).thenReturn(id);
        when(u.getPerfil()).thenReturn(perfil);
        when(u.getTokenVersion()).thenReturn(tv);

        Jwt jwt = DECODER.decode(service.emitir(u));

        assertThat(jwt.getSubject()).isEqualTo(id.toString());
        assertThat(jwt.getClaimAsString("perfil")).isEqualTo(perfil.name());
        assertThat(((Number) jwt.getClaims().get("tv")).intValue()).isEqualTo(tv);
        assertThat(jwt.getClaimAsString("iss")).isEqualTo("gestaousuarios");
        assertThat(jwt.getIssuedAt().getEpochSecond()).isEqualTo(emissao.getEpochSecond());
        assertThat(jwt.getExpiresAt().getEpochSecond() - jwt.getIssuedAt().getEpochSecond())
                .isEqualTo(duracao);
        assertThat(service.getExpirationSeconds()).isEqualTo(duracao);
    }
}
