package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
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

import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;

class TokenServicePropertyTest {

    // Feature: gestao-usuarios-autenticacao, Property 6: Round-trip de emissão/decodificação do token
    // Validates: Requirements 4.2
    @Property(tries = 100)
    void roundTripDeEmissaoEDecodificacaoDoToken(@ForAll Perfil perfil, @ForAll long hi, @ForAll long lo,
            @ForAll int tokenVersion) {
        SecretKey key = new SecretKeySpec(
                "0123456789-0123456789-0123456789-xx".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        JwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        TokenService tokenService = new TokenService(encoder, 900L);

        UUID uuid = new UUID(hi, lo);
        Usuario u = mock(Usuario.class);
        when(u.getId()).thenReturn(uuid);
        when(u.getPerfil()).thenReturn(perfil);
        when(u.getTokenVersion()).thenReturn(tokenVersion);

        String token = tokenService.emitir(u);
        Jwt jwt = decoder.decode(token);

        assertThat(jwt.getSubject()).isEqualTo(uuid.toString());
        assertThat(jwt.getClaimAsString("perfil")).isEqualTo(perfil.name());
        Object tv = jwt.getClaims().get("tv");
        assertThat(tv).isInstanceOf(Number.class);
        assertThat(((Number) tv).intValue()).isEqualTo(tokenVersion);
        assertThat(jwt.getExpiresAt()).isNotNull();
        assertThat(jwt.getIssuedAt()).isNotNull();
        assertThat(jwt.getExpiresAt().getEpochSecond() - jwt.getIssuedAt().getEpochSecond()).isEqualTo(900L);
    }
}
