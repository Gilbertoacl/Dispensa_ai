package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import dev.gilberto.gestaousuarios.testsupport.SessaoFixture;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;

class SessaoRenovacaoPropertyTest {

    // Feature: endurecimento-autenticacao, Property 6: Token renovado reflete o estado atual do usuário
    // Validates: Requirements 2.4
    @Property(tries = 100)
    void tokenRenovadoRefleteOPerfilEATokenVersionCorrentes(
            @ForAll Perfil perfilNoLogin,
            @ForAll Perfil perfilAtual,
            @ForAll @IntRange(min = 0, max = 1000) int tvNoLogin,
            @ForAll @IntRange(min = 0, max = 1000) int tvAtual) {
        SessaoFixture fx = new SessaoFixture();
        SecretKey key = new SecretKeySpec(
                "0123456789-0123456789-0123456789-xx".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        Usuario usuario = fx.novoUsuario(perfilNoLogin);
        fx.definirTokenVersion(usuario, tvNoLogin);

        TokenResponse login = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        Jwt jwtLogin = decoder.decode(login.accessToken());
        assertThat(jwtLogin.getClaimAsString("perfil")).isEqualTo(perfilNoLogin.name());

        // o estado do usuário muda entre o login e o refresh
        usuario.alterarPerfil(perfilAtual);
        fx.definirTokenVersion(usuario, tvAtual);

        TokenResponse renovado = fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE);
        Jwt jwt = decoder.decode(renovado.accessToken());

        assertThat(jwt.getSubject()).isEqualTo(usuario.getId().toString());
        assertThat(jwt.getClaimAsString("perfil")).isEqualTo(perfilAtual.name());
        assertThat(((Number) jwt.getClaims().get("tv")).intValue()).isEqualTo(tvAtual);
    }
}
