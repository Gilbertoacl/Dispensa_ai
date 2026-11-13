package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;

class TokenVersionValidatorTest {

    private static final String SEGREDO = "unit-test-secret-0123456789-0123456789-abcdef";

    private UsuarioRepository repo;
    private TokenVersionValidator validator;
    private final UUID id = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        repo = mock(UsuarioRepository.class);
        validator = new TokenVersionValidator(repo);
    }

    private static Jwt jwt(String sub, Object tv) {
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "HS256")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(600));
        if (sub != null) {
            b.subject(sub);
        }
        if (tv != null) {
            b.claim("tv", tv);
        }
        return b.build();
    }

    private static void assertRevogado(OAuth2TokenValidatorResult r) {
        assertThat(r.hasErrors()).isTrue();
        assertThat(r.getErrors()).hasSize(1);
        OAuth2Error e = r.getErrors().iterator().next();
        assertThat(e.getDescription()).isEqualTo("token_revogado");
        assertThat(e.getDescription()).isEqualTo(TokenVersionValidator.DESCRICAO_REVOGADO);
    }

    @Test
    void tvAusenteFalhaSemConsultar() {
        assertRevogado(validator.validate(jwt(id.toString(), null)));
        verifyNoInteractions(repo);
    }

    @Test
    void tvNaoInteiraFalhaSemConsultar() {
        assertRevogado(validator.validate(jwt(id.toString(), "3")));
        assertRevogado(validator.validate(jwt(id.toString(), 3.5d)));
        assertRevogado(validator.validate(jwt(id.toString(), Boolean.TRUE)));
        verifyNoInteractions(repo);
    }

    @Test
    void tvForaDeIntFalhaSemConsultar() {
        assertRevogado(validator.validate(jwt(id.toString(), (long) Integer.MAX_VALUE + 1)));
        assertRevogado(validator.validate(jwt(id.toString(), (long) Integer.MIN_VALUE - 1)));
        verifyNoInteractions(repo);
    }

    @Test
    void subInvalidoOuAusenteFalhaSemConsultar() {
        assertRevogado(validator.validate(jwt("nao-e-uuid", 1)));
        assertRevogado(validator.validate(jwt(null, 1)));
        verifyNoInteractions(repo);
    }

    @Test
    void usuarioInexistenteFalha() {
        when(repo.buscarTokenVersion(id)).thenReturn(Optional.empty());
        assertRevogado(validator.validate(jwt(id.toString(), 0)));
        verify(repo, times(1)).buscarTokenVersion(id);
    }

    @Test
    void versaoDiferenteFalha() {
        when(repo.buscarTokenVersion(id)).thenReturn(Optional.of(5));
        assertRevogado(validator.validate(jwt(id.toString(), 4)));
        verify(repo, times(1)).buscarTokenVersion(id);
    }

    @Test
    void versaoIgualSucesso() {
        when(repo.buscarTokenVersion(id)).thenReturn(Optional.of(5));
        assertThat(validator.validate(jwt(id.toString(), 5)).hasErrors()).isFalse();
        assertThat(validator.validate(jwt(id.toString(), 5L)).hasErrors()).isFalse();
        verify(repo, times(2)).buscarTokenVersion(id);
    }

    @Test
    void umaConsultaPorValidate() {
        when(repo.buscarTokenVersion(id)).thenReturn(Optional.of(1));
        validator.validate(jwt(id.toString(), 1));
        verify(repo, times(1)).buscarTokenVersion(any());
    }

    // ---- JwtDecoder real, montado como na SecurityConfig ----

    private SecretKey chave() {
        return new SecretKeySpec(SEGREDO.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    private NimbusJwtDecoder decoderReal() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(chave())
                .macAlgorithm(MacAlgorithm.HS256).build();
        OAuth2TokenValidator<Jwt> padrao = JwtValidators.createDefaultWithIssuer("gestaousuarios");
        decoder.setJwtValidator(jwt -> {
            OAuth2TokenValidatorResult r = padrao.validate(jwt);
            return r.hasErrors() ? r : validator.validate(jwt);
        });
        return decoder;
    }

    private String token(Instant iat, Instant exp, int tv) {
        JwtEncoder enc = new NimbusJwtEncoder(new ImmutableSecret<>(chave()));
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer("gestaousuarios")
                .issuedAt(iat).expiresAt(exp).subject(id.toString())
                .claim("perfil", "USER").claim("tv", tv).build();
        return enc.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims))
                .getTokenValue();
    }

    @Test
    void decoderReal_tokenValidoPassa() {
        when(repo.buscarTokenVersion(id)).thenReturn(Optional.of(2));
        Instant agora = Instant.now();
        Jwt jwt = decoderReal().decode(token(agora, agora.plusSeconds(600), 2));
        assertThat(jwt.getSubject()).isEqualTo(id.toString());
        verify(repo, times(1)).buscarTokenVersion(id);
    }

    @Test
    void decoderReal_tokenExpiradoFalhaSemConsultarBanco() {
        Instant agora = Instant.now();
        String t = token(agora.minusSeconds(1200), agora.minusSeconds(600), 2);
        assertThatThrownBy(() -> decoderReal().decode(t))
                .isInstanceOf(BadJwtException.class)
                .hasMessageContaining("Jwt expired");
        verifyNoInteractions(repo);
    }

    @Test
    void decoderReal_tvAntigoFalhaComTokenRevogado() {
        when(repo.buscarTokenVersion(id)).thenReturn(Optional.of(3));
        Instant agora = Instant.now();
        String t = token(agora, agora.plusSeconds(600), 2);
        assertThatThrownBy(() -> decoderReal().decode(t))
                .isInstanceOf(JwtValidationException.class)
                .satisfies(e -> assertThat(((JwtValidationException) e).getErrors())
                        .anyMatch(er -> "token_revogado".equals(er.getDescription())));
    }
}
