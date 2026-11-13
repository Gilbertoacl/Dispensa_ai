package dev.gilberto.gestaousuarios.auth;

import java.time.Clock;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import dev.gilberto.gestaousuarios.config.JwtProperties;
import dev.gilberto.gestaousuarios.usuario.Usuario;

/**
 * Emite tokens JWT assinados (HMAC-SHA256) para usuários autenticados (R4.2).
 *
 * <p>O token carrega o identificador do usuário em {@code sub}, o perfil na claim
 * {@code perfil} e expira em {@code dispensaai.security.jwt.access-expiration} segundos
 * (600 a 900, default 900). A assinatura é delegada ao {@link JwtEncoder} configurado em
 * {@code SecurityConfig}, que compartilha o mesmo segredo simétrico do decoder.
 */
@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final long expirationSeconds;
    private final Clock clock;

    @Autowired
    public TokenService(JwtEncoder jwtEncoder, JwtProperties jwtProperties, Clock clock) {
        this(jwtEncoder, jwtProperties.accessExpiration(), clock);
    }

    /** Construtor de conveniência (testes), com relógio do sistema. */
    public TokenService(JwtEncoder jwtEncoder, long expirationSeconds) {
        this(jwtEncoder, expirationSeconds, Clock.systemUTC());
    }

    private TokenService(JwtEncoder jwtEncoder, long expirationSeconds, Clock clock) {
        if (expirationSeconds < 600 || expirationSeconds > 900) {
            throw new IllegalArgumentException(
                    "A expiração do access token deve estar entre 600 e 900 segundos");
        }
        this.jwtEncoder = jwtEncoder;
        this.expirationSeconds = expirationSeconds;
        this.clock = clock;
    }

    /**
     * Emite um JWT para o usuário informado, com {@code sub=id}, claim {@code perfil} e
     * expiração {@code now + expirationSeconds} (R4.2).
     *
     * @param usuario usuário autenticado
     * @return o token JWT codificado (valor compacto)
     */
    public String emitir(Usuario usuario) {
        Instant now = clock.instant();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("gestaousuarios")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expirationSeconds))
                .subject(usuario.getId().toString())
                .claim("perfil", usuario.getPerfil().name())
                .claim("tv", usuario.getTokenVersion())
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    /**
     * Tempo de vida do token em segundos, usado para montar o {@code TokenResponse}.
     */
    public long getExpirationSeconds() {
        return expirationSeconds;
    }
}
