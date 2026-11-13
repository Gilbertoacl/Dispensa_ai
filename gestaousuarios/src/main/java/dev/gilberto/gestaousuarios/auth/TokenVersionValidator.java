package dev.gilberto.gestaousuarios.auth;

import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;
import java.math.BigInteger;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Valida a claim {@code tv} do access token contra a {@code tokenVersion} atual do usuario
 * (uma unica leitura por chave primaria). Claim ausente/nao inteira, {@code sub} invalido,
 * usuario inexistente ou versao diferente resultam em erro mapeado para 401 {@code token.revogado}.
 */
@Component
public class TokenVersionValidator implements OAuth2TokenValidator<Jwt> {

    public static final String DESCRICAO_REVOGADO = "token_revogado";

    private final UsuarioRepository usuarioRepository;

    public TokenVersionValidator(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Integer tv = extrairTv(jwt.getClaims().get("tv"));
        UUID id = extrairId(jwt.getSubject());
        if (tv == null || id == null) {
            return falha();
        }
        Optional<Integer> atual = usuarioRepository.buscarTokenVersion(id);
        if (atual.isPresent() && atual.get().intValue() == tv.intValue()) {
            return OAuth2TokenValidatorResult.success();
        }
        return falha();
    }

    private static OAuth2TokenValidatorResult falha() {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", DESCRICAO_REVOGADO, null));
    }

    private static UUID extrairId(String sub) {
        if (sub == null) {
            return null;
        }
        try {
            return UUID.fromString(sub);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static Integer extrairTv(Object claim) {
        if (claim instanceof Integer || claim instanceof Long || claim instanceof Short || claim instanceof Byte) {
            long v = ((Number) claim).longValue();
            return (v >= Integer.MIN_VALUE && v <= Integer.MAX_VALUE) ? Integer.valueOf((int) v) : null;
        }
        if (claim instanceof BigInteger b && b.bitLength() < 32) {
            return b.intValue();
        }
        return null;
    }
}
