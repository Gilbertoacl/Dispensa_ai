package dev.gilberto.gestaousuarios.config;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import dev.gilberto.gestaousuarios.auth.TokenVersionValidator;
import dev.gilberto.gestaousuarios.shared.exceptions.ErroResponseWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Ponto de entrada de autenticação: responde 401 com {@code ErroResponse}. Escolhe
 * {@code token.revogado} quando a causa é a falha do validador de {@code tv}
 * (descrição {@code token_revogado}); {@code token.expirado} quando o JWT está expirado;
 * caso contrário {@code user.invalid.credentials}.
 */
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ErroResponseWriter writer;

    public RestAuthenticationEntryPoint(ErroResponseWriter writer) {
        this.writer = writer;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        writer.escrever(response, HttpStatus.UNAUTHORIZED.value(), escolherChave(authException),
                request.getRequestURI(), (Map<String, String>) null);
    }

    static String escolherChave(Throwable erro) {
        for (Throwable t = erro; t != null; t = (t.getCause() == t ? null : t.getCause())) {
            if (t instanceof JwtValidationException jve) {
                for (OAuth2Error e : jve.getErrors()) {
                    if (TokenVersionValidator.DESCRICAO_REVOGADO.equals(e.getDescription())) {
                        return "token.revogado";
                    }
                }
            }
            String msg = t.getMessage();
            if (msg != null && msg.contains("Jwt expired")) {
                return "token.expirado";
            }
        }
        return "user.invalid.credentials";
    }
}
