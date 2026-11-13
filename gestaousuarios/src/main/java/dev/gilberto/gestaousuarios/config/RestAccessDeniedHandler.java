package dev.gilberto.gestaousuarios.config;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import dev.gilberto.gestaousuarios.shared.exceptions.ErroResponseWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Manipulador de acesso negado da cadeia de filtros: usuário autenticado sem autorização
 * recebe 403 com o contrato {@code ErroResponse}, escrito via {@link ErroResponseWriter}.
 */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final ErroResponseWriter writer;

    public RestAccessDeniedHandler(ErroResponseWriter writer) {
        this.writer = writer;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        writer.escrever(response, HttpStatus.FORBIDDEN.value(), "user.access.denied",
                request.getRequestURI(), (Map<String, String>) null);
    }
}
