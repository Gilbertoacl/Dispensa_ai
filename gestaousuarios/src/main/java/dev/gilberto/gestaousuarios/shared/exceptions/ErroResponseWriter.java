package dev.gilberto.gestaousuarios.shared.exceptions;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;

import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.ObjectMapper;

/**
 * Escreve um {@link ErroResponse} diretamente na resposta HTTP, para uso em filtros e entry
 * points, onde o {@code GlobalExceptionHandler} não atua. (R15.1, R15.6)
 */
@Component
public class ErroResponseWriter {

    private final ObjectMapper objectMapper;

    public ErroResponseWriter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /** Escreve o erro; se {@code retryAfter} não for nulo, inclui {@code Retry-After} em segundos (mínimo 1). */
    public void escrever(HttpServletResponse response, int status, String chave, String path,
                         Duration retryAfter) throws IOException {
        Map<String, String> cabecalhos = retryAfter == null
                ? Map.of()
                : Map.of(HttpHeaders.RETRY_AFTER, String.valueOf(segundos(retryAfter)));
        escrever(response, status, chave, path, cabecalhos);
    }

    /** Escreve o erro com cabeçalhos opcionais (pode ser nulo ou vazio). */
    public void escrever(HttpServletResponse response, int status, String chave, String path,
                         Map<String, String> cabecalhos) throws IOException {
        HttpStatus httpStatus = HttpStatus.valueOf(status);
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        if (cabecalhos != null) {
            cabecalhos.forEach(response::setHeader);
        }
        objectMapper.writeValue(response.getWriter(),
                ErroResponse.of(httpStatus, Mensagens.get(chave), path));
    }

    /** {@code max(1, ceil(segundos))}. */
    static long segundos(Duration d) {
        long s = d.getSeconds() + (d.getNano() > 0 ? 1 : 0);
        return Math.max(1, s);
    }
}
