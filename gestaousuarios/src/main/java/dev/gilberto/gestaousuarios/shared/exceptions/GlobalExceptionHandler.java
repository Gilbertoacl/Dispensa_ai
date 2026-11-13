package dev.gilberto.gestaousuarios.shared.exceptions;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Duration;
import java.util.List;

/**
 * Converte exceções em respostas {@link ErroResponse} padronizadas, com status HTTP
 * semanticamente correto e mensagens via {@link Mensagens} (i18n).
 *
 * <p>Regras de log (R11.1/R15): falhas de negócio esperadas (400/401/403/404/409) são
 * registradas em nível WARN; falhas inesperadas (500) em nível ERROR. Nenhum handler
 * registra senha, hash de senha ou qualquer PII — apenas o path e o tipo da exceção.</p>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Falha de validação de entrada (@Valid). Preenche {@code camposComErro} com o par
     * campo/mensagem de cada violação. (R3.5, R11.2)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErroResponse> handleValidacao(MethodArgumentNotValidException ex,
                                                        HttpServletRequest request) {
        List<ErroResponse.CampoErro> campos = ex.getBindingResult().getFieldErrors().stream()
                .map(fieldError -> new ErroResponse.CampoErro(fieldError.getField(), fieldError.getDefaultMessage()))
                .toList();

        LOGGER.warn("Validação de entrada falhou em [{}]: {} campo(s) inválido(s)",
                request.getRequestURI(), campos.size());

        ErroResponse erro = ErroResponse.of(
                HttpStatus.BAD_REQUEST, Mensagens.get("validation.error"), request.getRequestURI(), campos);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(erro);
    }

    /**
     * Falha de autenticação. (R11.3)
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErroResponse> handleAutenticacao(AuthenticationException ex,
                                                           HttpServletRequest request) {
        LOGGER.warn("Falha de autenticação em [{}]: {}", request.getRequestURI(), ex.getClass().getSimpleName());
        ErroResponse erro = ErroResponse.of(
                HttpStatus.UNAUTHORIZED, Mensagens.get("user.invalid.credentials"), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(erro);
    }

    /**
     * Falha de autorização. Rede de segurança para exceções que cheguem ao advice;
     * o fluxo padrão é tratado pelo AccessDeniedHandler da cadeia de filtros. (R11.4)
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErroResponse> handleAcessoNegado(AccessDeniedException ex,
                                                          HttpServletRequest request) {
        LOGGER.warn("Acesso negado em [{}]: {}", request.getRequestURI(), ex.getClass().getSimpleName());
        ErroResponse erro = ErroResponse.of(
                HttpStatus.FORBIDDEN, Mensagens.get("user.access.denied"), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(erro);
    }

    /**
     * Recurso não encontrado. A mensagem já vem resolvida na exceção. (R11.5)
     */
    @ExceptionHandler(RecursoNaoEncontradoException.class)
    public ResponseEntity<ErroResponse> handleRecursoNaoEncontrado(RecursoNaoEncontradoException ex,
                                                                   HttpServletRequest request) {
        LOGGER.warn("Recurso não encontrado em [{}]: {}", request.getRequestURI(), ex.getMessage());
        ErroResponse erro = ErroResponse.of(
                HttpStatus.NOT_FOUND, ex.getMessage(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(erro);
    }

    /**
     * Conflito de estado (ex.: email já registrado). A mensagem já vem resolvida na
     * exceção. (R11.6, R11.8)
     */
    @ExceptionHandler(ConflitoException.class)
    public ResponseEntity<ErroResponse> handleConflito(ConflitoException ex,
                                                       HttpServletRequest request) {
        LOGGER.warn("Conflito de estado em [{}]: {}", request.getRequestURI(), ex.getMessage());
        ErroResponse erro = ErroResponse.of(
                HttpStatus.CONFLICT, ex.getMessage(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(erro);
    }

    /**
     * Violação de regra de negócio (400). Com campo associado, preenche
     * {@code camposComErro}. (R15.2)
     */
    @ExceptionHandler(RegraNegocioException.class)
    public ResponseEntity<ErroResponse> handleRegraNegocio(RegraNegocioException ex,
                                                           HttpServletRequest request) {
        LOGGER.warn("Regra de negócio violada em [{}]: {}", request.getRequestURI(), ex.getChave());
        List<ErroResponse.CampoErro> campos = ex.getCampo() == null
                ? null
                : List.of(new ErroResponse.CampoErro(ex.getCampo(), ex.getMessage()));
        ErroResponse erro = ErroResponse.of(
                HttpStatus.BAD_REQUEST, ex.getMessage(), request.getRequestURI(), campos);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(erro);
    }

    /**
     * Refresh token inválido, expirado ou reutilizado (401). Inclui
     * {@link TokenReutilizadoException}. (R15.2)
     */
    @ExceptionHandler(TokenInvalidoException.class)
    public ResponseEntity<ErroResponse> handleTokenInvalido(TokenInvalidoException ex,
                                                            HttpServletRequest request) {
        LOGGER.warn("Refresh token rejeitado em [{}]: {}", request.getRequestURI(), ex.getClass().getSimpleName());
        ErroResponse erro = ErroResponse.of(
                HttpStatus.UNAUTHORIZED, ex.getMessage(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(erro);
    }

    /**
     * Limite excedido (429) com {@code Retry-After} em segundos inteiros, no mínimo 1. (R15.6)
     */
    @ExceptionHandler(LimiteExcedidoException.class)
    public ResponseEntity<ErroResponse> handleLimiteExcedido(LimiteExcedidoException ex,
                                                             HttpServletRequest request) {
        LOGGER.warn("Limite excedido em [{}]: {}", request.getRequestURI(), ex.getChave());
        Duration espera = ex.getRetryAfter();
        long segundos = espera == null ? 1 : Math.max(1, (espera.toMillis() + 999) / 1000);
        ErroResponse erro = ErroResponse.of(
                HttpStatus.TOO_MANY_REQUESTS, ex.getMessage(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(segundos))
                .body(erro);
    }

    /**
     * Parâmetro de caminho com tipo inválido (ex.: {@code {id}} que não é UUID). (R14.5)
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErroResponse> handleTipoInvalido(MethodArgumentTypeMismatchException ex,
                                                           HttpServletRequest request) {
        LOGGER.warn("Parâmetro com tipo inválido em [{}]: {}", request.getRequestURI(), ex.getName());
        String mensagem = Mensagens.get("id.invalido");
        ErroResponse erro = ErroResponse.of(HttpStatus.BAD_REQUEST, mensagem, request.getRequestURI(),
                List.of(new ErroResponse.CampoErro("id", mensagem)));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(erro);
    }

    /**
     * Corpo JSON ausente ou malformado (400).
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErroResponse> handleCorpoIlegivel(HttpMessageNotReadableException ex,
                                                            HttpServletRequest request) {
        LOGGER.warn("Corpo da requisição ilegível em [{}]", request.getRequestURI());
        ErroResponse erro = ErroResponse.of(
                HttpStatus.BAD_REQUEST, Mensagens.get("validation.error"), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(erro);
    }

    /**
     * {@link IllegalArgumentException} não é mais erro de negócio: indica bug e responde 500
     * sem expor detalhes, com stack em ERROR. (R15.4, R15.5)
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErroResponse> handleArgumentoInvalido(IllegalArgumentException ex,
                                                               HttpServletRequest request) {
        LOGGER.error("Argumento inválido inesperado em [{}]: {}",
                request.getRequestURI(), ex.getClass().getName(), ex);
        ErroResponse erro = ErroResponse.of(
                HttpStatus.INTERNAL_SERVER_ERROR, Mensagens.get("server.error"), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(erro);
    }

    /**
     * Fallback para exceções inesperadas. Loga a stack em nível ERROR, mas NÃO expõe
     * detalhes internos nem PII na resposta. (R11.7)
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErroResponse> handleGenerico(Exception ex, HttpServletRequest request) {
        LOGGER.error("Erro inesperado em [{}]: {}", request.getRequestURI(), ex.getClass().getName(), ex);
        ErroResponse erro = ErroResponse.of(
                HttpStatus.INTERNAL_SERVER_ERROR, Mensagens.get("server.error"), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(erro);
    }

}
