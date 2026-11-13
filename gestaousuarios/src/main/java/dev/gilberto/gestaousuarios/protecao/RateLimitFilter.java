package dev.gilberto.gestaousuarios.protecao;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import dev.gilberto.gestaousuarios.shared.exceptions.ErroResponseWriter;
import dev.gilberto.gestaousuarios.shared.util.ClienteIpResolver;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Aplica o limite por IP em {@code POST /v1/auth/login} e {@code POST /v1/auth/refresh}.
 * Não é {@code @Component}: é criado na SecurityConfig para não ser registrado também
 * como filtro de servlet (rodaria duas vezes).
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private final RateLimitService rateLimitService;
    private final ClienteIpResolver ipResolver;
    private final ErroResponseWriter writer;

    public RateLimitFilter(RateLimitService rateLimitService, ClienteIpResolver ipResolver,
                           ErroResponseWriter writer) {
        this.rateLimitService = rateLimitService;
        this.ipResolver = ipResolver;
        this.writer = writer;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !("/v1/auth/login".equals(path) || "/v1/auth/refresh".equals(path));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String ip = ipResolver.resolver(request);
        Optional<Duration> retryAfter = rateLimitService.registrar(ip);
        if (retryAfter.isPresent()) {
            log.warn("Limite de requisições excedido para o IP {} em {}", ip, request.getRequestURI());
            writer.escrever(response, 429, "ratelimit.excedido", request.getRequestURI(), retryAfter.get());
            return;
        }
        chain.doFilter(request, response);
    }
}
