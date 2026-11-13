package dev.gilberto.gestaousuarios.shared.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Resolve o IP do cliente a partir de {@code getRemoteAddr()}, sempre.
 * A confiança em X-Forwarded-For fica a cargo do Spring Boot
 * ({@code server.forward-headers-strategy}, desligado por padrão).
 */
@Component
public class ClienteIpResolver {

    public String resolver(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
