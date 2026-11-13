package dev.gilberto.gestaousuarios.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import dev.gilberto.gestaousuarios.shared.exceptions.ErroResponseWriter;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class RestAuthenticationEntryPointTest {

    private final JsonMapper mapper = JsonMapper.builder().build();
    private RestAuthenticationEntryPoint entryPoint;
    private RestAccessDeniedHandler deniedHandler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        ErroResponseWriter writer = new ErroResponseWriter(mapper);
        entryPoint = new RestAuthenticationEntryPoint(writer);
        deniedHandler = new RestAccessDeniedHandler(writer);
        request = new MockHttpServletRequest("GET", "/v1/usuarios/x");
        response = new MockHttpServletResponse();
    }

    private JsonNode corpo() throws Exception {
        return mapper.readTree(response.getContentAsString());
    }

    private void assert401(String chave) throws Exception {
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith("application/json");
        JsonNode n = corpo();
        assertThat(n.get("status").asInt()).isEqualTo(401);
        assertThat(n.get("erro").asString()).isEqualTo("Unauthorized");
        assertThat(n.get("mensagem").asString()).isEqualTo(Mensagens.get(chave));
        assertThat(n.get("path").asString()).isEqualTo("/v1/usuarios/x");
        assertThat(n.has("timestamp")).isTrue();
    }

    @Test
    void jwtValidationExceptionComTokenRevogadoGeraTokenRevogado() throws Exception {
        JwtValidationException cause = new JwtValidationException("x",
                List.of(new OAuth2Error("invalid_token", "token_revogado", null)));
        entryPoint.commence(request, response, new InvalidBearerTokenException("x", cause));
        assert401("token.revogado");
    }

    @Test
    void causaComJwtExpiredGeraTokenExpirado() throws Exception {
        AuthenticationException ex = new InvalidBearerTokenException("x",
                new BadJwtException("Jwt expired at 2026-01-01T00:00:00Z"));
        entryPoint.commence(request, response, ex);
        assert401("token.expirado");
    }

    @Test
    void jwtValidationExceptionComMensagemJwtExpiredGeraTokenExpirado() throws Exception {
        JwtValidationException cause = new JwtValidationException("Jwt expired at x",
                List.of(new OAuth2Error("invalid_token", "Jwt expired at x", null)));
        entryPoint.commence(request, response, new InvalidBearerTokenException("x", cause));
        assert401("token.expirado");
    }

    @Test
    void demaisCausasGeramCredenciaisInvalidas() throws Exception {
        entryPoint.commence(request, response, new BadCredentialsException("ruim"));
        assert401("user.invalid.credentials");

        response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new OAuth2AuthenticationException("invalid_token"));
        assert401("user.invalid.credentials");

        response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new InvalidBearerTokenException("x",
                new BadJwtException("Signed JWT rejected: Invalid signature")));
        assert401("user.invalid.credentials");
    }

    @Test
    void accessDeniedHandlerResponde403() throws Exception {
        deniedHandler.handle(request, response, new AccessDeniedException("nope"));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).startsWith("application/json");
        JsonNode n = corpo();
        assertThat(n.get("status").asInt()).isEqualTo(403);
        assertThat(n.get("erro").asString()).isEqualTo("Forbidden");
        assertThat(n.get("mensagem").asString()).isEqualTo(Mensagens.get("user.access.denied"));
        assertThat(n.get("path").asString()).isEqualTo("/v1/usuarios/x");
    }
}
