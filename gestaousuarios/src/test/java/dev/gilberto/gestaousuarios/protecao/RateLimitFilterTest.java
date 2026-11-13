package dev.gilberto.gestaousuarios.protecao;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import dev.gilberto.gestaousuarios.shared.exceptions.ErroResponseWriter;
import dev.gilberto.gestaousuarios.shared.util.ClienteIpResolver;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import dev.gilberto.gestaousuarios.testsupport.RelogioFalso;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class RateLimitFilterTest {

    private final JsonMapper mapper = JsonMapper.builder().build();
    private RelogioFalso relogio;
    private RateLimitFilter filtro;

    @BeforeEach
    void setUp() {
        relogio = new RelogioFalso();
        RateLimitService service = new RateLimitService(new RateLimitProperties(2, Duration.ofSeconds(60)), relogio);
        filtro = new RateLimitFilter(service, new ClienteIpResolver(), new ErroResponseWriter(mapper));
    }

    private MockFilterChain executar(String metodo, String uri, MockHttpServletResponse resp) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest(metodo, uri);
        MockFilterChain chain = new MockFilterChain();
        filtro.doFilter(req, resp, chain);
        return chain;
    }

    @Test
    void excedenteRecebe429ComRetryAfterEErroResponseJson() throws Exception {
        for (int i = 0; i < 2; i++) {
            MockHttpServletResponse ok = new MockHttpServletResponse();
            MockFilterChain chain = executar("POST", "/v1/auth/login", ok);
            assertThat(chain.getRequest()).isNotNull();
            assertThat(ok.getStatus()).isEqualTo(200);
        }
        relogio.avancar(Duration.ofMillis(10_500));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = executar("POST", "/v1/auth/login", resp);

        assertThat(chain.getRequest()).isNull(); // cadeia não continuou
        assertThat(resp.getStatus()).isEqualTo(429);
        assertThat(resp.getHeader("Retry-After")).isEqualTo("50"); // 49,5 s arredondado para cima
        assertThat(resp.getContentType()).startsWith("application/json");
        JsonNode corpo = mapper.readTree(resp.getContentAsString());
        assertThat(corpo.get("status").asInt()).isEqualTo(429);
        assertThat(corpo.get("mensagem").asString()).isEqualTo(Mensagens.get("ratelimit.excedido"));
        assertThat(corpo.get("path").asString()).isEqualTo("/v1/auth/login");
    }

    @Test
    void refreshTambemELimitadoEContaNoMesmoIp() throws Exception {
        executar("POST", "/v1/auth/login", new MockHttpServletResponse());
        executar("POST", "/v1/auth/refresh", new MockHttpServletResponse());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        executar("POST", "/v1/auth/refresh", resp);
        assertThat(resp.getStatus()).isEqualTo(429);
        assertThat(resp.getHeader("Retry-After")).isEqualTo("60");
    }

    @Test
    void outrosMetodosECaminhosNaoSaoLimitadosNemContados() throws Exception {
        for (int i = 0; i < 10; i++) {
            for (String[] c : new String[][] { { "GET", "/v1/auth/login" }, { "POST", "/v1/usuarios" },
                    { "POST", "/v1/auth/logout" }, { "GET", "/v1/usuarios" } }) {
                MockHttpServletResponse resp = new MockHttpServletResponse();
                MockFilterChain chain = executar(c[0], c[1], resp);
                assertThat(chain.getRequest()).as("%s %s", c[0], c[1]).isNotNull();
                assertThat(resp.getStatus()).isEqualTo(200);
            }
        }
        // nada foi consumido do limite
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = executar("POST", "/v1/auth/login", resp);
        assertThat(chain.getRequest()).isNotNull();
    }
}
