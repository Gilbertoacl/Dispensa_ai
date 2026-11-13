package dev.gilberto.gestaousuarios.integration;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import dev.gilberto.gestaousuarios.protecao.RateLimitProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT 16.6: limite de taxa por IP em {@code POST /v1/auth/login} e {@code POST /v1/auth/refresh}.
 *
 * <p>Contexto separado de propósito (max-requests = 3). O override é um bean {@code @Primary} de
 * {@link RateLimitProperties}: {@code @TestPropertySource} perde para o
 * {@code @DynamicPropertySource} do {@link AbstractPostgresIT} (max-requests = 10000), e um
 * {@code @DynamicPropertySource} na subclasse não prevaleceu sobre o da superclasse.
 * Cada teste usa um IP próprio ({@code setRemoteAddr}) e a janela é de 1 hora para a contagem
 * não ser zerada no meio do teste.
 */
@SpringBootTest
@AutoConfigureMockMvc
class RateLimitIT extends AbstractPostgresIT {

    private static final int MAXIMO = 3;

    @TestConfiguration
    static class LimiteBaixo {
        @Bean
        @Primary
        RateLimitProperties rateLimitPropertiesDeTeste() {
            return new RateLimitProperties(MAXIMO, Duration.ofHours(1));
        }
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    private static String ipUnico() {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        return "10." + r.nextInt(1, 255) + "." + r.nextInt(1, 255) + "." + r.nextInt(1, 255);
    }

    private ResultActions login(String ip) throws Exception {
        String corpo = objectMapper.writeValueAsString(Map.of(
                "email", "rl." + UUID.randomUUID() + "@dispensa.ai", "senha", "Inexistente#" + UUID.randomUUID()));
        return mockMvc.perform(post("/v1/auth/login").with(r -> {
            r.setRemoteAddr(ip);
            return r;
        }).contentType(MediaType.APPLICATION_JSON).content(corpo));
    }

    private ResultActions refresh(String ip) throws Exception {
        String corpo = objectMapper.writeValueAsString(Map.of("refreshToken", "desconhecido-" + UUID.randomUUID()));
        return mockMvc.perform(post("/v1/auth/refresh").with(r -> {
            r.setRemoteAddr(ip);
            return r;
        }).contentType(MediaType.APPLICATION_JSON).content(corpo));
    }

    private void exigirExcedido(ResultActions acao) throws Exception {
        MvcResult r = acao.andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("ratelimit.excedido")))
                .andReturn();
        String retry = r.getResponse().getHeader("Retry-After");
        assertThat(retry).isNotNull();
        assertThat(Long.parseLong(retry)).isPositive().isLessThanOrEqualTo(3600L);
    }

    @Test
    void requisicaoAlemDoMaximoNoLoginRecebe429ComRetryAfter() throws Exception {
        String ip = ipUnico();
        for (int i = 0; i < MAXIMO; i++) {
            login(ip).andExpect(status().isUnauthorized());
        }
        exigirExcedido(login(ip));
        exigirExcedido(login(ip));
    }

    @Test
    void refreshCompartilhaOLimiteComOLogin() throws Exception {
        String ip = ipUnico();
        login(ip).andExpect(status().isUnauthorized());
        login(ip).andExpect(status().isUnauthorized());
        refresh(ip).andExpect(status().isUnauthorized()); // 3ª requisição do IP, ainda permitida

        exigirExcedido(login(ip));
        exigirExcedido(refresh(ip));
    }

    @Test
    void limiteEPorIpEOutrosEndpointsNaoSaoLimitados() throws Exception {
        String ip = ipUnico();
        for (int i = 0; i < MAXIMO; i++) {
            login(ip).andExpect(status().isUnauthorized());
        }
        exigirExcedido(login(ip));

        // Outro IP não é afetado.
        login(ipUnico()).andExpect(status().isUnauthorized());

        // Com o IP esgotado, outros endpoints continuam respondendo normalmente (sem 429).
        AuthFlowHelper f = new AuthFlowHelper(mockMvc, objectMapper);
        for (int i = 0; i < MAXIMO + 2; i++) {
            mockMvc.perform(get("/v1/me").with(r -> {
                r.setRemoteAddr(ip);
                return r;
            })).andExpect(status().isUnauthorized());
        }
        for (int i = 0; i < 2; i++) {
            String c = f.json(Map.of("email", AuthFlowHelper.emailUnico("rl"), "nome", "Sem Limite",
                    "senha", AuthFlowHelper.senhaUnica()));
            mockMvc.perform(post("/v1/usuarios").with(r -> {
                r.setRemoteAddr(ip);
                return r;
            }).contentType(MediaType.APPLICATION_JSON).content(c)).andExpect(status().isCreated());
        }
    }
}
