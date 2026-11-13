package dev.gilberto.gestaousuarios.auth;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import dev.gilberto.gestaousuarios.config.JwtProperties;
import dev.gilberto.gestaousuarios.config.JwtSecretValidator;
import dev.gilberto.gestaousuarios.config.RestAccessDeniedHandler;
import dev.gilberto.gestaousuarios.config.RestAuthenticationEntryPoint;
import dev.gilberto.gestaousuarios.config.SecurityConfig;
import dev.gilberto.gestaousuarios.protecao.RateLimitService;
import dev.gilberto.gestaousuarios.shared.exceptions.ErroResponseWriter;
import dev.gilberto.gestaousuarios.shared.exceptions.LimiteExcedidoException;
import dev.gilberto.gestaousuarios.shared.exceptions.TokenInvalidoException;
import dev.gilberto.gestaousuarios.shared.exceptions.TokenReutilizadoException;
import dev.gilberto.gestaousuarios.shared.util.ClienteIpResolver;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import tools.jackson.databind.ObjectMapper;

/**
 * Slice WebMvc de {@link AuthController} com a {@link SecurityConfig} real. Cobre login, refresh,
 * logout e logout-all: status, corpo, {@code Retry-After} e a publicidade das rotas
 * (R2.6-2.8, 3.2, 4.3, 4.5, 9.4, 10.2, 19.3).
 */
@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, RestAuthenticationEntryPoint.class, RestAccessDeniedHandler.class,
        ErroResponseWriter.class, ClienteIpResolver.class, JwtSecretValidator.class})
@EnableConfigurationProperties(JwtProperties.class)
@TestPropertySource(properties = "dispensaai.security.jwt.secret=0123456789-0123456789-0123456789-xx")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private SessaoService sessaoService;

    @MockitoBean
    private TokenVersionValidator tokenVersionValidator;

    /** Mock devolve {@code Optional.empty()} por padrão (requisição permitida). */
    @MockitoBean
    private RateLimitService rateLimitService;

    private static TokenResponse tokens() {
        return new TokenResponse("acesso.jwt.valor", "refresh-opaco-valor", "Bearer", 900L, 604800L);
    }

    private String json(Object o) throws Exception {
        return objectMapper.writeValueAsString(o);
    }

    private org.springframework.test.web.servlet.ResultActions postJson(String uri, String corpo) throws Exception {
        return mockMvc.perform(post(uri).contentType(MediaType.APPLICATION_JSON).content(corpo));
    }

    // ---------------------------------------------------------------- login

    @Test
    void loginDeveRetornar200ComCorpoCompleto() throws Exception {
        when(authService.autenticar(any(LoginRequest.class), any(ContextoCliente.class))).thenReturn(tokens());

        postJson("/v1/auth/login", json(Map.of("email", "mail@mail.com", "senha", "Dispensa#2024")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("acesso.jwt.valor"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-opaco-valor"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiraEm").value(900))
                .andExpect(jsonPath("$.refreshExpiraEm").value(604800));
    }

    @Test
    void loginComCamposEmBrancoDeveRetornar400ComCamposComErro() throws Exception {
        postJson("/v1/auth/login", json(Map.of("email", "", "senha", "")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("validation.error")))
                .andExpect(jsonPath("$.camposComErro", hasSize(2)))
                .andExpect(jsonPath("$.camposComErro[*].campo", containsInAnyOrder("email", "senha")));
        verifyNoInteractions(authService);
    }

    @Test
    void loginComCredenciaisInvalidasDeveRetornar401() throws Exception {
        when(authService.autenticar(any(LoginRequest.class), any(ContextoCliente.class)))
                .thenThrow(new BadCredentialsException("x"));

        postJson("/v1/auth/login", json(Map.of("email", "mail@mail.com", "senha", "errada")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("user.invalid.credentials")));
    }

    @Test
    void loginBloqueadoDeveRetornar429ComRetryAfter() throws Exception {
        when(authService.autenticar(any(LoginRequest.class), any(ContextoCliente.class)))
                .thenThrow(new LimiteExcedidoException("login.bloqueado", Duration.ofSeconds(30)));

        postJson("/v1/auth/login", json(Map.of("email", "mail@mail.com", "senha", "Dispensa#2024")))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "30"))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("login.bloqueado")));
    }

    @Test
    void loginComLimiteDeIpExcedidoDeveRetornar429ComRetryAfterSemChamarServico() throws Exception {
        when(rateLimitService.registrar(any())).thenReturn(Optional.of(Duration.ofMillis(1500)));

        postJson("/v1/auth/login", json(Map.of("email", "mail@mail.com", "senha", "Dispensa#2024")))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "2"))
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("ratelimit.excedido")));
        verifyNoInteractions(authService);
    }

    @Test
    void loginNaoExigeBearerEIgnoraAuthorizationInvalido() throws Exception {
        when(authService.autenticar(any(LoginRequest.class), any(ContextoCliente.class))).thenReturn(tokens());

        mockMvc.perform(post("/v1/auth/login")
                        .header("Authorization", "Bearer token-expirado-ou-lixo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", "mail@mail.com", "senha", "Dispensa#2024"))))
                .andExpect(status().isOk());
    }

    // -------------------------------------------------------------- refresh

    @Test
    void refreshDeveRetornar200ComNovoPar() throws Exception {
        when(sessaoService.renovar(eq("refresh-antigo"), any(ContextoCliente.class))).thenReturn(tokens());

        mockMvc.perform(post("/v1/auth/refresh")
                        .header("Authorization", "Bearer access-expirado")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("refreshToken", "refresh-antigo"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("acesso.jwt.valor"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-opaco-valor"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void refreshComObjetoVazioDeveRetornar400RefreshObrigatorio() throws Exception {
        assertRefreshObrigatorio(postJson("/v1/auth/refresh", "{}"));
    }

    @Test
    void refreshComTokenEmBrancoDeveRetornar400RefreshObrigatorio() throws Exception {
        assertRefreshObrigatorio(postJson("/v1/auth/refresh", json(Map.of("refreshToken", "   "))));
    }

    @Test
    void refreshSemCorpoDeveRetornar400RefreshObrigatorio() throws Exception {
        assertRefreshObrigatorio(mockMvc.perform(post("/v1/auth/refresh")));
    }

    private void assertRefreshObrigatorio(org.springframework.test.web.servlet.ResultActions r) throws Exception {
        r.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("refresh.obrigatorio")))
                .andExpect(jsonPath("$.camposComErro", hasSize(1)))
                .andExpect(jsonPath("$.camposComErro[0].campo").value("refreshToken"))
                .andExpect(jsonPath("$.camposComErro[0].mensagem").value(Mensagens.get("refresh.obrigatorio")));
        verifyNoInteractions(sessaoService);
    }

    @Test
    void refreshInvalidoDeveRetornar401() throws Exception {
        assertRefresh401("refresh.invalido", new TokenInvalidoException("refresh.invalido"));
    }

    @Test
    void refreshExpiradoDeveRetornar401() throws Exception {
        assertRefresh401("refresh.expirado", new TokenInvalidoException("refresh.expirado"));
    }

    @Test
    void refreshReutilizadoDeveRetornar401() throws Exception {
        assertRefresh401("refresh.reutilizado", new TokenReutilizadoException());
    }

    private void assertRefresh401(String chave, RuntimeException erro) throws Exception {
        when(sessaoService.renovar(any(), any(ContextoCliente.class))).thenThrow(erro);

        postJson("/v1/auth/refresh", json(Map.of("refreshToken", "qualquer")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get(chave)));
    }

    @Test
    void refreshComLimiteDeIpExcedidoDeveRetornar429() throws Exception {
        when(rateLimitService.registrar(any())).thenReturn(Optional.of(Duration.ofSeconds(10)));

        postJson("/v1/auth/refresh", json(Map.of("refreshToken", "x")))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "10"));
        verifyNoInteractions(sessaoService);
    }

    @Test
    void refreshComServicoLimitandoDeveRetornar429ComRetryAfter() throws Exception {
        when(sessaoService.renovar(any(), any(ContextoCliente.class)))
                .thenThrow(new LimiteExcedidoException("ratelimit.excedido", Duration.ofSeconds(5)));

        postJson("/v1/auth/refresh", json(Map.of("refreshToken", "x")))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "5"));
    }

    // --------------------------------------------------------------- logout

    @Test
    void logoutDeveRetornar204SemCorpo() throws Exception {
        postJson("/v1/auth/logout", json(Map.of("refreshToken", "refresh-atual")))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));
        verify(sessaoService).encerrar("refresh-atual");
    }

    @Test
    void logoutComTokenDesconhecidoDeveRetornar204() throws Exception {
        // O serviço é idempotente: token desconhecido não lança exceção.
        postJson("/v1/auth/logout", json(Map.of("refreshToken", "desconhecido")))
                .andExpect(status().isNoContent());
        verify(sessaoService).encerrar("desconhecido");
    }

    @Test
    void logoutComBearerInvalidoAindaRetorna204() throws Exception {
        mockMvc.perform(post("/v1/auth/logout")
                        .header("Authorization", "Bearer lixo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("refreshToken", "x"))))
                .andExpect(status().isNoContent());
    }

    @Test
    void logoutSemCorpoDeveRetornar400() throws Exception {
        mockMvc.perform(post("/v1/auth/logout"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("refresh.obrigatorio")))
                .andExpect(jsonPath("$.camposComErro[0].campo").value("refreshToken"));
        verify(sessaoService, never()).encerrar(any());
    }

    @Test
    void logoutComTokenEmBrancoDeveRetornar400() throws Exception {
        postJson("/v1/auth/logout", json(Map.of("refreshToken", "")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("refresh.obrigatorio")));
        verify(sessaoService, never()).encerrar(any());
    }

    // ----------------------------------------------------------- logout-all

    @Test
    void logoutAllAutenticadoDeveRetornar204() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(post("/v1/auth/logout-all")
                        .with(jwt().jwt(j -> j.subject(id.toString()).claim("perfil", "USER"))
                                .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isNoContent());
        verify(sessaoService).encerrarTodas(id);
    }

    @Test
    void logoutAllSemTokenDeveRetornar401() throws Exception {
        mockMvc.perform(post("/v1/auth/logout-all"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
        verifyNoInteractions(sessaoService);
    }
}
