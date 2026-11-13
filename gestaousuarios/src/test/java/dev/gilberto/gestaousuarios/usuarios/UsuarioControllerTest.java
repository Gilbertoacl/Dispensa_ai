package dev.gilberto.gestaousuarios.usuarios;

import dev.gilberto.gestaousuarios.config.RestAccessDeniedHandler;
import dev.gilberto.gestaousuarios.config.RestAuthenticationEntryPoint;
import dev.gilberto.gestaousuarios.auth.TokenVersionValidator;
import dev.gilberto.gestaousuarios.config.JwtProperties;
import dev.gilberto.gestaousuarios.config.JwtSecretValidator;
import dev.gilberto.gestaousuarios.config.SecurityConfig;
import dev.gilberto.gestaousuarios.shared.exceptions.ErroResponseWriter;
import dev.gilberto.gestaousuarios.shared.util.ClienteIpResolver;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.UsuarioController;
import dev.gilberto.gestaousuarios.usuario.UsuarioRequest;
import dev.gilberto.gestaousuarios.usuario.UsuarioResponse;
import dev.gilberto.gestaousuarios.usuario.UsuarioService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import dev.gilberto.gestaousuarios.shared.exceptions.ConflitoException;
import dev.gilberto.gestaousuarios.shared.exceptions.RecursoNaoEncontradoException;
import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Testes de slice WebMvc para {@link UsuarioController}, cobrindo a nova API {@code /v1} e a
 * integração com Spring Security.
 *
 * <p><strong>Abordagem de segurança escolhida.</strong> O teste importa explicitamente
 * {@link SecurityConfig}, {@link RestAuthenticationEntryPoint} e {@link RestAccessDeniedHandler}
 * via {@link Import}. Isso garante que a {@code SecurityFilterChain} real seja usada no slice,
 * ativando o {@code @EnableMethodSecurity} (necessário para os {@code @PreAuthorize} do
 * controller) e os handlers de 401/403. Como {@code SecurityConfig} injeta o segredo
 * {@code dispensaai.security.jwt.secret} para construir {@code JwtEncoder}/{@code JwtDecoder},
 * a property é fornecida via {@link TestPropertySource} com um valor de pelo menos 32 bytes.
 *
 * <p>A autenticação é simulada com o post-processor {@code jwt()} do spring-security-test, que
 * injeta diretamente um token de autenticação já validado (sem exercer o {@code JwtDecoder}).
 * O {@code subject} do JWT é sempre um UUID válido, pois o controller executa
 * {@code UUID.fromString(jwt.getSubject())}. Requisições sem {@code jwt()} exercem o fluxo real
 * de 401; requisições com perfil insuficiente exercem o fluxo real de 403.
 *
 * <p>O {@code jwt()} não passa pelo {@code JwtDecoder}; por isso a claim {@code tv} não é
 * validada aqui e o {@code TokenVersionValidator} é um mock.
 */
@WebMvcTest(UsuarioController.class)
@Import({SecurityConfig.class, RestAuthenticationEntryPoint.class, RestAccessDeniedHandler.class,
        ErroResponseWriter.class, ClienteIpResolver.class, JwtSecretValidator.class})
@EnableConfigurationProperties(JwtProperties.class)
@TestPropertySource(properties = "dispensaai.security.jwt.secret=0123456789-0123456789-0123456789-xx")
class UsuarioControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private TokenVersionValidator tokenVersionValidator;

    /** Mock devolve {@code Optional.empty()} por padrão (requisição permitida). */
    @MockitoBean
    private dev.gilberto.gestaousuarios.protecao.RateLimitService rateLimitService;

    @MockitoBean
    private UsuarioService usuarioService;

    private UsuarioRequest requestValido() {
        return new UsuarioRequest("mail@mail.com", "João das Neves", "Dispensa#2024");
    }

    private UsuarioResponse responseValido() {
        return new UsuarioResponse(UUID.randomUUID(), "mail@mail.com", "João das Neves", Perfil.USER, Instant.now());
    }

    // 1. POST /v1/usuarios (público) → 201 (R1.1)
    @Test
    void deveCriarUsuarioERetornar201() throws Exception {
        UsuarioRequest request = requestValido();
        when(usuarioService.criarUsuario(any(UsuarioRequest.class)))
                .thenReturn(responseValido());

        mockMvc.perform(post("/v1/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(request.email()))
                .andExpect(jsonPath("$.nome").value(request.nome()))
                .andExpect(jsonPath("$.perfil").value(Perfil.USER.name()));
    }

    // 2. POST /v1/usuarios com email inválido → 400 (R3.2)
    @Test
    void deveRetornar400AoCriarComEmailInvalido() throws Exception {
        UsuarioRequest request = new UsuarioRequest("emailinvalido", "João das Neves", "Dispensa#2024");

        mockMvc.perform(post("/v1/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    // 3. POST /v1/usuarios com senha curta (<8) → 400 (R2.5/R3)
    @Test
    void deveRetornar400AoCriarComSenhaCurta() throws Exception {
        UsuarioRequest request = new UsuarioRequest("mail@mail.com", "João das Neves", "1234567");

        mockMvc.perform(post("/v1/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    // 4. GET /v1/me autenticado → 200 (R5.2)
    @Test
    void deveRetornarUsuarioAutenticadoEm_me() throws Exception {
        String id = UUID.randomUUID().toString();
        when(usuarioService.buscarPorId(any(UUID.class)))
                .thenReturn(responseValido());

        mockMvc.perform(get("/v1/me")
                        .with(jwt().jwt(j -> j.subject(id).claim("perfil", "USER"))
                                .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("mail@mail.com"));
    }

    // 5. GET /v1/me sem token → 401 (R5.3)
    @Test
    void deveRetornar401EmMeSemToken() throws Exception {
        mockMvc.perform(get("/v1/me"))
                .andExpect(status().isUnauthorized());
    }

    // 6. GET /v1/usuarios como ADMIN → 200 (R6.4, R7.1)
    @Test
    void deveListarUsuariosComoAdmin() throws Exception {
        String id = UUID.randomUUID().toString();
        Page<UsuarioResponse> page = new PageImpl<>(List.of());
        when(usuarioService.listar(any())).thenReturn(page);

        mockMvc.perform(get("/v1/usuarios")
                        .with(jwt().jwt(j -> j.subject(id).claim("perfil", "ADMIN"))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk());
    }

    // 7. GET /v1/usuarios como USER → 403 (R6.5)
    @Test
    void deveNegarListagemParaUser() throws Exception {
        String id = UUID.randomUUID().toString();

        mockMvc.perform(get("/v1/usuarios")
                        .with(jwt().jwt(j -> j.subject(id).claim("perfil", "USER"))
                                .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }

    // 8. DELETE /v1/usuarios/{id} como ADMIN → 204 (R10.1)
    @Test
    void deveExcluirComoAdmin() throws Exception {
        String callerId = UUID.randomUUID().toString();
        UUID alvo = UUID.randomUUID();

        mockMvc.perform(delete("/v1/usuarios/{id}", alvo)
                        .with(jwt().jwt(j -> j.subject(callerId).claim("perfil", "ADMIN"))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNoContent());

        verify(usuarioService).excluir(eq(alvo));
    }

    // 9. DELETE /v1/usuarios/{id} como USER → 403 (R10.3)
    @Test
    void deveNegarExclusaoParaUser() throws Exception {
        String callerId = UUID.randomUUID().toString();
        UUID alvo = UUID.randomUUID();

        mockMvc.perform(delete("/v1/usuarios/{id}", alvo)
                        .with(jwt().jwt(j -> j.subject(callerId).claim("perfil", "USER"))
                                .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }

    // ------------------------------------------------------------------
    // Novos cenários: perfil, consulta por id, cadastro, política de senha
    // ------------------------------------------------------------------

    @Autowired
    private JwtEncoder jwtEncoder;

    private static RequestPostProcessor como(UUID sub, String perfil) {
        return jwt().jwt(j -> j.subject(sub.toString()).claim("perfil", perfil))
                .authorities(new SimpleGrantedAuthority("ROLE_" + perfil));
    }

    private UsuarioResponse responseComId(UUID id, Perfil perfil) {
        return new UsuarioResponse(id, "mail@mail.com", "João das Neves", perfil, Instant.now());
    }

    private static final String CORPO_ADMIN = "{\"perfil\":\"ADMIN\"}";

    @Test
    void adminDeveAlterarPerfilERetornar200() throws Exception {
        UUID executor = UUID.randomUUID();
        UUID alvo = UUID.randomUUID();
        when(usuarioService.alterarPerfil(alvo, Perfil.ADMIN, executor))
                .thenReturn(responseComId(alvo, Perfil.ADMIN));

        mockMvc.perform(put("/v1/usuarios/{id}/perfil", alvo)
                        .with(como(executor, "ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(CORPO_ADMIN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(alvo.toString()))
                .andExpect(jsonPath("$.perfil").value("ADMIN"));
        verify(usuarioService).alterarPerfil(alvo, Perfil.ADMIN, executor);
    }

    @Test
    void userNaoDeveAlterarPerfil403() throws Exception {
        mockMvc.perform(put("/v1/usuarios/{id}/perfil", UUID.randomUUID())
                        .with(como(UUID.randomUUID(), "USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(CORPO_ADMIN))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));
        verifyNoInteractions(usuarioService);
    }

    @Test
    void alterarPerfilSemTokenDeveRetornar401() throws Exception {
        mockMvc.perform(put("/v1/usuarios/{id}/perfil", UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(CORPO_ADMIN))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(usuarioService);
    }

    @Test
    void alterarPerfilComValorInvalidoDeveRetornar400PerfilInvalido() throws Exception {
        for (String corpo : new String[] {"{\"perfil\":\"SUPER\"}", "{\"perfil\":\"\"}", "{}"}) {
            mockMvc.perform(put("/v1/usuarios/{id}/perfil", UUID.randomUUID())
                            .with(como(UUID.randomUUID(), "ADMIN"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(corpo))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.camposComErro[*].campo", hasItem("perfil")))
                    .andExpect(jsonPath("$.camposComErro[*].mensagem", hasItem(Mensagens.get("perfil.invalido"))));
        }
        verifyNoInteractions(usuarioService);
    }

    @Test
    void alterarPerfilComIdInvalidoDeveRetornar400IdInvalido() throws Exception {
        mockMvc.perform(put("/v1/usuarios/{id}/perfil", "abc")
                        .with(como(UUID.randomUUID(), "ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(CORPO_ADMIN))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("id.invalido")))
                .andExpect(jsonPath("$.camposComErro[0].campo").value("id"));
        verifyNoInteractions(usuarioService);
    }

    @Test
    void alterarPerfilDoUltimoAdminDeveRetornar409() throws Exception {
        when(usuarioService.alterarPerfil(any(), any(), any()))
                .thenThrow(new ConflitoException(Mensagens.get("perfil.ultimo.admin")));

        mockMvc.perform(put("/v1/usuarios/{id}/perfil", UUID.randomUUID())
                        .with(como(UUID.randomUUID(), "ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"perfil\":\"USER\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("perfil.ultimo.admin")));
    }

    @Test
    void alterarPerfilDeUsuarioInexistenteDeveRetornar404() throws Exception {
        when(usuarioService.alterarPerfil(any(), any(), any()))
                .thenThrow(new RecursoNaoEncontradoException(Mensagens.get("user.nao.encontrado")));

        mockMvc.perform(put("/v1/usuarios/{id}/perfil", UUID.randomUUID())
                        .with(como(UUID.randomUUID(), "ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(CORPO_ADMIN))
                .andExpect(status().isNotFound());
    }

    @Test
    void adminDeveConsultarUsuarioPorIdComIdNoCorpo() throws Exception {
        UUID alvo = UUID.randomUUID();
        when(usuarioService.buscarPorId(alvo)).thenReturn(responseComId(alvo, Perfil.USER));

        mockMvc.perform(get("/v1/usuarios/{id}", alvo).with(como(UUID.randomUUID(), "ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(alvo.toString()))
                .andExpect(jsonPath("$.email").value("mail@mail.com"))
                .andExpect(jsonPath("$.perfil").value("USER"));
    }

    @Test
    void consultaPorIdInexistenteDeveRetornar404() throws Exception {
        when(usuarioService.buscarPorId(any(UUID.class)))
                .thenThrow(new RecursoNaoEncontradoException(Mensagens.get("user.nao.encontrado")));

        mockMvc.perform(get("/v1/usuarios/{id}", UUID.randomUUID()).with(como(UUID.randomUUID(), "ADMIN")))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("user.nao.encontrado")));
    }

    @Test
    void userNaoDeveConsultarUsuarioPorId403() throws Exception {
        mockMvc.perform(get("/v1/usuarios/{id}", UUID.randomUUID()).with(como(UUID.randomUUID(), "USER")))
                .andExpect(status().isForbidden());
        verifyNoInteractions(usuarioService);
    }

    @Test
    void consultaPorIdSemTokenDeveRetornar401() throws Exception {
        mockMvc.perform(get("/v1/usuarios/{id}", UUID.randomUUID()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void consultaPorIdInvalidoDeveRetornar400IdInvalido() throws Exception {
        mockMvc.perform(get("/v1/usuarios/{id}", "abc").with(como(UUID.randomUUID(), "ADMIN")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("id.invalido")))
                .andExpect(jsonPath("$.camposComErro", hasSize(1)))
                .andExpect(jsonPath("$.camposComErro[0].campo").value("id"));
        verifyNoInteractions(usuarioService);
    }

    @Test
    void cadastroComPerfilAdminNoCorpoDeveSerAceitoEIgnorado() throws Exception {
        when(usuarioService.criarUsuario(any(UsuarioRequest.class))).thenReturn(responseValido());

        mockMvc.perform(post("/v1/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"mail@mail.com\",\"nome\":\"João das Neves\","
                                + "\"senha\":\"Dispensa#2024\",\"perfil\":\"ADMIN\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.perfil").value("USER"));

        ArgumentCaptor<UsuarioRequest> captor = ArgumentCaptor.forClass(UsuarioRequest.class);
        verify(usuarioService).criarUsuario(captor.capture());
        org.assertj.core.api.Assertions.assertThat(captor.getValue())
                .isEqualTo(new UsuarioRequest("mail@mail.com", "João das Neves", "Dispensa#2024"));
        org.assertj.core.api.Assertions.assertThat(UsuarioRequest.class.getRecordComponents())
                .extracting(java.lang.reflect.RecordComponent::getName)
                .doesNotContain("perfil");
    }

    @Test
    void cadastroComSenhaComumDeveRetornar400ComCampoSenha() throws Exception {
        when(usuarioService.criarUsuario(any(UsuarioRequest.class)))
                .thenThrow(new RegraNegocioException("senha.comum", "senha"));

        mockMvc.perform(post("/v1/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new UsuarioRequest("mail@mail.com", "João das Neves", "password123"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("senha.comum")))
                .andExpect(jsonPath("$.camposComErro", hasSize(1)))
                .andExpect(jsonPath("$.camposComErro[0].campo").value("senha"))
                .andExpect(jsonPath("$.camposComErro[0].mensagem").value(Mensagens.get("senha.comum")));
    }

    @Test
    void cadastroComSenhaIgualAoEmailDeveRetornar400ComCampoSenha() throws Exception {
        when(usuarioService.criarUsuario(any(UsuarioRequest.class)))
                .thenThrow(new RegraNegocioException("senha.igual.email", "senha"));

        mockMvc.perform(post("/v1/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new UsuarioRequest("mail@mail.com", "João das Neves", "mail@mail.com"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("senha.igual.email")))
                .andExpect(jsonPath("$.camposComErro[*].campo", containsInAnyOrder("senha")));
    }

    @Test
    void tokenAssinadoComVersaoRevogadaDeveRetornar401TokenRevogado() throws Exception {
        UUID id = UUID.randomUUID();
        when(tokenVersionValidator.validate(any())).thenReturn(OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", TokenVersionValidator.DESCRICAO_REVOGADO, null)));
        Instant agora = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("gestaousuarios").subject(id.toString())
                .issuedAt(agora).expiresAt(agora.plusSeconds(600))
                .claim("perfil", "ADMIN").claim("tv", 0).build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();

        mockMvc.perform(get("/v1/usuarios/{id}", UUID.randomUUID())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("token.revogado")));
        verify(usuarioService, never()).buscarPorId(any());
    }
}
