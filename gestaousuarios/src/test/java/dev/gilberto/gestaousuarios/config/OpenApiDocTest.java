package dev.gilberto.gestaousuarios.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Teste de documentação OpenAPI (R14.1, R14.2, R14.3).
 *
 * <p>Verifica, com o contexto completo da aplicação de pé (perfil {@code test}, H2 em memória),
 * que o documento OpenAPI gerado pelo springdoc:
 * <ul>
 *   <li>é servido publicamente, com status 200 e corpo JSON (R14.1);</li>
 *   <li>contém os paths {@code /v1/...} da API — {@code /v1/usuarios}, {@code /v1/auth/login}
 *       e {@code /v1/me} (R14.2);</li>
 *   <li>declara o esquema de segurança <em>bearer</em> JWT ({@code bearer-jwt}) proveniente de
 *       {@link OpenApiConfig} (R14.3).</li>
 * </ul>
 *
 * <p><strong>Path do documento.</strong> O {@code application.yml} define
 * {@code springdoc.api-docs.path: /swagger-ui/api-docs}, de modo que o JSON do OpenAPI é servido
 * nesse caminho (e não no default {@code /v3/api-docs}). A {@code SecurityFilterChain} de
 * {@link SecurityConfig} libera {@code /v3/api-docs/**}, {@code /swagger-ui/**} e
 * {@code /swagger-ui/api-docs}, portanto o endpoint é público (sem token).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class OpenApiDocTest {

    /**
     * Caminho configurado em {@code application.yml} para o documento JSON do OpenAPI.
     */
    private static final String API_DOCS_PATH = "/swagger-ui/api-docs";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void deveExporDocumentacaoOpenApiComPathsV1EBearer() throws Exception {
        MvcResult resultado = mockMvc.perform(get(API_DOCS_PATH))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn();

        String corpo = resultado.getResponse().getContentAsString();

        // R14.2 — paths /v1/... expostos na documentação
        assertThat(corpo)
                .as("documento OpenAPI deve declarar os paths /v1 da API")
                .contains("/v1/usuarios")
                .contains("/v1/auth/login")
                .contains("/v1/me");

        // R14.3 — esquema de segurança bearer JWT declarado em OpenApiConfig
        assertThat(corpo)
                .as("documento OpenAPI deve declarar o securityScheme bearer JWT")
                .contains("bearer-jwt")
                .contains("\"scheme\":\"bearer\"")
                .contains("\"bearerFormat\":\"JWT\"");
    }

    // ------------------------------------------------------------------
    // Documentação das novas rotas, erros, segurança e schemas (R18.3-18.5)
    // ------------------------------------------------------------------

    private JsonNode documento() throws Exception {
        String corpo = mockMvc.perform(get(API_DOCS_PATH)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return new ObjectMapper().readTree(corpo);
    }

    private static JsonNode operacao(JsonNode doc, String path, String metodo) {
        JsonNode op = doc.path("paths").path(path).path(metodo);
        assertThat(op.isMissingNode()).as("%s %s deve estar documentado", metodo, path).isFalse();
        return op;
    }

    private static void assertPublica(JsonNode op, String rotulo) {
        // @SecurityRequirements vazio sobrescreve o requisito global: "security": []
        assertThat(op.has("security")).as("%s deve declarar security vazio", rotulo).isTrue();
        assertThat(op.get("security").size()).as("%s não exige bearer", rotulo).isZero();
    }

    private static void assertProtegida(JsonNode doc, JsonNode op, String rotulo) {
        JsonNode sec = op.has("security") ? op.get("security") : doc.path("security");
        assertThat(sec.toString()).as("%s exige bearer-jwt", rotulo).contains("bearer-jwt");
    }

    @Test
    void deveDocumentarPathsDeSessaoEPerfil() throws Exception {
        JsonNode doc = documento();
        operacao(doc, "/v1/auth/refresh", "post");
        operacao(doc, "/v1/auth/logout", "post");
        operacao(doc, "/v1/auth/logout-all", "post");
        operacao(doc, "/v1/usuarios/{id}", "get");
        operacao(doc, "/v1/usuarios/{id}/perfil", "put");
    }

    @Test
    void deveDocumentarCodigosDeErro() throws Exception {
        JsonNode doc = documento();
        assertRespostas(operacao(doc, "/v1/auth/login", "post"), "200", "400", "401", "429");
        assertRespostas(operacao(doc, "/v1/auth/refresh", "post"), "200", "400", "401", "429");
        assertRespostas(operacao(doc, "/v1/auth/logout", "post"), "204", "400");
        assertRespostas(operacao(doc, "/v1/auth/logout-all", "post"), "204", "401");
        assertRespostas(operacao(doc, "/v1/usuarios/{id}", "get"), "200", "400", "401", "403", "404");
        assertRespostas(operacao(doc, "/v1/usuarios/{id}/perfil", "put"),
                "200", "400", "401", "403", "404", "409");
    }

    private static void assertRespostas(JsonNode op, String... codigos) {
        for (String c : codigos) {
            assertThat(op.path("responses").has(c)).as("resposta %s documentada", c).isTrue();
        }
    }

    @Test
    void deveDocumentarCabecalhoRetryAfterNos429() throws Exception {
        JsonNode doc = documento();
        for (String path : new String[] {"/v1/auth/login", "/v1/auth/refresh"}) {
            JsonNode h = operacao(doc, path, "post").path("responses").path("429").path("headers");
            assertThat(h.has("Retry-After")).as("Retry-After em 429 de %s", path).isTrue();
            assertThat(h.path("Retry-After").path("schema").path("type").asText()).isEqualTo("integer");
        }
    }

    @Test
    void deveDistinguirRotasPublicasDasProtegidas() throws Exception {
        JsonNode doc = documento();
        assertThat(doc.path("security").toString()).contains("bearer-jwt");

        assertPublica(operacao(doc, "/v1/auth/login", "post"), "login");
        assertPublica(operacao(doc, "/v1/auth/refresh", "post"), "refresh");
        assertPublica(operacao(doc, "/v1/auth/logout", "post"), "logout");

        assertProtegida(doc, operacao(doc, "/v1/auth/logout-all", "post"), "logout-all");
        assertProtegida(doc, operacao(doc, "/v1/usuarios/{id}", "get"), "GET usuarios/{id}");
        assertProtegida(doc, operacao(doc, "/v1/usuarios/{id}/perfil", "put"), "PUT perfil");
        assertProtegida(doc, operacao(doc, "/v1/me", "get"), "GET me");
    }

    @Test
    void deveExporRefreshTokenNoSchemaTokenResponse() throws Exception {
        JsonNode props = documento().path("components").path("schemas").path("TokenResponse").path("properties");
        assertThat(props.has("refreshToken")).isTrue();
        assertThat(props.has("accessToken")).isTrue();
        assertThat(props.has("refreshExpiraEm")).isTrue();
    }

    @Test
    void deveDescreverTradeOffD2ELimitacaoD4() throws Exception {
        String descricao = documento().path("info").path("description").asText();
        // D2: custo de uma leitura por requisição em troca de revogação imediata
        assertThat(descricao).contains("Decisão D2").contains("leitura por chave primária")
                .contains("revogação imediata");
        // D4: contador em memória, válido para instância única, evolução para Redis
        assertThat(descricao).contains("Decisão D4").contains("memória do processo")
                .contains("instância única").contains("Redis").contains("Retry-After");
    }
}
