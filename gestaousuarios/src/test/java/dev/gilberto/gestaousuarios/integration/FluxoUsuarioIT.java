package dev.gilberto.gestaousuarios.integration;

import dev.gilberto.gestaousuarios.auth.LoginRequest;
import dev.gilberto.gestaousuarios.usuario.AlterarPerfilRequest;
import dev.gilberto.gestaousuarios.usuario.AtualizarPerfilRequest;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.TrocarSenhaRequest;
import dev.gilberto.gestaousuarios.usuario.UsuarioRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Teste de integração 16.2 — fluxo fim-a-fim com Testcontainers (PostgreSQL).
 *
 * <p>Independe de ordem de execução e de contagens absolutas (o container é compartilhado):
 * cada teste usa e-mails únicos (UUID no local-part) e asserções relativas. O ADMIN vem do
 * Admin_Inicial configurado em {@link AbstractPostgresIT}; o cadastro público nunca cria ADMIN.
 *
 * <p>Sem Docker a classe é pulada automaticamente (ver {@link AbstractPostgresIT}).
 */
@SpringBootTest
@AutoConfigureMockMvc
class FluxoUsuarioIT extends AbstractPostgresIT {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    /** Par de tokens devolvido pelo login/refresh. */
    private record Tokens(String access, String refresh) {}

    private String json(Object body) {
        return objectMapper.writeValueAsString(body);
    }

    private static String emailUnico(String prefixo) {
        return prefixo + "." + UUID.randomUUID() + "@dispensa.ai";
    }

    private static String senhaUnica() {
        return "Fluxo#" + UUID.randomUUID().toString().substring(0, 18);
    }

    /** Cadastra um usuário público e retorna o id. */
    private UUID cadastrar(String email, String nome, String senha) throws Exception {
        MvcResult result = mockMvc.perform(post("/v1/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new UsuarioRequest(email, nome, senha))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.perfil").value(Perfil.USER.name()))
                .andReturn();
        return UUID.fromString(objectMapper.readTree(result.getResponse().getContentAsString())
                .get("id").asString());
    }

    private Tokens login(String email, String senha) throws Exception {
        MvcResult result = mockMvc.perform(post("/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new LoginRequest(email, senha))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiraEm").value(900))
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();
        return extrair(result);
    }

    private Tokens extrair(MvcResult result) throws Exception {
        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        return new Tokens(node.get("accessToken").asString(), node.get("refreshToken").asString());
    }

    private String bearer(Tokens tokens) {
        return "Bearer " + tokens.access();
    }

    private Tokens loginAdmin() throws Exception {
        return login(ADMIN_EMAIL, ADMIN_SENHA);
    }

    private void alterarPerfil(Tokens admin, UUID id, Perfil perfil) throws Exception {
        mockMvc.perform(put("/v1/usuarios/{id}/perfil", id)
                        .header("Authorization", bearer(admin))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new AlterarPerfilRequest(perfil.name()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.perfil").value(perfil.name()));
    }

    // Cadastro → login (access + refresh) → /me → PUT /me → refresh com rotação → logout.
    @Test
    void fluxoCadastroLoginMeRefreshLogout() throws Exception {
        String email = emailUnico("fluxo");
        String senha = senhaUnica();
        cadastrar(email, "Fluxo Inicial", senha);

        Tokens tokens = login(email, senha);
        assertThat(tokens.access()).isNotBlank();
        assertThat(tokens.refresh()).isNotBlank();

        mockMvc.perform(get("/v1/me").header("Authorization", bearer(tokens)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.nome").value("Fluxo Inicial"))
                .andExpect(jsonPath("$.perfil").value(Perfil.USER.name()));

        mockMvc.perform(put("/v1/me")
                        .header("Authorization", bearer(tokens))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new AtualizarPerfilRequest("Fluxo Atualizado"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nome").value("Fluxo Atualizado"));

        // Refresh com rotação: novo par; o refresh antigo deixa de valer.
        MvcResult refreshed = mockMvc.perform(post("/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("refreshToken", tokens.refresh()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiraEm").value(900))
                .andReturn();
        Tokens novos = extrair(refreshed);
        assertThat(novos.refresh()).isNotEqualTo(tokens.refresh());

        mockMvc.perform(get("/v1/me").header("Authorization", bearer(novos)))
                .andExpect(status().isOk());

        // Logout encerra o refresh atual; reutilizá-lo é recusado.
        mockMvc.perform(post("/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("refreshToken", novos.refresh()))))
                .andExpect(status().isNoContent());
        mockMvc.perform(post("/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("refreshToken", novos.refresh()))))
                .andExpect(status().isUnauthorized());
    }

    // Troca de senha: nova senha autentica, antiga não, e o access token antigo é revogado (tv).
    @Test
    void trocaDeSenhaRevogaAccessTokenAntigo() throws Exception {
        String email = emailUnico("senha");
        String senha = senhaUnica();
        String novaSenha = senhaUnica();
        cadastrar(email, "Troca Senha", senha);
        Tokens tokens = login(email, senha);

        mockMvc.perform(put("/v1/me/senha")
                        .header("Authorization", bearer(tokens))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new TrocarSenhaRequest(senha, novaSenha))))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/v1/me").header("Authorization", bearer(tokens)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(org.hamcrest.Matchers.containsString("revogado")));

        assertThat(login(email, novaSenha).access()).isNotBlank();
        mockMvc.perform(post("/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new LoginRequest(email, senha))))
                .andExpect(status().isUnauthorized());
    }

    // Escalada: "perfil": "ADMIN" no cadastro público é ignorado e o usuário nasce USER.
    @Test
    void cadastroPublicoComPerfilAdminCriaUserSemAcessoAdmin() throws Exception {
        String email = emailUnico("escalada");
        String senha = senhaUnica();

        mockMvc.perform(post("/v1/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", email, "nome", "Tentativa Escalada",
                                "senha", senha, "perfil", "ADMIN"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.perfil").value(Perfil.USER.name()));

        Tokens tokens = login(email, senha);
        mockMvc.perform(get("/v1/usuarios").header("Authorization", bearer(tokens)))
                .andExpect(status().isForbidden());
    }

    // Listagem paginada e exclusão por ADMIN (Admin_Inicial), com asserções relativas.
    @Test
    void listagemPaginadaEExclusaoComoAdmin() throws Exception {
        UUID alvoId = cadastrar(emailUnico("alvo1"), "Alvo Um", senhaUnica());
        String alvoEmail = emailUnico("alvo2");
        String alvoSenha = senhaUnica();
        UUID alvo2Id = cadastrar(alvoEmail, "Alvo Dois", alvoSenha);
        Tokens alvoTokens = login(alvoEmail, alvoSenha);
        Tokens admin = loginAdmin();

        // Em container compartilhado há pelo menos o Admin_Inicial e os dois alvos.
        mockMvc.perform(get("/v1/usuarios")
                        .header("Authorization", bearer(admin))
                        .param("page", "0")
                        .param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size").value(2))
                .andExpect(jsonPath("$.number").value(0))
                .andExpect(jsonPath("$.numberOfElements").value(2))
                .andExpect(jsonPath("$.totalElements").value(
                        org.hamcrest.Matchers.greaterThanOrEqualTo(3)));

        mockMvc.perform(get("/v1/usuarios/{id}", alvoId)
                        .header("Authorization", bearer(admin)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(alvoId.toString()));

        mockMvc.perform(delete("/v1/usuarios/{id}", alvoId)
                        .header("Authorization", bearer(admin)))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/v1/usuarios/{id}", alvoId)
                        .header("Authorization", bearer(admin)))
                .andExpect(status().isNotFound());

        // A exclusão invalida o access token do usuário removido.
        mockMvc.perform(delete("/v1/usuarios/{id}", alvo2Id)
                        .header("Authorization", bearer(admin)))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/v1/me").header("Authorization", bearer(alvoTokens)))
                .andExpect(status().isUnauthorized());
    }

    // Alteração de perfil por ADMIN invalida o token anterior (tv) e concede/retira acesso.
    @Test
    void alteracaoDePerfilInvalidaTokenAnterior() throws Exception {
        String email = emailUnico("promovido");
        String senha = senhaUnica();
        UUID id = cadastrar(email, "Promovido", senha);
        Tokens antigo = login(email, senha);
        Tokens admin = loginAdmin();

        alterarPerfil(admin, id, Perfil.ADMIN);

        mockMvc.perform(get("/v1/me").header("Authorization", bearer(antigo)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(org.hamcrest.Matchers.containsString("revogado")));

        Tokens promovido = login(email, senha);
        mockMvc.perform(get("/v1/usuarios").header("Authorization", bearer(promovido)))
                .andExpect(status().isOk());

        alterarPerfil(admin, id, Perfil.USER);
        mockMvc.perform(get("/v1/usuarios").header("Authorization", bearer(promovido)))
                .andExpect(status().isUnauthorized());
        Tokens rebaixado = login(email, senha);
        mockMvc.perform(get("/v1/usuarios").header("Authorization", bearer(rebaixado)))
                .andExpect(status().isForbidden());
    }
}
