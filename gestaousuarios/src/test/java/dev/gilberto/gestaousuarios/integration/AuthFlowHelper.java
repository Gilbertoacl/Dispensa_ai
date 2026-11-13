package dev.gilberto.gestaousuarios.integration;

import dev.gilberto.gestaousuarios.auth.LoginRequest;
import dev.gilberto.gestaousuarios.usuario.UsuarioRequest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Apoio comum dos ITs de autenticação (MockMvc): cadastro, login, refresh e logout. */
final class AuthFlowHelper {

    /** Par de tokens devolvido pelo login/refresh. */
    record Tokens(String access, String refresh) {}

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;

    AuthFlowHelper(MockMvc mockMvc, ObjectMapper objectMapper) {
        this.mockMvc = mockMvc;
        this.objectMapper = objectMapper;
    }

    static String emailUnico(String prefixo) {
        return prefixo + "." + UUID.randomUUID() + "@dispensa.ai";
    }

    /** Fora da lista de senhas comuns e dentro da política (8-64). */
    static String senhaUnica() {
        return "Fluxo#" + UUID.randomUUID().toString().substring(0, 18);
    }

    String json(Object body) {
        return objectMapper.writeValueAsString(body);
    }

    UUID cadastrar(String email, String nome, String senha) throws Exception {
        MvcResult result = mockMvc.perform(post("/v1/usuarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new UsuarioRequest(email, nome, senha))))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(objectMapper.readTree(result.getResponse().getContentAsString())
                .get("id").asString());
    }

    ResultActions tentarLogin(String email, String senha) throws Exception {
        return mockMvc.perform(post("/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(new LoginRequest(email, senha))));
    }

    Tokens login(String email, String senha) throws Exception {
        return extrair(tentarLogin(email, senha).andExpect(status().isOk()).andReturn());
    }

    ResultActions tentarRefresh(String refresh) throws Exception {
        return mockMvc.perform(post("/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("refreshToken", refresh))));
    }

    Tokens refresh(String refresh) throws Exception {
        return extrair(tentarRefresh(refresh).andExpect(status().isOk()).andReturn());
    }

    ResultActions logout(String refresh) throws Exception {
        return mockMvc.perform(post("/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("refreshToken", refresh))));
    }

    ResultActions logoutAll(Tokens tokens) throws Exception {
        return mockMvc.perform(post("/v1/auth/logout-all")
                .header("Authorization", bearer(tokens)));
    }

    Tokens extrair(MvcResult result) throws Exception {
        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        return new Tokens(node.get("accessToken").asString(), node.get("refreshToken").asString());
    }

    static String bearer(Tokens tokens) {
        return "Bearer " + tokens.access();
    }
}
