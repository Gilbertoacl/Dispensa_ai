package dev.gilberto.gestaousuarios.integration;

import dev.gilberto.gestaousuarios.integration.AuthFlowHelper.Tokens;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT 16.3: ciclo de vida da sessão (login, rotação, reuso, logout, logout-all, expiração) contra
 * PostgreSQL real, com verificação do estado em REFRESH_TOKENS e EVENTOS_SEGURANCA.
 * E-mails únicos por teste; nenhuma contagem absoluta.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SessaoIT extends AbstractPostgresIT {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JdbcTemplate jdbc;

    private AuthFlowHelper fluxo() {
        return new AuthFlowHelper(mockMvc, objectMapper);
    }

    private List<Map<String, Object>> tokensDoUsuario(UUID usuarioId) {
        return jdbc.queryForList(
                "select id, familia_id, revogado_em, motivo_revogacao, substituido_por_id, expira_em "
                        + "from refresh_tokens where usuario_id = ? order by criado_em, id", usuarioId);
    }

    private List<String> tiposDeEvento(UUID usuarioId) {
        return jdbc.queryForList(
                "select tipo from eventos_seguranca where usuario_id = ? order by instante", String.class,
                usuarioId);
    }

    // Rotação: refresh novo != antigo, mesma família, antigo aponta para o substituto.
    @Test
    void rotacaoMantemFamiliaEMarcaSubstituto() throws Exception {
        AuthFlowHelper f = fluxo();
        String email = AuthFlowHelper.emailUnico("rot");
        String senha = AuthFlowHelper.senhaUnica();
        UUID id = f.cadastrar(email, "Rotacao", senha);

        Tokens t1 = f.login(email, senha);
        Tokens t2 = f.refresh(t1.refresh());

        assertThat(t2.refresh()).isNotEqualTo(t1.refresh());
        assertThat(t2.access()).isNotBlank();
        mockMvc.perform(get("/v1/me").header("Authorization", AuthFlowHelper.bearer(t2)))
                .andExpect(status().isOk());

        List<Map<String, Object>> linhas = tokensDoUsuario(id);
        assertThat(linhas).hasSize(2);
        Map<String, Object> antigo = linhas.get(0);
        Map<String, Object> novo = linhas.get(1);
        assertThat(antigo.get("familia_id")).isEqualTo(novo.get("familia_id"));
        assertThat(antigo.get("substituido_por_id")).isEqualTo(novo.get("id"));
        assertThat(antigo.get("revogado_em")).isNotNull();
        assertThat(antigo.get("motivo_revogacao")).isEqualTo("ROTACAO");
        assertThat(novo.get("revogado_em")).isNull();
        assertThat(novo.get("substituido_por_id")).isNull();
        assertThat(tiposDeEvento(id)).contains("LOGIN_SUCESSO", "REFRESH_SUCESSO");
    }

    // Reuso do refresh antigo: 401 refresh.reutilizado, família inteira revogada, evento gravado
    // apesar do 401 (REQUIRES_NEW), e o refresh novo também deixa de funcionar.
    @Test
    void reusoRevogaFamiliaInteiraEGravaEventoApesarDo401() throws Exception {
        AuthFlowHelper f = fluxo();
        String email = AuthFlowHelper.emailUnico("reuso");
        String senha = AuthFlowHelper.senhaUnica();
        UUID id = f.cadastrar(email, "Reuso", senha);

        Tokens t1 = f.login(email, senha);
        Tokens t2 = f.refresh(t1.refresh());

        f.tentarRefresh(t1.refresh())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("refresh.reutilizado")));

        for (Map<String, Object> linha : tokensDoUsuario(id)) {
            assertThat(linha.get("revogado_em")).as("toda a família revogada").isNotNull();
        }
        assertThat(jdbc.queryForObject(
                "select count(*) from eventos_seguranca where usuario_id = ? and tipo = 'REFRESH_REUSO_DETECTADO'",
                Integer.class, id)).isEqualTo(1);

        f.tentarRefresh(t2.refresh())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("refresh.invalido")));
    }

    // Logout revoga a família; o refresh deixa de valer e o logout é idempotente (204).
    @Test
    void logoutRevogaARefreshDaSessao() throws Exception {
        AuthFlowHelper f = fluxo();
        String email = AuthFlowHelper.emailUnico("logout");
        String senha = AuthFlowHelper.senhaUnica();
        UUID id = f.cadastrar(email, "Logout", senha);
        Tokens t = f.login(email, senha);

        f.logout(t.refresh()).andExpect(status().isNoContent());

        f.tentarRefresh(t.refresh())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("refresh.invalido")));
        assertThat(tokensDoUsuario(id)).allSatisfy(l -> {
            assertThat(l.get("revogado_em")).isNotNull();
            assertThat(l.get("motivo_revogacao")).isEqualTo("LOGOUT");
        });
        f.logout(t.refresh()).andExpect(status().isNoContent());
        assertThat(tiposDeEvento(id)).contains("LOGOUT");
    }

    // Logout global: revoga todas as sessões e invalida o access token anterior (tv).
    @Test
    void logoutAllRevogaTodasAsSessoesEInvalidaOAccessAnterior() throws Exception {
        AuthFlowHelper f = fluxo();
        String email = AuthFlowHelper.emailUnico("logoutall");
        String senha = AuthFlowHelper.senhaUnica();
        UUID id = f.cadastrar(email, "Logout All", senha);
        Tokens a = f.login(email, senha);
        Tokens b = f.login(email, senha);

        f.logoutAll(a).andExpect(status().isNoContent());

        mockMvc.perform(get("/v1/me").header("Authorization", AuthFlowHelper.bearer(a)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("token.revogado")));
        mockMvc.perform(get("/v1/me").header("Authorization", AuthFlowHelper.bearer(b)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("token.revogado")));
        f.tentarRefresh(a.refresh()).andExpect(status().isUnauthorized());
        f.tentarRefresh(b.refresh()).andExpect(status().isUnauthorized());
        assertThat(tokensDoUsuario(id)).hasSize(2).allSatisfy(l -> {
            assertThat(l.get("revogado_em")).isNotNull();
            assertThat(l.get("motivo_revogacao")).isEqualTo("LOGOUT_TODOS");
        });
        assertThat(tiposDeEvento(id)).contains("LOGOUT_TODOS");

        // Um novo login volta a funcionar com a tokenVersion incrementada.
        Tokens nova = f.login(email, senha);
        mockMvc.perform(get("/v1/me").header("Authorization", AuthFlowHelper.bearer(nova)))
                .andExpect(status().isOk());
    }

    // Refresh expirado: EXPIRA_EM no passado => 401 refresh.expirado, sem rotação.
    @Test
    void refreshExpiradoRecebe401() throws Exception {
        AuthFlowHelper f = fluxo();
        String email = AuthFlowHelper.emailUnico("expira");
        String senha = AuthFlowHelper.senhaUnica();
        UUID id = f.cadastrar(email, "Expira", senha);
        Tokens t = f.login(email, senha);

        jdbc.update("update refresh_tokens set expira_em = ? where usuario_id = ?",
                Timestamp.valueOf("2000-01-01 00:00:00"), id);

        f.tentarRefresh(t.refresh())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("refresh.expirado")));
        List<Map<String, Object>> linhas = tokensDoUsuario(id);
        assertThat(linhas).hasSize(1);
        assertThat(linhas.get(0).get("substituido_por_id")).isNull();
    }

    // Refresh desconhecido não revela nada além de 401 refresh.invalido.
    @Test
    void refreshDesconhecidoRecebe401() throws Exception {
        fluxo().tentarRefresh("token-que-nunca-existiu-" + UUID.randomUUID())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("refresh.invalido")));
    }

    // Eventos persistidos não carregam e-mail, senha, refresh token ou access token em claro.
    @Test
    void eventosDeSegurancaNaoVazamDadosSensiveis() throws Exception {
        AuthFlowHelper f = fluxo();
        String email = AuthFlowHelper.emailUnico("pii");
        String senha = AuthFlowHelper.senhaUnica();
        UUID id = f.cadastrar(email, "Sem Pii", senha);

        f.tentarLogin(email, "Errada#" + UUID.randomUUID().toString().substring(0, 10))
                .andExpect(status().isUnauthorized());
        Tokens t1 = f.login(email, senha);
        Tokens t2 = f.refresh(t1.refresh());
        f.tentarRefresh(t1.refresh()).andExpect(status().isUnauthorized()); // reuso
        f.logout(t2.refresh()).andExpect(status().isNoContent());

        List<Map<String, Object>> eventos = jdbc.queryForList(
                "select tipo, ip, detalhe from eventos_seguranca where usuario_id = ?", id);
        assertThat(eventos).extracting(e -> e.get("tipo")).contains(
                "LOGIN_FALHA", "LOGIN_SUCESSO", "REFRESH_SUCESSO", "REFRESH_REUSO_DETECTADO");
        String tudo = eventos.toString();
        assertThat(tudo).doesNotContainIgnoringCase(email)
                .doesNotContain(senha)
                .doesNotContain(t1.refresh())
                .doesNotContain(t2.refresh())
                .doesNotContain(t1.access())
                .doesNotContain(t2.access());
    }
}
