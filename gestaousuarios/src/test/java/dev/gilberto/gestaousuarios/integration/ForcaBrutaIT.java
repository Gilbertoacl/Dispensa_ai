package dev.gilberto.gestaousuarios.integration;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT 16.5: bloqueio temporário por força bruta (limiar 5, definido em {@link AbstractPostgresIT}).
 * O contador é em memória e por e-mail normalizado: cada teste usa e-mails únicos.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ForcaBrutaIT extends AbstractPostgresIT {

    private static final int LIMIAR = 5;

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    private AuthFlowHelper fluxo() {
        return new AuthFlowHelper(mockMvc, objectMapper);
    }

    private static String senhaErrada() {
        return "Errada#" + UUID.randomUUID().toString().substring(0, 12);
    }

    private void falhar(AuthFlowHelper f, String email, int vezes) throws Exception {
        for (int i = 0; i < vezes; i++) {
            f.tentarLogin(email, senhaErrada())
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.mensagem").value(Mensagens.get("user.invalid.credentials")));
        }
    }

    /** Após o limiar: 429 login.bloqueado com Retry-After inteiro positivo; devolve (mensagem, retry). */
    private String[] exigirBloqueio(AuthFlowHelper f, String email, String senha) throws Exception {
        MvcResult r = f.tentarLogin(email, senha)
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.mensagem").value(Mensagens.get("login.bloqueado")))
                .andReturn();
        String retry = r.getResponse().getHeader("Retry-After");
        assertThat(retry).isNotNull();
        assertThat(Long.parseLong(retry)).isPositive().isLessThanOrEqualTo(15 * 60L);
        return new String[] {r.getResponse().getContentAsString(), retry};
    }

    @Test
    void usuarioExistenteBloqueadoAposOLimiarMesmoComSenhaCorreta() throws Exception {
        AuthFlowHelper f = fluxo();
        String email = AuthFlowHelper.emailUnico("brute");
        String senha = AuthFlowHelper.senhaUnica();
        f.cadastrar(email, "Forca Bruta", senha);

        falhar(f, email, LIMIAR);

        exigirBloqueio(f, email, senha);
        // A normalização do e-mail faz variações de caixa/espaços cair na mesma conta.
        exigirBloqueio(f, email.toUpperCase(), senha);
    }

    @Test
    void emailInexistenteTemMesmaRespostaEMesmoLimiar() throws Exception {
        AuthFlowHelper f = fluxo();
        String email = AuthFlowHelper.emailUnico("fantasma");
        String existente = AuthFlowHelper.emailUnico("real");
        String senha = AuthFlowHelper.senhaUnica();
        f.cadastrar(existente, "Real", senha);

        // Antes do limiar: respostas idênticas (corpo e status) para existente e inexistente.
        MvcResult rInexistente = f.tentarLogin(email, senhaErrada()).andExpect(status().isUnauthorized()).andReturn();
        MvcResult rExistente = f.tentarLogin(existente, senhaErrada()).andExpect(status().isUnauthorized()).andReturn();
        assertThat(semDadosVolateis(rInexistente)).isEqualTo(semDadosVolateis(rExistente));

        falhar(f, email, LIMIAR - 1); // 1 + (LIMIAR - 1) = LIMIAR falhas
        falhar(f, existente, LIMIAR - 1);

        String[] bloqInexistente = exigirBloqueio(f, email, senha);
        String[] bloqExistente = exigirBloqueio(f, existente, senha);
        assertThat(semDadosVolateis(bloqInexistente[0])).isEqualTo(semDadosVolateis(bloqExistente[0]));
    }

    @Test
    void falhasAntesDoLimiarNaoBloqueiamESucessoZeraOContador() throws Exception {
        AuthFlowHelper f = fluxo();
        String email = AuthFlowHelper.emailUnico("zera");
        String senha = AuthFlowHelper.senhaUnica();
        f.cadastrar(email, "Zera", senha);

        falhar(f, email, LIMIAR - 1);
        f.login(email, senha); // sucesso zera o contador

        // Outra rodada de LIMIAR-1 falhas não bloqueia (se o contador não zerasse, bloquearia).
        falhar(f, email, LIMIAR - 1);
        f.login(email, senha);

        // E o limiar completo ainda bloqueia depois do reset.
        falhar(f, email, LIMIAR);
        exigirBloqueio(f, email, senha);
    }

    @Test
    void bloqueioDeUmaContaNaoAfetaOutra() throws Exception {
        AuthFlowHelper f = fluxo();
        String bloqueada = AuthFlowHelper.emailUnico("bloq");
        String livre = AuthFlowHelper.emailUnico("livre");
        String senha = AuthFlowHelper.senhaUnica();
        f.cadastrar(bloqueada, "Bloqueada", senha);
        f.cadastrar(livre, "Livre", senha);

        falhar(f, bloqueada, LIMIAR);
        exigirBloqueio(f, bloqueada, senha);

        f.login(livre, senha);
    }

    /** Remove o timestamp (varia a cada resposta) para comparar o restante do corpo. */
    private String semDadosVolateis(MvcResult r) throws Exception {
        return semDadosVolateis(r.getResponse().getContentAsString());
    }

    private String semDadosVolateis(String corpo) {
        ObjectNode node = (ObjectNode) objectMapper.readTree(corpo);
        node.remove("timestamp");
        return node.toString();
    }
}
