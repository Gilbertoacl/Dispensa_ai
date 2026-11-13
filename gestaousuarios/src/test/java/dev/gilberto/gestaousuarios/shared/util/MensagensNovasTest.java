package dev.gilberto.gestaousuarios.shared.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.io.InputStreamReader;
import java.io.Reader;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

class MensagensNovasTest {

    static final String[] CHAVES = {
            "jwt.segredo.invalido.producao", "refresh.obrigatorio", "refresh.invalido", "refresh.expirado",
            "refresh.reutilizado", "token.revogado", "login.bloqueado", "ratelimit.excedido",
            "perfil.ultimo.admin", "senha.igual.email", "senha.comum", "senha.bytes.excedido",
            "id.invalido", "admin.inicial.senha.invalida"
    };

    @ParameterizedTest
    @ValueSource(strings = {
            "jwt.segredo.invalido.producao", "refresh.obrigatorio", "refresh.invalido", "refresh.expirado",
            "refresh.reutilizado", "token.revogado", "login.bloqueado", "ratelimit.excedido",
            "perfil.ultimo.admin", "senha.igual.email", "senha.comum", "senha.bytes.excedido",
            "id.invalido", "admin.inicial.senha.invalida"
    })
    void chaveNovaExisteENaoEhVazia(String chave) {
        String valor = Mensagens.get(chave);
        assertThat(valor).isNotBlank().isNotEqualTo("???" + chave + "???");
    }

    @Test
    void adminInicialSenhaInvalidaAceitaParametro() {
        assertThat(Mensagens.get("admin.inicial.senha.invalida", "senha comum"))
                .contains("senha comum")
                .doesNotContain("{0}");
    }

    @Test
    void acentosEstaoCorretosEmUtf8() throws Exception {
        Properties props = new Properties();
        try (InputStream in = getClass().getResourceAsStream("/messages.properties");
             Reader r = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            props.load(r);
        }
        for (String chave : CHAVES) {
            assertThat(props.getProperty(chave)).as(chave).doesNotContain("\uFFFD").doesNotContain("Ã");
        }
        assertThat(props.getProperty("refresh.invalido")).isEqualTo("Refresh token inválido");
        assertThat(props.getProperty("perfil.ultimo.admin")).contains("Não é possível").contains("último");
        assertThat(props.getProperty("login.bloqueado")).contains("Muitas tentativas");
        // A resolução via Mensagens (ResourceBundle) deve coincidir com a leitura UTF-8.
        for (String chave : CHAVES) {
            assertThat(Mensagens.get(chave)).as(chave).isEqualTo(props.getProperty(chave));
        }
    }
}
