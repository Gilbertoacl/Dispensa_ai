package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;

class PasswordPolicyTest {

    private final PasswordPolicy policy = PasswordPolicy.padrao();

    private void assertRejeita(PasswordPolicy p, String senha, String email, String chave, String campo) {
        assertThatThrownBy(() -> p.validar(senha, email, campo))
                .isInstanceOfSatisfying(RegraNegocioException.class, e -> {
                    assertThat(e.getChave()).isEqualTo(chave);
                    assertThat(e.getCampo()).isEqualTo(campo);
                    assertThat(e.getMessage()).isEqualTo(Mensagens.get(chave));
                });
    }

    @Test
    void listaPadraoTemPeloMenos20PadroesComOitoOuMaisCaracteres() {
        List<String> padrao = PasswordPolicyProperties.padrao().senhasComuns();
        assertThat(padrao.size()).isGreaterThanOrEqualTo(20);
        assertThat(padrao).allSatisfy(s -> assertThat(s.length()).isGreaterThanOrEqualTo(8));
    }

    @Test
    void listaVaziaOuNulaUsaPadrao() {
        assertThat(new PasswordPolicyProperties(null).senhasComuns()).isEqualTo(PasswordPolicyProperties.PADRAO);
        assertThat(new PasswordPolicyProperties(List.of()).senhasComuns()).isEqualTo(PasswordPolicyProperties.PADRAO);
    }

    @Test
    void listaConfiguradaSubstituiAPadrao() {
        PasswordPolicy custom = new PasswordPolicy(new PasswordPolicyProperties(List.of("MinhaSenhaProibida")));
        assertRejeita(custom, "minhasenhaproibida", null, "senha.comum", "senha");
        // item da lista padrão deixa de ser comum
        assertThatCode(() -> custom.validar("12345678", null, "senha")).doesNotThrowAnyException();
    }

    @Test
    void bordasDeTamanho8e64() {
        assertThatCode(() -> policy.validar("Abcd#123", null, "senha")).doesNotThrowAnyException();
        assertThatCode(() -> policy.validar("a".repeat(64), null, "senha")).doesNotThrowAnyException();
        assertRejeita(policy, "Abcd#12", null, "password.tamanho", "senha");
        assertRejeita(policy, "a".repeat(65), null, "password.tamanho", "senha");
        assertRejeita(policy, null, null, "password.tamanho", "senha");
    }

    @Test
    void bordaDe72BytesComAcentos() {
        // 36 x 'é' = 72 bytes, 36 caracteres: aceita
        assertThatCode(() -> policy.validar("é".repeat(36), null, "senha")).doesNotThrowAnyException();
        // 37 x 'é' = 74 bytes, 37 caracteres (<= 64): rejeita por bytes
        assertRejeita(policy, "é".repeat(37), null, "senha.bytes.excedido", "senha");
        // 71 'a' + 'é' = 73 bytes, 72 caracteres -> tamanho vence (> 64 caracteres)
        assertRejeita(policy, "a".repeat(71) + "é", null, "password.tamanho", "senha");
        // 64 caracteres com 73 bytes: 55 'a' + 9 'é' = 55 + 18 = 73
        assertRejeita(policy, "a".repeat(55) + "é".repeat(9), null, "senha.bytes.excedido", "senha");
        // 64 caracteres com exatamente 72 bytes: 56 'a' + 8 'é' = 72
        assertThatCode(() -> policy.validar("a".repeat(56) + "é".repeat(8), null, "senha"))
                .doesNotThrowAnyException();
    }

    @Test
    void dentroDoLimiteDeBytesNasBordas() {
        assertThat(PasswordPolicy.dentroDoLimiteDeBytes("a".repeat(72))).isTrue();
        assertThat(PasswordPolicy.dentroDoLimiteDeBytes("a".repeat(73))).isFalse();
        assertThat(PasswordPolicy.dentroDoLimiteDeBytes("😀".repeat(18))).isTrue();
        assertThat(PasswordPolicy.dentroDoLimiteDeBytes("😀".repeat(19))).isFalse();
    }

    @Test
    void senhaIgualAoEmailComCaixaDiferente() {
        String email = "usuario.teste@exemplo.com";
        assertRejeita(policy, "Usuario.Teste@Exemplo.COM", email, "senha.igual.email", "novaSenha");
        assertRejeita(policy, "  USUARIO.TESTE@EXEMPLO.COM ", email, "senha.igual.email", "senha");
        assertThatCode(() -> policy.validar("Usuario.Teste@Exemplo.COM", null, "senha")).doesNotThrowAnyException();
    }

    @Test
    void senhasComunsSaoRejeitadasSemDistincaoDeMaiusculas() {
        assertRejeita(policy, "12345678", null, "senha.comum", "senha");
        assertRejeita(policy, "Password123", null, "senha.comum", "senha");
        assertRejeita(policy, "QWERTYUI", "outro@x.com", "senha.comum", "senha");
        assertRejeita(policy, "DispensaAI", null, "senha.comum", "novaSenha");
        for (String comum : PasswordPolicyProperties.PADRAO) {
            assertRejeita(policy, comum, null, "senha.comum", "senha");
        }
    }

    @Test
    void ordemDasRegrasTamanhoBytesEmailComum() {
        // e-mail curto igual à senha: tamanho vence
        assertRejeita(policy, "a@b.c", "a@b.c", "password.tamanho", "senha");
        // e-mail igual à senha e comum: e-mail vence
        assertRejeita(policy, "12345678", "12345678", "senha.igual.email", "senha");
    }

    @Test
    void mensagensI18nDasChavesDaPolitica() {
        for (String chave : List.of("password.tamanho", "senha.bytes.excedido", "senha.igual.email", "senha.comum")) {
            String msg = Mensagens.get(chave);
            assertThat(msg).isNotBlank().doesNotContain("???");
        }
        assertThat(Mensagens.get("senha.bytes.excedido")).contains("72");
    }
}
