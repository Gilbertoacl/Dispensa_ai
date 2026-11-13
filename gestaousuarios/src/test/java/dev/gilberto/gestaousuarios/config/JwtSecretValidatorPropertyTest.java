package dev.gilberto.gestaousuarios.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;

import org.springframework.mock.env.MockEnvironment;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Testes de propriedade (jqwik) do {@link JwtSecretValidator}.
 */
class JwtSecretValidatorPropertyTest {

    private static final String PREFIXO_DEV = "dev-only-secret-";

    @Provide
    Arbitrary<String> segredos() {
        Arbitrary<String> ascii = Arbitraries.strings().ascii().ofMinLength(0).ofMaxLength(80);
        // multibyte: 2 a 3 bytes por caractere em UTF-8
        Arbitrary<String> multibyte = Arbitraries.strings()
                .withCharRange('\u00e0', '\u00ff').withCharRange('\u4e00', '\u4e40')
                .ofMinLength(0).ofMaxLength(40);
        Arbitrary<String> brancos = Arbitraries.strings().withChars(' ', '\t', '\n', '\r')
                .ofMinLength(0).ofMaxLength(80);
        Arbitrary<String> comPrefixoDev = Arbitraries.strings().ascii().ofMinLength(0).ofMaxLength(64)
                .map(sufixo -> PREFIXO_DEV + sufixo);
        // bordas em torno de 32 bytes
        Arbitrary<String> bordas = Arbitraries.integers().between(30, 34)
                .map(n -> "a".repeat(n));
        return Arbitraries.oneOf(ascii, multibyte, brancos, comPrefixoDev, bordas,
                Arbitraries.just(""), Arbitraries.just(PREFIXO_DEV));
    }

    private static boolean modeloReferencia(String s) {
        return s != null
                && !s.trim().isEmpty()
                && s.getBytes(StandardCharsets.UTF_8).length >= 32
                && !s.startsWith(PREFIXO_DEV);
    }

    // Feature: endurecimento-autenticacao, Property 16: Validador de segredo JWT em produção
    // Validates: Requirements 12.1, 12.2, 12.4, 12.5
    @Property(tries = 300)
    void aceitoEmProducaoSeESomenteSeRegraAtendida(@ForAll("segredos") String s) {
        assertThat(JwtSecretValidator.aceitoEmProducao(s)).isEqualTo(modeloReferencia(s));
    }

    // Feature: endurecimento-autenticacao, Property 16: Validador de segredo JWT em produção
    // Validates: Requirements 12.1, 12.2, 12.4, 12.5
    @Property(tries = 300)
    void falhaEmProducaoSoParaRejeitadosEMensagemNaoVazaSegredo(@ForAll("segredos") String s) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        JwtSecretValidator validator = new JwtSecretValidator(env, new JwtProperties(s, 900));

        if (modeloReferencia(s)) {
            validator.afterPropertiesSet();
            return;
        }
        String esperada = Mensagens.get("jwt.segredo.invalido.producao");
        assertThatThrownBy(validator::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                // mensagem fixa: independe do valor do segredo, logo nunca o contém
                .hasMessage(esperada);
        // verificação literal para segredos não triviais (curtos podem coincidir com o texto fixo)
        if (s.length() >= 12) {
            assertThat(esperada).doesNotContain(s);
        }
    }

    // Feature: endurecimento-autenticacao, Property 16: Validador de segredo JWT em produção
    // Validates: Requirements 12.3
    @Property(tries = 100)
    void foraDeProducaoNuncaFalha(@ForAll("segredos") String s) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("dev");
        new JwtSecretValidator(env, new JwtProperties(s, 900)).afterPropertiesSet();
    }
}
