package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Random;

import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class PasswordPolicyReferenciaPropertyTest {

    private static final String CAMPO = "senha";

    record Caso(String senha, String email) {
    }

    private final PasswordPolicy policy = PasswordPolicy.padrao();

    // ---- Modelo de referência independente (não reutiliza código de produção) ----

    /** Devolve a chave da primeira regra violada, ou null se a senha é aceita. */
    static String referencia(String senha, String email, List<String> comuns) {
        int chars = senha.length();
        if (chars < 8 || chars > 64) {
            return "password.tamanho";
        }
        int bytes = 0;
        for (int i = 0; i < senha.length(); ) {
            int cp = senha.codePointAt(i);
            i += Character.charCount(cp);
            bytes += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
        }
        if (bytes > 72) {
            return "senha.bytes.excedido";
        }
        if (email != null && senha.strip().toLowerCase(Locale.ROOT).equals(email)) {
            return "senha.igual.email";
        }
        String minuscula = senha.toLowerCase(Locale.ROOT);
        for (String c : comuns) {
            if (c.equalsIgnoreCase(minuscula) || c.toLowerCase(Locale.ROOT).equals(minuscula)) {
                return "senha.comum";
            }
        }
        return null;
    }

    // ---- Geradores ----

    private static String caixaAleatoria(String s, long semente) {
        Random r = new Random(semente);
        StringBuilder sb = new StringBuilder();
        for (char ch : s.toCharArray()) {
            sb.append(r.nextBoolean() ? Character.toUpperCase(ch) : Character.toLowerCase(ch));
        }
        return sb.toString();
    }

    private static String montar(List<Integer> pontos) {
        StringBuilder sb = new StringBuilder();
        pontos.forEach(sb::appendCodePoint);
        return sb.toString();
    }

    private Arbitrary<String> textoLivre() {
        Arbitrary<Integer> um = Arbitraries.integers().between(0x21, 0x7E);
        Arbitrary<Integer> dois = Arbitraries.integers().between(0xA0, 0x7FF);
        Arbitrary<Integer> tres = Arbitraries.integers().between(0x800, 0xD7FF);
        Arbitrary<Integer> quatro = Arbitraries.integers().between(0x10000, 0x10FFFF);
        Arbitrary<Integer> cp = Arbitraries.frequencyOf(
                net.jqwik.api.Tuple.of(6, um), net.jqwik.api.Tuple.of(3, dois),
                net.jqwik.api.Tuple.of(1, tres), net.jqwik.api.Tuple.of(1, quatro));
        return cp.list().ofMinSize(0).ofMaxSize(80).map(PasswordPolicyReferenciaPropertyTest::montar);
    }

    private Arbitrary<String> emailNormalizado() {
        Arbitrary<String> local = Arbitraries.strings().withCharRange('a', 'z').numeric()
                .ofMinLength(1).ofMaxLength(70);
        return local.map(l -> l + "@x.com");
    }

    private Arbitrary<String> emailOuNulo() {
        return Arbitraries.frequencyOf(
                net.jqwik.api.Tuple.of(9, emailNormalizado()),
                net.jqwik.api.Tuple.of(1, Arbitraries.just((String) null)));
    }

    @Provide
    Arbitrary<Caso> casos() {
        Arbitrary<Caso> livre = Combinators.combine(textoLivre(), emailOuNulo()).as(Caso::new);

        // senha igual ao e-mail com caixa e espaços variados
        Arbitrary<Caso> igualEmail = Combinators.combine(
                emailNormalizado(),
                Arbitraries.integers().between(0, 3),
                Arbitraries.integers().between(0, 3),
                Arbitraries.longs())
                .as((email, antes, depois, seed) -> new Caso(
                        " ".repeat(antes) + caixaAleatoria(email, seed) + " ".repeat(depois), email));

        // item da lista de comuns com caixa aleatória, com e-mail aleatório (ou nulo)
        Arbitrary<Caso> comum = Combinators.combine(
                Arbitraries.of(PasswordPolicyProperties.PADRAO),
                Arbitraries.longs(),
                emailOuNulo())
                .as((c, seed, email) -> new Caso(caixaAleatoria(c, seed), email));

        // comum com e-mail coincidente (a regra do e-mail vem antes da lista)
        Arbitrary<Caso> comumIgualEmail = Arbitraries.of(PasswordPolicyProperties.PADRAO)
                .map(c -> new Caso(c.toUpperCase(Locale.ROOT), c));

        // comprimento exato 0..80 de ASCII e de 2 bytes (fronteiras 8/64/72 bytes)
        Arbitrary<Caso> porComprimento = Combinators.combine(
                Arbitraries.integers().between(0, 80),
                Arbitraries.of('a', 'Z', '7', 'é', 'ç', '€'),
                emailOuNulo())
                .as((n, ch, email) -> new Caso(String.valueOf(ch).repeat(n), email));

        return Arbitraries.frequencyOf(
                net.jqwik.api.Tuple.of(4, livre),
                net.jqwik.api.Tuple.of(2, igualEmail),
                net.jqwik.api.Tuple.of(2, comum),
                net.jqwik.api.Tuple.of(1, comumIgualEmail),
                net.jqwik.api.Tuple.of(3, porComprimento));
    }

    // Feature: endurecimento-autenticacao, Property 18: Política de senha concorda com o modelo de referência
    // Validates: Requirements 13.1, 13.3, 13.4, 13.6
    @Property(tries = 500)
    void politicaConcordaComModeloDeReferencia(@ForAll("casos") Caso caso) {
        String esperado = referencia(caso.senha(), caso.email(), PasswordPolicyProperties.PADRAO);

        RegraNegocioException lancada = null;
        try {
            policy.validar(caso.senha(), caso.email(), CAMPO);
        } catch (RegraNegocioException e) {
            lancada = e;
        }

        if (esperado == null) {
            assertThat(lancada).as("senha aceita pelo modelo").isNull();
        } else {
            assertThat(lancada).as("senha rejeitada pelo modelo com %s", esperado).isNotNull();
            assertThat(lancada.getChave()).isEqualTo(esperado);
            assertThat(lancada.getCampo()).isEqualTo(CAMPO);
        }
        // sanidade do gerador: bytes calculados pelo JDK coincidem com o modelo
        if (esperado != null && esperado.equals("senha.bytes.excedido")) {
            assertThat(caso.senha().getBytes(StandardCharsets.UTF_8).length).isGreaterThan(72);
        }
    }
}
