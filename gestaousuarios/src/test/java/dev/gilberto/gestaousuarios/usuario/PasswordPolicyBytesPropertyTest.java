package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.List;

import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class PasswordPolicyBytesPropertyTest {

    private final PasswordPolicy policy = PasswordPolicy.padrao();

    /** Strings Unicode com code points de 1, 2, 3 e 4 bytes em UTF-8 (sem substitutos soltos). */
    @Provide
    Arbitrary<String> textos() {
        Arbitrary<Integer> um = Arbitraries.integers().between(0x21, 0x7E);
        Arbitrary<Integer> dois = Arbitraries.integers().between(0xA0, 0x7FF);
        Arbitrary<Integer> tres = Arbitraries.integers().between(0x800, 0xD7FF);
        Arbitrary<Integer> quatro = Arbitraries.integers().between(0x10000, 0x10FFFF);
        Arbitrary<Integer> cp = Arbitraries.frequencyOf(
                net.jqwik.api.Tuple.of(4, um), net.jqwik.api.Tuple.of(4, dois),
                net.jqwik.api.Tuple.of(2, tres), net.jqwik.api.Tuple.of(2, quatro));
        return cp.list().ofMinSize(0).ofMaxSize(80).map(PasswordPolicyBytesPropertyTest::montar);
    }

    private static String montar(List<Integer> pontos) {
        StringBuilder sb = new StringBuilder();
        pontos.forEach(sb::appendCodePoint);
        return sb.toString();
    }

    private static int bytesPorCodePoint(String s) {
        return s.codePoints().map(c -> c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4).sum();
    }

    // Feature: endurecimento-autenticacao, Property 17: Limite de 72 bytes da senha
    // Validates: Requirements 13.2, 13.9
    @Property(tries = 300)
    void dentroDoLimiteEquivaleASomaDeBytesMenorOuIgualA72(@ForAll("textos") String s) {
        int bytes = bytesPorCodePoint(s);
        assertThat(s.getBytes(StandardCharsets.UTF_8)).hasSize(bytes);
        assertThat(PasswordPolicy.dentroDoLimiteDeBytes(s)).isEqualTo(bytes <= 72);
    }

    // Feature: endurecimento-autenticacao, Property 17: Limite de 72 bytes da senha
    // Validates: Requirements 13.2, 13.9
    @Property(tries = 300)
    void validarRejeitaAcimaDe72BytesComTamanhoValidoEAceitaAbaixo(@ForAll("textos") String s) {
        boolean tamanhoOk = s.length() >= 8 && s.length() <= 64;
        int bytes = bytesPorCodePoint(s);
        if (!tamanhoOk) {
            return; // fora do escopo desta propriedade (coberto pela Property 18)
        }
        if (bytes > 72) {
            assertThatThrownBy(() -> policy.validar(s, null, "senha"))
                    .isInstanceOfSatisfying(RegraNegocioException.class, e -> {
                        assertThat(e.getChave()).isEqualTo("senha.bytes.excedido");
                        assertThat(e.getCampo()).isEqualTo("senha");
                    });
        } else {
            assertThatCode(() -> policy.validar(s, null, "senha")).doesNotThrowAnyException();
        }
    }
}
