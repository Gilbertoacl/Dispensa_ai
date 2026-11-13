package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;
import net.jqwik.api.constraints.UniqueElements;

class TokenOpacoPropertyTest {

    private static final SecureRandom RND = new SecureRandom();

    // Feature: endurecimento-autenticacao, Property 2: Formato e determinismo do token opaco
    // Validates: Requirements 1.4, 2.12
    @Property(tries = 100)
    void lotesDeTokensTemFormatoValidoSaoDistintosEHashDistintoDoClaro(@ForAll @IntRange(min = 1, max = 50) int tamanho) {
        Set<String> tokens = new HashSet<>();
        Set<String> hashes = new HashSet<>();
        for (int i = 0; i < tamanho; i++) {
            String token = TokenOpaco.gerar(RND);
            assertThat(token).hasSize(43).matches("[A-Za-z0-9_-]{43}");
            assertThat(java.util.Base64.getUrlDecoder().decode(token)).hasSize(32);

            String hash = TokenOpaco.hash(token);
            assertThat(hash).hasSize(64).matches("[0-9a-f]{64}");
            assertThat(hash).isNotEqualTo(token);
            assertThat(TokenOpaco.hash(token)).isEqualTo(hash);

            tokens.add(token);
            hashes.add(hash);
        }
        assertThat(tokens).hasSize(tamanho);
        assertThat(hashes).hasSize(tamanho);
    }

    // Feature: endurecimento-autenticacao, Property 2: Formato e determinismo do token opaco
    // Validates: Requirements 1.4, 2.12
    @Property(tries = 200)
    void hashDeQualquerStringUnicodeEHexDe64DeterministicoEDiferenteDoClaro(@ForAll String claro) {
        String hash = TokenOpaco.hash(claro);
        assertThat(hash).hasSize(64).matches("[0-9a-f]{64}");
        assertThat(TokenOpaco.hash(claro)).isEqualTo(hash);
        assertThat(hash).isNotEqualTo(claro);
    }

    // Feature: endurecimento-autenticacao, Property 2: Formato e determinismo do token opaco
    // Validates: Requirements 1.4, 2.12
    @Property(tries = 100)
    void entradasDistintasGeramHashesDistintos(@ForAll @Size(min = 2, max = 20) @UniqueElements List<String> entradas) {
        Set<String> hashes = new HashSet<>();
        for (String e : entradas) {
            hashes.add(TokenOpaco.hash(e));
        }
        assertThat(hashes).hasSize(entradas.size());
    }
}
