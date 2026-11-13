package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.security.oauth2.jwt.Jwt;

import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class TokenVersionValidatorPropertyTest {

    private static Jwt jwt(UUID sub, Object tv) {
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "HS256")
                .subject(sub.toString())
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(600));
        if (tv != null) {
            b.claim("tv", tv);
        }
        return b.build();
    }

    @Provide
    Arbitrary<Integer> versoes() {
        return Arbitraries.integers().between(0, 1_000_000);
    }

    // Feature: endurecimento-autenticacao, Property 8: Validador de tokenVersion aceita se e somente se a versão confere (monotonicidade)
    // Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.10
    @Property(tries = 200)
    void aposKIncrementosTokenAntigoERejeitadoEIgualAoCorrenteEAceito(
            @ForAll("versoes") int n,
            @ForAll @net.jqwik.api.constraints.IntRange(min = 1, max = 50) int k) {
        UUID id = UUID.randomUUID();
        AtomicInteger atual = new AtomicInteger(n);
        UsuarioRepository repo = mock(UsuarioRepository.class);
        when(repo.buscarTokenVersion(id)).thenAnswer(i -> Optional.of(atual.get()));
        TokenVersionValidator v = new TokenVersionValidator(repo);

        Jwt emitidoEmN = jwt(id, n);
        assertThat(v.validate(emitidoEmN).hasErrors()).isFalse();

        // monotonicidade: a cada incremento, o token antigo permanece rejeitado
        for (int i = 1; i <= k; i++) {
            atual.incrementAndGet();
            assertThat(v.validate(emitidoEmN).hasErrors()).as("tv=%d, atual=%d", n, atual.get()).isTrue();
            assertThat(v.validate(emitidoEmN).getErrors().iterator().next().getDescription())
                    .isEqualTo(TokenVersionValidator.DESCRICAO_REVOGADO);
        }
        // token com tv igual ao corrente é aceito
        assertThat(v.validate(jwt(id, n + k)).hasErrors()).isFalse();
        // tokens de qualquer versão diferente da corrente são rejeitados
        assertThat(v.validate(jwt(id, n + k + 1)).hasErrors()).isTrue();
    }

    // Feature: endurecimento-autenticacao, Property 8: Validador de tokenVersion aceita se e somente se a versão confere (monotonicidade)
    // Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.10
    @Property(tries = 200)
    void aceitaSeESomenteSeVersaoConfere(
            @ForAll("versoes") int tv,
            @ForAll("versoes") int atual,
            @ForAll boolean usuarioExiste) {
        UUID id = UUID.randomUUID();
        UsuarioRepository repo = mock(UsuarioRepository.class);
        when(repo.buscarTokenVersion(id))
                .thenReturn(usuarioExiste ? Optional.of(atual) : Optional.empty());
        TokenVersionValidator v = new TokenVersionValidator(repo);

        boolean ok = !v.validate(jwt(id, tv)).hasErrors();

        assertThat(ok).isEqualTo(usuarioExiste && tv == atual);
        verify(repo, times(1)).buscarTokenVersion(id);
    }

    // Feature: endurecimento-autenticacao, Property 8: Validador de tokenVersion aceita se e somente se a versão confere (monotonicidade)
    // Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.10
    @Property(tries = 100)
    void claimAusenteOuNaoInteiraSempreRejeitadaSemConsulta(
            @ForAll("claimsInvalidas") Optional<Object> claim) {
        UUID id = UUID.randomUUID();
        UsuarioRepository repo = mock(UsuarioRepository.class);
        TokenVersionValidator v = new TokenVersionValidator(repo);

        assertThat(v.validate(jwt(id, claim.orElse(null))).hasErrors()).isTrue();
        verify(repo, times(0)).buscarTokenVersion(any());
    }

    @Provide
    Arbitrary<Optional<Object>> claimsInvalidas() {
        Arbitrary<Object> strings = Arbitraries.strings().numeric().ofMinLength(1).ofMaxLength(5).map(s -> (Object) s);
        Arbitrary<Object> doubles = Arbitraries.doubles().between(-1000, 1000).map(d -> (Object) (d + 0.5));
        Arbitrary<Object> foraDeInt = Arbitraries.longs()
                .filter(l -> l > Integer.MAX_VALUE || l < Integer.MIN_VALUE).map(l -> (Object) l);
        return Arbitraries.oneOf(
                Arbitraries.just(Optional.<Object>empty()),
                strings.map(Optional::of), doubles.map(Optional::of), foraDeInt.map(Optional::of));
    }
}
