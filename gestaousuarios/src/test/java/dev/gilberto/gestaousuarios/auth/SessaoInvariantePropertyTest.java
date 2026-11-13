package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import dev.gilberto.gestaousuarios.shared.exceptions.TokenInvalidoException;
import dev.gilberto.gestaousuarios.testsupport.SessaoFixture;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;

class SessaoInvariantePropertyTest {

    // Feature: endurecimento-autenticacao, Property 4: Invariante da sessão sob qualquer sequência de operações
    // Validates: Requirements 2.2, 2.3, 2.5, 2.7, 4.1, 4.2
    @Property(tries = 200)
    void invarianteDaSessaoSobQualquerSequenciaDeOperacoes(
            @ForAll @Size(min = 1, max = 40) List<@IntRange(min = 0, max = 5999) Integer> passos) {
        SessaoFixture fx = new SessaoFixture();
        Usuario usuario = fx.novoUsuario(Perfil.USER);
        // hash -> valor claro, de todo token já emitido
        Map<String, String> claros = new HashMap<>();
        // revogadoEm observado de cada token, para garantir que revogação nunca é desfeita
        Map<UUID, Instant> revogacoes = new HashMap<>();

        for (int passo : passos) {
            int op = passo % 6;
            int sel = passo / 6;
            Instant agora = fx.relogio.instant();
            switch (op) {
                case 0 -> registrar(claros, fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE));
                case 1 -> escolher(ativosClaros(fx, claros, agora), sel).ifPresent(c -> registrar(claros,
                        fx.sessao.renovar(c, SessaoFixture.CLIENTE)));
                case 2 -> escolher(new ArrayList<>(claros.values()), sel).ifPresent(c -> {
                    try {
                        registrar(claros, fx.sessao.renovar(c, SessaoFixture.CLIENTE));
                    } catch (TokenInvalidoException esperado) {
                        // rejeição é um resultado legítimo
                    }
                });
                case 3 -> escolher(ativosClaros(fx, claros, agora), sel).ifPresent(fx.sessao::encerrar);
                case 4 -> escolher(new ArrayList<>(claros.values()), sel).ifPresent(fx.sessao::encerrar);
                default -> fx.relogio.avancar(Duration.ofHours(1 + sel % 72));
            }
            verificar(fx, revogacoes);
        }
    }

    private static void registrar(Map<String, String> claros, TokenResponse r) {
        claros.put(TokenOpaco.hash(r.refreshToken()), r.refreshToken());
    }

    private static List<String> ativosClaros(SessaoFixture fx, Map<String, String> claros, Instant agora) {
        return fx.store.todos().stream().filter(t -> t.ativoEm(agora))
                .map(t -> claros.get(t.getTokenHash())).collect(Collectors.toList());
    }

    private static java.util.Optional<String> escolher(List<String> lista, int sel) {
        return lista.isEmpty() ? java.util.Optional.empty() : java.util.Optional.of(lista.get(sel % lista.size()));
    }

    private static void verificar(SessaoFixture fx, Map<UUID, Instant> revogacoes) {
        Instant agora = fx.relogio.instant();
        Map<UUID, Long> ativosPorFamilia = fx.store.todos().stream().filter(t -> t.ativoEm(agora))
                .collect(Collectors.groupingBy(RefreshToken::getFamiliaId, Collectors.counting()));
        assertThat(ativosPorFamilia.values()).allMatch(n -> n <= 1);
        for (RefreshToken t : fx.store.todos()) {
            // token rotacionado nunca fica ativo
            if (t.getSubstituidoPorId() != null) {
                assertThat(t.getRevogadoEm()).isNotNull();
            }
            // revogação é permanente
            Instant anterior = revogacoes.get(t.getId());
            if (anterior != null) {
                assertThat(t.getRevogadoEm()).isEqualTo(anterior);
            }
            if (t.getRevogadoEm() != null) {
                revogacoes.put(t.getId(), t.getRevogadoEm());
            }
        }
    }
}
