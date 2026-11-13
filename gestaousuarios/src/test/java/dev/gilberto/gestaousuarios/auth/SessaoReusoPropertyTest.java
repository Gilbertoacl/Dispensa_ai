package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;
import dev.gilberto.gestaousuarios.shared.exceptions.TokenReutilizadoException;
import dev.gilberto.gestaousuarios.testsupport.SessaoFixture;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;

class SessaoReusoPropertyTest {

    private record Estado(Object revogadoEm, Object motivo, Object substituidoPor) { }

    // Feature: endurecimento-autenticacao, Property 5: Reuso revoga a família inteira, e somente ela
    // Validates: Requirements 3.1, 3.2, 3.4, 3.5
    @Property(tries = 100)
    void reusoRevogaAFamiliaInteiraESomenteEla(
            @ForAll @IntRange(min = 1, max = 4) int familias,
            @ForAll @IntRange(min = 1, max = 5) int rotacoes,
            @ForAll @IntRange(min = 0, max = 3) int alvo,
            @ForAll @IntRange(min = 0, max = 4) int indiceReapresentado) {
        SessaoFixture fx = new SessaoFixture();
        Usuario usuario = fx.novoUsuario(Perfil.USER);

        // para cada família: todos os claros emitidos, em ordem (o último é o vigente)
        List<List<String>> historico = new ArrayList<>();
        for (int f = 0; f < familias; f++) {
            List<String> tokens = new ArrayList<>();
            tokens.add(fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE).refreshToken());
            for (int r = 0; r < rotacoes; r++) {
                tokens.add(fx.sessao.renovar(tokens.get(tokens.size() - 1), SessaoFixture.CLIENTE).refreshToken());
            }
            historico.add(tokens);
        }

        int fAlvo = alvo % familias;
        List<String> tokensAlvo = historico.get(fAlvo);
        String reapresentado = tokensAlvo.get(indiceReapresentado % rotacoes); // sempre um já rotacionado
        UUID familiaAlvo = fx.store.buscarPorHash(TokenOpaco.hash(reapresentado)).orElseThrow().getFamiliaId();
        Map<UUID, Estado> antesOutras = new HashMap<>();
        for (RefreshToken t : fx.store.todos()) {
            if (!t.getFamiliaId().equals(familiaAlvo)) {
                antesOutras.put(t.getId(), new Estado(t.getRevogadoEm(), t.getMotivoRevogacao(),
                        t.getSubstituidoPorId()));
            }
        }

        assertThatThrownBy(() -> fx.sessao.renovar(reapresentado, SessaoFixture.CLIENTE))
                .isInstanceOf(TokenReutilizadoException.class);

        // a família inteira ficou sem token ativo, inclusive o vigente
        assertThat(fx.store.daFamilia(familiaAlvo)).allMatch(t -> !t.ativoEm(fx.relogio.instant()));
        assertThat(fx.store.buscarPorHash(TokenOpaco.hash(tokensAlvo.get(tokensAlvo.size() - 1))).orElseThrow()
                .getRevogadoEm()).isNotNull();
        // as demais famílias seguem idênticas e ativas
        Map<UUID, Estado> depoisOutras = new HashMap<>();
        for (RefreshToken t : fx.store.todos()) {
            if (!t.getFamiliaId().equals(familiaAlvo)) {
                depoisOutras.put(t.getId(), new Estado(t.getRevogadoEm(), t.getMotivoRevogacao(),
                        t.getSubstituidoPorId()));
            }
        }
        assertThat(depoisOutras).isEqualTo(antesOutras);
        for (int f = 0; f < familias; f++) {
            if (f != fAlvo) {
                String vigente = historico.get(f).get(historico.get(f).size() - 1);
                assertThat(fx.store.buscarPorHash(TokenOpaco.hash(vigente)).orElseThrow()
                        .ativoEm(fx.relogio.instant())).isTrue();
            }
        }
        assertThat(fx.auditoria.eventosDo(TipoEventoSeguranca.REFRESH_REUSO_DETECTADO)).hasSize(1);
        assertThat(fx.auditoria.eventosDo(TipoEventoSeguranca.REFRESH_REUSO_DETECTADO).get(0).detalhe())
                .contains(familiaAlvo.toString());
    }
}
