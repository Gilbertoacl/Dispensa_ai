package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import dev.gilberto.gestaousuarios.testsupport.SessaoFixture;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;

class SessaoLogoutGlobalPropertyTest {

    // Feature: endurecimento-autenticacao, Property 7: Logout global revoga todas as sessões do usuário e somente dele
    // Validates: Requirements 4.4
    @Property(tries = 100)
    void logoutGlobalRevogaTudoDoAlvoEIncrementaTokenVersionSoDele(
            @ForAll @IntRange(min = 2, max = 4) int usuarios,
            @ForAll @IntRange(min = 1, max = 3) int familias,
            @ForAll @IntRange(min = 0, max = 3) int rotacoes,
            @ForAll @IntRange(min = 0, max = 3) int alvo,
            @ForAll @IntRange(min = 0, max = 50) int tvInicial) {
        SessaoFixture fx = new SessaoFixture();
        List<Usuario> lista = new ArrayList<>();
        for (int u = 0; u < usuarios; u++) {
            Usuario usuario = fx.novoUsuario(Perfil.USER);
            fx.definirTokenVersion(usuario, tvInicial + u);
            lista.add(usuario);
            for (int f = 0; f < familias; f++) {
                String token = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE).refreshToken();
                for (int r = 0; r < rotacoes; r++) {
                    token = fx.sessao.renovar(token, SessaoFixture.CLIENTE).refreshToken();
                }
            }
        }
        Usuario alvoUsuario = lista.get(alvo % usuarios);
        List<Integer> tvAntes = lista.stream().map(Usuario::getTokenVersion).toList();
        Instant agora = fx.relogio.instant();
        long ativosOutrosAntes = fx.store.todos().stream()
                .filter(t -> !t.getUsuarioId().equals(alvoUsuario.getId()) && t.ativoEm(agora)).count();
        assertThat(fx.store.doUsuario(alvoUsuario.getId()).stream().filter(t -> t.ativoEm(agora)).count())
                .isEqualTo(familias);

        fx.sessao.encerrarTodas(alvoUsuario.getId());

        assertThat(fx.store.doUsuario(alvoUsuario.getId())).allMatch(t -> t.getRevogadoEm() != null);
        assertThat(fx.store.doUsuario(alvoUsuario.getId()).stream().filter(t -> t.ativoEm(agora)).count()).isZero();
        for (int i = 0; i < lista.size(); i++) {
            int esperado = lista.get(i) == alvoUsuario ? tvAntes.get(i) + 1 : tvAntes.get(i);
            assertThat(lista.get(i).getTokenVersion()).isEqualTo(esperado);
        }
        long ativosOutrosDepois = fx.store.todos().stream()
                .filter(t -> !t.getUsuarioId().equals(alvoUsuario.getId()) && t.ativoEm(agora)).count();
        assertThat(ativosOutrosDepois).isEqualTo(ativosOutrosAntes);
    }
}
