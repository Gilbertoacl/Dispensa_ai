package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import dev.gilberto.gestaousuarios.testsupport.SessaoFixture;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;

class SessaoEmissaoPropertyTest {

    // Feature: endurecimento-autenticacao, Property 3: Emissão de sessão persiste só o hash, em família nova, com a duração configurada
    // Validates: Requirements 1.3, 1.5, 1.6
    @Property(tries = 100)
    void emissaoPersisteSoOHashEmFamiliaNovaComADuracaoConfigurada(
            @ForAll @IntRange(min = 1, max = 10) int logins,
            @ForAll @IntRange(min = 7, max = 30) int dias,
            @ForAll Perfil perfil) {
        Duration duracao = Duration.ofDays(dias);
        SessaoFixture fx = new SessaoFixture(duracao);
        Usuario usuario = fx.novoUsuario(perfil);

        Set<UUID> familias = new HashSet<>();
        for (int i = 0; i < logins; i++) {
            TokenResponse r = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);

            RefreshToken t = fx.store.buscarPorHash(TokenOpaco.hash(r.refreshToken())).orElseThrow();
            assertThat(t.getTokenHash()).isEqualTo(TokenOpaco.hash(r.refreshToken()));
            assertThat(t.getTokenHash()).isNotEqualTo(r.refreshToken());
            assertThat(t.getExpiraEm()).isEqualTo(fx.relogio.instant().plus(duracao));
            assertThat(r.refreshExpiraEm()).isEqualTo(duracao.toSeconds());
            assertThat(t.getUsuarioId()).isEqualTo(usuario.getId());
            assertThat(t.getRevogadoEm()).isNull();
            assertThat(familias.add(t.getFamiliaId())).as("família nova a cada login").isTrue();
            fx.relogio.avancar(Duration.ofMinutes(1));
        }

        List<RefreshToken> todos = fx.store.todos();
        assertThat(todos).hasSize(logins);
        // nenhum refresh token em claro é persistido: nenhum campo do registro contém o valor claro
        assertThat(todos).extracting(RefreshToken::getTokenHash).doesNotHaveDuplicates().allMatch(h -> h.length() == 64);
    }
}
