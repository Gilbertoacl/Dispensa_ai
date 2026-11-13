package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.test.util.ReflectionTestUtils;

import dev.gilberto.gestaousuarios.shared.exceptions.ConflitoException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;

class UltimoAdminPropertyTest {

    /** Repositório em memória consistente com findById/save/travarPorPerfil/incrementarTokenVersion. */
    private static UsuarioRepository repoEmMemoria(Map<UUID, Usuario> base) {
        UsuarioRepository repo = mock(UsuarioRepository.class);
        when(repo.findById(any(UUID.class))).thenAnswer(i -> Optional.ofNullable(base.get(i.<UUID>getArgument(0))));
        when(repo.save(any(Usuario.class))).thenAnswer(i -> {
            Usuario u = i.getArgument(0);
            base.put(u.getId(), u);
            return u;
        });
        when(repo.travarPorPerfil(any(Perfil.class))).thenAnswer(i -> {
            Perfil p = i.getArgument(0);
            List<Usuario> r = new ArrayList<>();
            for (Usuario u : base.values()) {
                if (u.getPerfil() == p) {
                    r.add(u);
                }
            }
            return r;
        });
        when(repo.incrementarTokenVersion(any(UUID.class))).thenAnswer(i -> {
            Usuario u = base.get(i.<UUID>getArgument(0));
            ReflectionTestUtils.setField(u, "tokenVersion", u.getTokenVersion() + 1);
            return 1;
        });
        return repo;
    }

    private static long admins(Map<UUID, Usuario> base) {
        return base.values().stream().filter(u -> u.getPerfil() == Perfil.ADMIN).count();
    }

    // Feature: endurecimento-autenticacao, Property 11: Nenhuma sequência de mudanças de perfil remove o último ADMIN
    // Validates: Requirements 7.5
    @Property(tries = 200)
    void nenhumaSequenciaDeMudancasRemoveOUltimoAdmin(
            @ForAll @IntRange(min = 1, max = 6) int totalUsuarios,
            @ForAll @IntRange(min = 1, max = 6) int adminsIniciais,
            @ForAll @Size(min = 1, max = 40) List<@IntRange(min = 0, max = 5) Integer> alvos,
            @ForAll @Size(min = 1, max = 40) List<Perfil> novos,
            @ForAll @Size(min = 1, max = 40) List<@IntRange(min = 0, max = 5) Integer> executores) {
        int nAdmins = Math.min(adminsIniciais, totalUsuarios);
        Map<UUID, Usuario> base = new LinkedHashMap<>();
        List<UUID> ids = new ArrayList<>();
        for (int i = 0; i < totalUsuarios; i++) {
            Usuario u = new Usuario("u" + i + "@x.com", "n", "h", i < nAdmins ? Perfil.ADMIN : Perfil.USER);
            UUID id = UUID.randomUUID();
            ReflectionTestUtils.setField(u, "id", id);
            base.put(id, u);
            ids.add(id);
        }
        UsuarioService service = new UsuarioService(repoEmMemoria(base), mock(org.springframework.security.crypto.password.PasswordEncoder.class));

        int passos = Math.min(alvos.size(), Math.min(novos.size(), executores.size()));
        for (int k = 0; k < passos; k++) {
            UUID alvo = ids.get(alvos.get(k) % totalUsuarios);
            UUID executor = ids.get(executores.get(k) % totalUsuarios);
            Perfil novo = novos.get(k);
            Perfil anterior = base.get(alvo).getPerfil();
            long antes = admins(base);
            int tvAntes = base.get(alvo).getTokenVersion();

            boolean rebaixaUnico = anterior == Perfil.ADMIN && novo == Perfil.USER && antes == 1;
            if (rebaixaUnico) {
                assertThatThrownBy(() -> service.alterarPerfil(alvo, novo, executor))
                        .isInstanceOf(ConflitoException.class)
                        .hasMessage(Mensagens.get("perfil.ultimo.admin"));
                assertThat(base.get(alvo).getPerfil()).isEqualTo(Perfil.ADMIN);
                assertThat(base.get(alvo).getTokenVersion()).isEqualTo(tvAntes);
                assertThat(admins(base)).isEqualTo(antes);
            } else {
                service.alterarPerfil(alvo, novo, executor);
                assertThat(base.get(alvo).getPerfil()).isEqualTo(novo);
            }
            assertThat(admins(base)).as("passo %d", k).isGreaterThanOrEqualTo(1);
        }
    }
}
