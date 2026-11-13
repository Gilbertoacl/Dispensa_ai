package dev.gilberto.gestaousuarios.usuario;

import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.StringLength;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Testes de propriedade (jqwik) para {@link UsuarioService}.
 */
class UsuarioServicePropertyTest {

    // Feature: gestao-usuarios-autenticacao, Property 9: Metadados de paginação são consistentes
    @Property(tries = 100)
    void metadadosDePaginacaoConsistentes(@ForAll @IntRange(min = 0, max = 50) int n,
                                          @ForAll @IntRange(min = 1, max = 20) int size,
                                          @ForAll @IntRange(min = 0, max = 5) int page) {
        UsuarioRepository usuarioRepository = mock(UsuarioRepository.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        UsuarioService service = new UsuarioService(usuarioRepository, passwordEncoder);

        // Base de N usuários
        List<Usuario> todos = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            todos.add(new Usuario("u" + i + "@x.com", "n", "h", Perfil.USER));
        }

        // Sublista correspondente à página solicitada
        int fromIndex = page * size;
        List<Usuario> subLista;
        if (fromIndex >= n) {
            subLista = new ArrayList<>();
        } else {
            int toIndex = Math.min(fromIndex + size, n);
            subLista = new ArrayList<>(todos.subList(fromIndex, toIndex));
        }

        Pageable pageable = PageRequest.of(page, size);
        Page<Usuario> pageEntidade = new PageImpl<>(subLista, pageable, n);
        when(usuarioRepository.findAll(any(Pageable.class))).thenReturn(pageEntidade);

        Page<UsuarioResponse> resultado = service.listar(PageRequest.of(page, size));

        int totalPagesEsperado = (n == 0) ? 0 : (int) Math.ceil((double) n / size);

        assertThat(resultado.getTotalElements()).isEqualTo(n);
        assertThat(resultado.getTotalPages()).isEqualTo(totalPagesEsperado);
        assertThat(resultado.getSize()).isEqualTo(size);
        assertThat(resultado.getNumberOfElements()).isLessThanOrEqualTo(size);
        assertThat(resultado.getContent()).hasSameSizeAs(subLista);
    }

    // Feature: gestao-usuarios-autenticacao, Property 10: Troca de senha rejeitada preserva o hash
    @Property(tries = 100)
    void trocaDeSenhaComSenhaAtualIncorretaPreservaHash(@ForAll String senhaAtual,
                                                        @ForAll @StringLength(min = 8, max = 64) String novaSenha) {
        UsuarioRepository usuarioRepository = mock(UsuarioRepository.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        UsuarioService service = new UsuarioService(usuarioRepository, passwordEncoder);

        UUID id = UUID.randomUUID();
        Usuario usuario = new Usuario("u@x.com", "n", "HASH_ORIGINAL", Perfil.USER);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(usuario));

        // Senha atual incorreta
        when(passwordEncoder.matches(senhaAtual, "HASH_ORIGINAL")).thenReturn(false);

        assertThatThrownBy(() -> service.trocarSenha(id, senhaAtual, novaSenha))
                .isInstanceOf(RegraNegocioException.class);

        assertThat(usuario.getSenhaHash()).isEqualTo("HASH_ORIGINAL");
        verify(usuarioRepository, never()).save(any());
    }

    // Feature: gestao-usuarios-autenticacao, Property 10: Troca de senha rejeitada preserva o hash
    @Property(tries = 100)
    void trocaDeSenhaComNovaIgualAtualPreservaHash(@ForAll String senhaAtual,
                                                   @ForAll @StringLength(min = 8, max = 64) String novaSenha) {
        UsuarioRepository usuarioRepository = mock(UsuarioRepository.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        UsuarioService service = new UsuarioService(usuarioRepository, passwordEncoder);

        UUID id = UUID.randomUUID();
        Usuario usuario = new Usuario("u@x.com", "n", "HASH_ORIGINAL", Perfil.USER);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(usuario));

        // Senha atual correta, mas a nova senha também corresponde ao hash atual (igual à atual)
        when(passwordEncoder.matches(senhaAtual, "HASH_ORIGINAL")).thenReturn(true);
        when(passwordEncoder.matches(novaSenha, "HASH_ORIGINAL")).thenReturn(true);

        assertThatThrownBy(() -> service.trocarSenha(id, senhaAtual, novaSenha))
                .isInstanceOf(RegraNegocioException.class);

        assertThat(usuario.getSenhaHash()).isEqualTo("HASH_ORIGINAL");
        verify(usuarioRepository, never()).save(any());
    }
}
