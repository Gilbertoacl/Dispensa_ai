package dev.gilberto.gestaousuarios.usuarios;

import dev.gilberto.gestaousuarios.shared.exceptions.RecursoNaoEncontradoException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import dev.gilberto.gestaousuarios.usuario.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UsuarioServiceTest {
    @Mock
    private UsuarioRepository usuarioRepository;

    @InjectMocks
    private UsuarioService usuarioService;

    private UsuarioRequest requestValido(){
        return new UsuarioRequest("mail@mail.com", "João das Neves", "123456789");
    }

    @Test
    void deveCriarUsuarioComSucesso(){
        UsuarioRequest request = requestValido();

        when(usuarioRepository.findByEmail(request.email())).thenReturn(Optional.empty());
        when(usuarioRepository.save(any(Usuario.class))).thenAnswer(invocation -> {
            return invocation.getArgument(0);
        });

        UsuarioResponse response = usuarioService.criarUsuario(request);

        assertThat(response.email()).isNotNull();
        assertThat(response.nome()).isEqualTo("João das Neves");
        assertThat(response.email()).isEqualTo("mail@mail.com");
        verify(usuarioRepository).save(any(Usuario.class));
    }

    @Test
    void deveLancarExcecaoAoCriarUsuarioComEmailJaRegistrado() {
        UsuarioRequest request = requestValido();
        when(usuarioRepository.findByEmail(request.email())).thenReturn(Optional.of(new Usuario(request.email(),request.nome(),request.senha())));
        assertThatThrownBy(() -> usuarioService.criarUsuario(request))
                .isInstanceOf(RecursoNaoEncontradoException.class)
                .hasMessage(Mensagens.get("user.email.registrado"));

    }

    @Test
    void deveBuscarUsuarioPorIdComSucesso(){
        UUID id = UUID.randomUUID();
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(new Usuario("mail@mail.com", "João das Neves", "123456789")));

        UsuarioResponse response = usuarioService.buscarUsuarioPorId(id);
        assertThat(response.email()).isEqualTo("mail@mail.com");
        assertThat(response.nome()).isEqualTo("João das Neves");
    }

    @Test
    void deveLancarExcesaoAoBuscarUsuarioPorIdInexistente() {
        UUID id = UUID.randomUUID();
        when(usuarioRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(()-> usuarioService.buscarUsuarioPorId(id))
                .isInstanceOf(RecursoNaoEncontradoException.class)
                .hasMessage(Mensagens.get("user.nao.encontrado"));
    }
}
