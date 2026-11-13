package dev.gilberto.gestaousuarios.usuarios;

import dev.gilberto.gestaousuarios.shared.exceptions.ConflitoException;
import dev.gilberto.gestaousuarios.shared.exceptions.RecursoNaoEncontradoException;
import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import dev.gilberto.gestaousuarios.usuario.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import dev.gilberto.gestaousuarios.auditoria.AuditoriaSeguranca;
import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;
import dev.gilberto.gestaousuarios.auth.MotivoRevogacao;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UsuarioServiceTest {

    @Mock
    private UsuarioRepository usuarioRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UsuarioService usuarioService;

    private UsuarioRequest requestValido() {
        return new UsuarioRequest("mail@mail.com", "João das Neves", "Dispensa#2024");
    }

    // ---------- criarUsuario ----------

    @Test
    void deveCriarUsuarioComSucesso() {
        UsuarioRequest request = requestValido();

        when(usuarioRepository.existsByEmail("mail@mail.com")).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("HASH");
        when(usuarioRepository.save(any(Usuario.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        UsuarioResponse response = usuarioService.criarUsuario(request);

        assertThat(response.email()).isEqualTo("mail@mail.com");
        assertThat(response.nome()).isEqualTo("João das Neves");
        assertThat(response.perfil()).isEqualTo(Perfil.USER);
        verify(usuarioRepository).save(any(Usuario.class));
    }

    @Test
    void deveLancarConflitoAoCriarUsuarioComEmailJaRegistrado() {
        UsuarioRequest request = requestValido();

        when(usuarioRepository.existsByEmail("mail@mail.com")).thenReturn(true);

        assertThatThrownBy(() -> usuarioService.criarUsuario(request))
                .isInstanceOf(ConflitoException.class)
                .hasMessage(Mensagens.get("user.email.registrado"));

        verify(usuarioRepository, never()).save(any(Usuario.class));
    }

    @Test
    void deveCriarSempreComPerfilUser() {
        UsuarioRequest request = new UsuarioRequest("mail@mail.com", "João das Neves", "Dispensa#2024");

        when(usuarioRepository.existsByEmail("mail@mail.com")).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("HASH");
        when(usuarioRepository.save(any(Usuario.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        UsuarioResponse response = usuarioService.criarUsuario(request);

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).save(captor.capture());

        assertThat(captor.getValue().getPerfil()).isEqualTo(Perfil.USER);
        assertThat(response.perfil()).isEqualTo(Perfil.USER);
    }

    // ---------- buscarPorId ----------

    @Test
    void deveBuscarUsuarioPorIdComSucesso() {
        UUID id = UUID.randomUUID();
        Usuario usuario = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(usuario));

        UsuarioResponse response = usuarioService.buscarPorId(id);

        assertThat(response.email()).isEqualTo("mail@mail.com");
        assertThat(response.nome()).isEqualTo("João");
        assertThat(response.perfil()).isEqualTo(Perfil.USER);
    }

    @Test
    void deveLancarExcecaoAoBuscarUsuarioPorIdInexistente() {
        UUID id = UUID.randomUUID();
        when(usuarioRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> usuarioService.buscarPorId(id))
                .isInstanceOf(RecursoNaoEncontradoException.class)
                .hasMessage(Mensagens.get("user.nao.encontrado"));
    }

    // ---------- atualizarNome ----------

    @Test
    void deveLancarAoAtualizarNomeDeUsuarioInexistente() {
        UUID id = UUID.randomUUID();
        when(usuarioRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> usuarioService.atualizarNome(id, "Novo Nome"))
                .isInstanceOf(RecursoNaoEncontradoException.class)
                .hasMessage(Mensagens.get("user.nao.encontrado"));

        verify(usuarioRepository, never()).save(any(Usuario.class));
    }

    // ---------- trocarSenha ----------

    @Test
    void deveLancarAoTrocarSenhaDeUsuarioInexistente() {
        UUID id = UUID.randomUUID();
        when(usuarioRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> usuarioService.trocarSenha(id, "senhaAtual", "novaSenha123"))
                .isInstanceOf(RecursoNaoEncontradoException.class)
                .hasMessage(Mensagens.get("user.nao.encontrado"));

        verify(usuarioRepository, never()).save(any(Usuario.class));
    }

    @Test
    void deveLancarQuandoSenhaAtualIncorreta() {
        UUID id = UUID.randomUUID();
        Usuario usuario = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senhaAtual", "HASH")).thenReturn(false);

        assertThatThrownBy(() -> usuarioService.trocarSenha(id, "senhaAtual", "novaSenha123"))
                .isInstanceOf(RegraNegocioException.class)
                .hasMessage(Mensagens.get("user.password.invalid"));

        verify(usuarioRepository, never()).save(any(Usuario.class));
        assertThat(usuario.getSenhaHash()).isEqualTo("HASH");
    }

    @Test
    void deveLancarQuandoNovaSenhaForaDoTamanho() {
        UUID id = UUID.randomUUID();
        Usuario usuario = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senhaAtual", "HASH")).thenReturn(true);

        assertThatThrownBy(() -> usuarioService.trocarSenha(id, "senhaAtual", "123"))
                .isInstanceOf(RegraNegocioException.class)
                .hasMessage(Mensagens.get("password.tamanho"));

        verify(usuarioRepository, never()).save(any(Usuario.class));
    }

    @Test
    void deveLancarQuandoNovaSenhaIgualAtual() {
        UUID id = UUID.randomUUID();
        Usuario usuario = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senhaAtual", "HASH")).thenReturn(true);
        when(passwordEncoder.matches("novaSenha123", "HASH")).thenReturn(true);

        assertThatThrownBy(() -> usuarioService.trocarSenha(id, "senhaAtual", "novaSenha123"))
                .isInstanceOf(RegraNegocioException.class)
                .hasMessage(Mensagens.get("password.nova.igual"));

        verify(usuarioRepository, never()).save(any(Usuario.class));
    }

    @Test
    void deveTrocarSenhaComSucesso() {
        UUID id = UUID.randomUUID();
        Usuario usuario = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senhaAtual", "HASH")).thenReturn(true);
        when(passwordEncoder.matches("novaSenha123", "HASH")).thenReturn(false);
        when(passwordEncoder.encode("novaSenha123")).thenReturn("NOVOHASH");

        usuarioService.trocarSenha(id, "senhaAtual", "novaSenha123");

        verify(usuarioRepository).save(usuario);
        assertThat(usuario.getSenhaHash()).isEqualTo("NOVOHASH");
    }

    // ---------- excluir ----------

    @Test
    void deveLancarAoExcluirUsuarioInexistente() {
        UUID id = UUID.randomUUID();
        when(usuarioRepository.existsById(id)).thenReturn(false);

        assertThatThrownBy(() -> usuarioService.excluir(id))
                .isInstanceOf(RecursoNaoEncontradoException.class)
                .hasMessage(Mensagens.get("user.nao.encontrado"));

        verify(usuarioRepository, never()).deleteById(any(UUID.class));
    }

    @Test
    void deveExcluirComSucesso() {
        UUID id = UUID.randomUUID();
        when(usuarioRepository.existsById(id)).thenReturn(true);

        usuarioService.excluir(id);

        verify(usuarioRepository).deleteById(eq(id));
    }

    // ---------- política de senha, perfil e revogação de sessões ----------

    @Test
    void deveRejeitarSenhaComumNoCadastro() {
        UsuarioRequest request = new UsuarioRequest("mail@mail.com", "João", "12345678");
        when(usuarioRepository.existsByEmail("mail@mail.com")).thenReturn(false);

        assertThatThrownBy(() -> usuarioService.criarUsuario(request))
                .isInstanceOf(RegraNegocioException.class)
                .hasMessage(Mensagens.get("senha.comum"));

        verify(usuarioRepository, never()).save(any(Usuario.class));
    }

    @Test
    void trocarSenhaDeveRevogarSessoesIncrementarVersaoEAuditar() {
        RevogadorDeSessoes revogador = mock(RevogadorDeSessoes.class);
        AuditoriaSeguranca auditoria = mock(AuditoriaSeguranca.class);
        UsuarioService service = new UsuarioService(usuarioRepository, passwordEncoder, null,
                PasswordPolicy.padrao(), revogador, auditoria);
        UUID id = UUID.randomUUID();
        Usuario usuario = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("senhaAtual", "HASH")).thenReturn(true);
        when(passwordEncoder.matches("Dispensa#2024", "HASH")).thenReturn(false);
        when(passwordEncoder.encode("Dispensa#2024")).thenReturn("NOVOHASH");

        service.trocarSenha(id, "senhaAtual", "Dispensa#2024");

        verify(usuarioRepository).incrementarTokenVersion(id);
        verify(revogador).revogarTodas(id, MotivoRevogacao.SENHA_ALTERADA);
        verify(auditoria).registrar(TipoEventoSeguranca.SENHA_ALTERADA, id, null);
    }

    @Test
    void alterarPerfilDeveRecusarRebaixarOUltimoAdmin() {
        UUID id = UUID.randomUUID();
        Usuario admin = new Usuario("admin@mail.com", "Admin", "HASH", Perfil.ADMIN);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(admin));
        when(usuarioRepository.travarPorPerfil(Perfil.ADMIN)).thenReturn(List.of(admin));

        assertThatThrownBy(() -> usuarioService.alterarPerfil(id, Perfil.USER, UUID.randomUUID()))
                .isInstanceOf(ConflitoException.class)
                .hasMessage(Mensagens.get("perfil.ultimo.admin"));

        verify(usuarioRepository, never()).incrementarTokenVersion(any(UUID.class));
    }

    @Test
    void alterarPerfilDeveRevogarSessoesIncrementarVersaoEAuditar() {
        RevogadorDeSessoes revogador = mock(RevogadorDeSessoes.class);
        AuditoriaSeguranca auditoria = mock(AuditoriaSeguranca.class);
        UsuarioService service = new UsuarioService(usuarioRepository, passwordEncoder, null,
                PasswordPolicy.padrao(), revogador, auditoria);
        UUID id = UUID.randomUUID();
        UUID executor = UUID.randomUUID();
        Usuario usuario = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(usuarioRepository.findById(id)).thenReturn(Optional.of(usuario));

        UsuarioResponse response = service.alterarPerfil(id, Perfil.ADMIN, executor);

        assertThat(response.perfil()).isEqualTo(Perfil.ADMIN);
        verify(usuarioRepository).incrementarTokenVersion(id);
        verify(revogador).revogarTodas(id, MotivoRevogacao.PERFIL_ALTERADO);
        verify(auditoria).registrar(eq(TipoEventoSeguranca.PERFIL_ALTERADO), eq(id),
                org.mockito.ArgumentMatchers.contains(executor.toString()));
    }

    @Test
    void excluirDeveRemoverRefreshTokens() {
        RevogadorDeSessoes revogador = mock(RevogadorDeSessoes.class);
        UsuarioService service = new UsuarioService(usuarioRepository, passwordEncoder, null,
                PasswordPolicy.padrao(), revogador, null);
        UUID id = UUID.randomUUID();
        when(usuarioRepository.existsById(id)).thenReturn(true);

        service.excluir(id);

        verify(revogador).removerTodas(id);
        verify(usuarioRepository).deleteById(id);
    }
}
