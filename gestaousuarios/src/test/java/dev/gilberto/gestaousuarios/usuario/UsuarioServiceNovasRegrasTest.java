package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;
import dev.gilberto.gestaousuarios.auth.MotivoRevogacao;
import dev.gilberto.gestaousuarios.shared.exceptions.ConflitoException;
import dev.gilberto.gestaousuarios.shared.exceptions.RecursoNaoEncontradoException;
import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import dev.gilberto.gestaousuarios.testsupport.AuditoriaFalsa;

/** Testes unitários das regras novas do UsuarioService (sessões, perfil, política, admin inicial). */
class UsuarioServiceNovasRegrasTest {

    private UsuarioRepository repo;
    private PasswordEncoder encoder;
    private RevogadorDeSessoes revogador;
    private AuditoriaFalsa auditoria;
    private EventoPublisher publisher;
    private UsuarioService service;

    @BeforeEach
    void setUp() {
        repo = mock(UsuarioRepository.class);
        encoder = mock(PasswordEncoder.class);
        revogador = mock(RevogadorDeSessoes.class);
        auditoria = new AuditoriaFalsa();
        publisher = mock(EventoPublisher.class);
        service = new UsuarioService(repo, encoder, publisher, PasswordPolicy.padrao(), revogador, auditoria);
    }

    private static Usuario usuario(String email, Perfil perfil, String hash) {
        Usuario u = new Usuario(email, "Nome", hash, perfil);
        ReflectionTestUtils.setField(u, "id", UUID.randomUUID());
        return u;
    }

    // ---------- alterarPerfil ----------

    @Test
    void alterarPerfilInexistenteLancaNaoEncontrado() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.alterarPerfil(id, Perfil.ADMIN, UUID.randomUUID()))
                .isInstanceOf(RecursoNaoEncontradoException.class);
        verifyNoInteractions(revogador);
    }

    @Test
    void alterarPerfilParaOMesmoValorNaoFazNada() {
        Usuario alvo = usuario("a@x.com", Perfil.USER, "h");
        when(repo.findById(alvo.getId())).thenReturn(Optional.of(alvo));

        UsuarioResponse r = service.alterarPerfil(alvo.getId(), Perfil.USER, UUID.randomUUID());

        assertThat(r.perfil()).isEqualTo(Perfil.USER);
        verify(repo, never()).save(any());
        verify(repo, never()).incrementarTokenVersion(any());
        verifyNoInteractions(revogador);
        assertThat(auditoria.eventos()).isEmpty();
    }

    @Test
    void rebaixarOUnicoAdminLancaConflito() {
        Usuario admin = usuario("a@x.com", Perfil.ADMIN, "h");
        when(repo.findById(admin.getId())).thenReturn(Optional.of(admin));
        when(repo.travarPorPerfil(Perfil.ADMIN)).thenReturn(List.of(admin));

        assertThatThrownBy(() -> service.alterarPerfil(admin.getId(), Perfil.USER, admin.getId()))
                .isInstanceOf(ConflitoException.class)
                .hasMessage(Mensagens.get("perfil.ultimo.admin"));

        assertThat(admin.getPerfil()).isEqualTo(Perfil.ADMIN);
        verify(repo, never()).save(any());
        verify(repo, never()).incrementarTokenVersion(any());
        verifyNoInteractions(revogador);
        assertThat(auditoria.eventos()).isEmpty();
    }

    @Test
    void alterarPerfilComSucessoIncrementaTvRevogaEAudita() {
        Usuario alvo = usuario("a@x.com", Perfil.USER, "h");
        UUID executor = UUID.randomUUID();
        when(repo.findById(alvo.getId())).thenReturn(Optional.of(alvo));

        UsuarioResponse r = service.alterarPerfil(alvo.getId(), Perfil.ADMIN, executor);

        assertThat(r.perfil()).isEqualTo(Perfil.ADMIN);
        verify(repo).save(alvo);
        verify(repo).incrementarTokenVersion(alvo.getId());
        verify(revogador).revogarTodas(alvo.getId(), MotivoRevogacao.PERFIL_ALTERADO);
        List<AuditoriaFalsa.Evento> eventos = auditoria.eventosDo(TipoEventoSeguranca.PERFIL_ALTERADO);
        assertThat(eventos).hasSize(1);
        assertThat(eventos.get(0).usuarioId()).isEqualTo(alvo.getId());
        assertThat(eventos.get(0).detalhe())
                .contains(executor.toString()).contains("USER").contains("ADMIN");
    }

    @Test
    void rebaixarAdminQuandoHaOutroAdminTemSucesso() {
        Usuario a1 = usuario("a@x.com", Perfil.ADMIN, "h");
        Usuario a2 = usuario("b@x.com", Perfil.ADMIN, "h");
        when(repo.findById(a1.getId())).thenReturn(Optional.of(a1));
        when(repo.travarPorPerfil(Perfil.ADMIN)).thenReturn(List.of(a1, a2));

        UsuarioResponse r = service.alterarPerfil(a1.getId(), Perfil.USER, a2.getId());

        assertThat(r.perfil()).isEqualTo(Perfil.USER);
        verify(repo).incrementarTokenVersion(a1.getId());
        verify(revogador).revogarTodas(a1.getId(), MotivoRevogacao.PERFIL_ALTERADO);
    }

    // ---------- trocarSenha ----------

    @Test
    void trocarSenhaIncrementaTvRevogaEAudita() {
        Usuario u = usuario("a@x.com", Perfil.USER, "HASH_ANTIGO");
        when(repo.findById(u.getId())).thenReturn(Optional.of(u));
        when(encoder.matches("SenhaAtual#1", "HASH_ANTIGO")).thenReturn(true);
        when(encoder.matches("NovaSenha#2024", "HASH_ANTIGO")).thenReturn(false);
        when(encoder.encode("NovaSenha#2024")).thenReturn("HASH_NOVO");

        service.trocarSenha(u.getId(), "SenhaAtual#1", "NovaSenha#2024");

        assertThat(u.getSenhaHash()).isEqualTo("HASH_NOVO");
        InOrder ordem = inOrder(repo, revogador);
        ordem.verify(repo).save(u);
        ordem.verify(repo).incrementarTokenVersion(u.getId());
        ordem.verify(revogador).revogarTodas(u.getId(), MotivoRevogacao.SENHA_ALTERADA);
        assertThat(auditoria.contar(TipoEventoSeguranca.SENHA_ALTERADA)).isEqualTo(1);
        assertThat(auditoria.eventosDo(TipoEventoSeguranca.SENHA_ALTERADA).get(0).usuarioId()).isEqualTo(u.getId());
    }

    @Test
    void trocarSenhaAplicaPoliticaNoCampoNovaSenha() {
        Usuario u = usuario("a@x.com", Perfil.USER, "HASH_ANTIGO");
        when(repo.findById(u.getId())).thenReturn(Optional.of(u));
        when(encoder.matches("SenhaAtual#1", "HASH_ANTIGO")).thenReturn(true);

        assertThatThrownBy(() -> service.trocarSenha(u.getId(), "SenhaAtual#1", "password"))
                .isInstanceOfSatisfying(RegraNegocioException.class, e -> {
                    assertThat(e.getChave()).isEqualTo("senha.comum");
                    assertThat(e.getCampo()).isEqualTo("novaSenha");
                });
        assertThat(u.getSenhaHash()).isEqualTo("HASH_ANTIGO");
        verify(repo, never()).incrementarTokenVersion(any());
        verifyNoInteractions(revogador);
    }

    // ---------- excluir ----------

    @Test
    void excluirRemoveTokensAntesDoDelete() {
        UUID id = UUID.randomUUID();
        when(repo.existsById(id)).thenReturn(true);

        service.excluir(id);

        InOrder ordem = inOrder(revogador, repo);
        ordem.verify(revogador).removerTodas(id);
        ordem.verify(repo).deleteById(id);
    }

    @Test
    void excluirInexistenteNaoRemoveNada() {
        UUID id = UUID.randomUUID();
        when(repo.existsById(id)).thenReturn(false);

        assertThatThrownBy(() -> service.excluir(id)).isInstanceOf(RecursoNaoEncontradoException.class);
        verifyNoInteractions(revogador);
        verify(repo, never()).deleteById(any());
    }

    // ---------- criarUsuario ----------

    @Test
    void criarUsuarioSempreUserComTokenVersionZero() {
        when(repo.existsByEmail("novo@x.com")).thenReturn(false);
        when(encoder.encode(anyString())).thenReturn("HASH");
        when(repo.save(any(Usuario.class))).thenAnswer(i -> i.getArgument(0));

        UsuarioResponse r = service.criarUsuario(new UsuarioRequest("Novo@X.com", "Novo", "Dispensa#2024"));

        ArgumentCaptor<Usuario> cap = ArgumentCaptor.forClass(Usuario.class);
        verify(repo).save(cap.capture());
        assertThat(cap.getValue().getPerfil()).isEqualTo(Perfil.USER);
        assertThat(cap.getValue().getTokenVersion()).isZero();
        assertThat(r.perfil()).isEqualTo(Perfil.USER);
    }

    @Test
    void criarUsuarioRejeitaSenhaComum() {
        when(repo.existsByEmail("novo@x.com")).thenReturn(false);

        assertThatThrownBy(() -> service.criarUsuario(new UsuarioRequest("novo@x.com", "Novo", "Password123")))
                .isInstanceOfSatisfying(RegraNegocioException.class, e -> {
                    assertThat(e.getChave()).isEqualTo("senha.comum");
                    assertThat(e.getCampo()).isEqualTo("senha");
                });
        verify(repo, never()).save(any());
    }

    @Test
    void criarUsuarioRejeitaSenhaIgualAoEmail() {
        when(repo.existsByEmail("usuario@example.com")).thenReturn(false);

        assertThatThrownBy(() -> service.criarUsuario(
                new UsuarioRequest("usuario@example.com", "Novo", " Usuario@Example.com ")))
                .isInstanceOfSatisfying(RegraNegocioException.class,
                        e -> assertThat(e.getChave()).isEqualTo("senha.igual.email"));
        verify(repo, never()).save(any());
    }

    // ---------- criarAdminInicial ----------

    @Test
    void criarAdminInicialCriaAdminAuditaEPublica() {
        when(repo.existsByEmail("admin@x.com")).thenReturn(false);
        when(encoder.encode("Dispensa#2024")).thenReturn("HASH");
        when(repo.saveAndFlush(any(Usuario.class))).thenAnswer(i -> {
            Usuario u = i.getArgument(0);
            ReflectionTestUtils.setField(u, "id", UUID.randomUUID());
            return u;
        });

        Optional<UUID> id = service.criarAdminInicial("Admin@X.com", "Admin", "Dispensa#2024");

        assertThat(id).isPresent();
        ArgumentCaptor<Usuario> cap = ArgumentCaptor.forClass(Usuario.class);
        verify(repo).saveAndFlush(cap.capture());
        assertThat(cap.getValue().getPerfil()).isEqualTo(Perfil.ADMIN);
        assertThat(cap.getValue().getEmail()).isEqualTo("admin@x.com");
        verify(publisher).publicarUsuarioCriado(any(UsuarioCriadoEvent.class));
        assertThat(auditoria.contar(TipoEventoSeguranca.ADMIN_INICIAL_CRIADO)).isEqualTo(1);
    }

    @Test
    void criarAdminInicialQuandoEmailExisteDevolveVazioSemEfeitos() {
        when(repo.existsByEmail("admin@x.com")).thenReturn(true);

        assertThat(service.criarAdminInicial("admin@x.com", "Admin", "Dispensa#2024")).isEmpty();

        verify(repo, never()).saveAndFlush(any());
        verifyNoInteractions(publisher);
        assertThat(auditoria.eventos()).isEmpty();
    }

    @Test
    void criarAdminInicialEmCorridaDeUnicidadeDevolveVazio() {
        when(repo.existsByEmail("admin@x.com")).thenReturn(false);
        when(encoder.encode(anyString())).thenReturn("HASH");
        when(repo.saveAndFlush(any(Usuario.class))).thenThrow(new DataIntegrityViolationException("uk"));

        assertThat(service.criarAdminInicial("admin@x.com", "Admin", "Dispensa#2024")).isEmpty();

        verifyNoInteractions(publisher);
        assertThat(auditoria.eventos()).isEmpty();
    }
}
