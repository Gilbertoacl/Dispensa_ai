package dev.gilberto.gestaousuarios.auditoria;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.gilberto.gestaousuarios.auth.AuthService;
import dev.gilberto.gestaousuarios.auth.HashFicticio;
import dev.gilberto.gestaousuarios.auth.LoginRequest;
import dev.gilberto.gestaousuarios.auth.SessaoService;
import dev.gilberto.gestaousuarios.auth.TokenOpaco;
import dev.gilberto.gestaousuarios.auth.TokenResponse;
import dev.gilberto.gestaousuarios.protecao.ForcaBrutaService;
import dev.gilberto.gestaousuarios.shared.exceptions.TokenReutilizadoException;
import dev.gilberto.gestaousuarios.testsupport.RelogioFalso;
import dev.gilberto.gestaousuarios.testsupport.SessaoFixture;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import dev.gilberto.gestaousuarios.usuario.UsuarioService;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class AuditoriaSemDadosSensiveisPropertyTest {

    private enum Fluxo { LOGIN_FALHO, REUSO, TROCA_SENHA, MUDANCA_PERFIL }

    // Feature: endurecimento-autenticacao, Property 22: Eventos de segurança não carregam dados sensíveis
    // Validates: Requirements 16.6
    @Property(tries = 200)
    void eventosELogsNaoCarregamDadosSensiveis(@ForAll Fluxo fluxo,
                                               @ForAll("locais") String local,
                                               @ForAll("senhas") String senhaA,
                                               @ForAll("senhas") String senhaB,
                                               @ForAll("hashes") String senhaHash,
                                               @ForAll boolean usuarioExiste,
                                               @ForAll boolean iniciouBloqueio) throws Exception {
        String email = local + "@example.com";
        SessaoFixture fx = new SessaoFixture();
        Usuario usuario = fx.novoUsuario(fluxo == Fluxo.MUDANCA_PERFIL ? Perfil.ADMIN : Perfil.USER);
        definir(usuario, "email", email);
        definir(usuario, "senhaHash", senhaHash);

        List<String> sensiveis = new ArrayList<>(List.of(email, senhaA, senhaB, senhaHash));
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        root.addAppender(appender);
        try {
            switch (fluxo) {
                case LOGIN_FALHO -> loginFalho(fx, encoder, usuario, email, senhaA, usuarioExiste, iniciouBloqueio);
                case REUSO -> reuso(fx, usuario, sensiveis);
                case TROCA_SENHA -> trocaSenha(fx, encoder, usuario, senhaA, senhaB);
                case MUDANCA_PERFIL -> mudancaDePerfil(fx, encoder, usuario);
            }
            // hash persistido de todo refresh token emitido também é sensível
            fx.store.todos().forEach(t -> sensiveis.add(t.getTokenHash()));

            List<String> textos = new ArrayList<>(replicarEmEventoSegurancaService(fx));
            for (ILoggingEvent e : appender.list) {
                textos.add(e.getFormattedMessage());
                e.getKeyValuePairs().forEach(kv -> textos.add(kv.key + "=" + kv.value));
                if (e.getThrowableProxy() != null) {
                    textos.add(String.valueOf(e.getThrowableProxy().getMessage()));
                }
            }
            fx.auditoria.eventos().forEach(ev -> textos.add(String.valueOf(ev.detalhe())));

            assertThat(fx.auditoria.eventos()).isNotEmpty();
            assertThat(textos).anySatisfy(t -> assertThat(t).contains("evento_seguranca"));
            for (String texto : textos) {
                for (String segredo : sensiveis) {
                    assertThat(texto).as("texto auditado/logado não deve conter dado sensível").doesNotContain(segredo);
                }
                assertThat(texto.toLowerCase()).doesNotContain("senhahash");
            }
        } finally {
            root.detachAppender(appender);
            RequestContextHolder.resetRequestAttributes();
        }
    }

    private static void guardar(TokenResponse r, List<String> sensiveis) {
        sensiveis.add(r.refreshToken());
        sensiveis.add(TokenOpaco.hash(r.refreshToken()));
        sensiveis.add(r.accessToken());
    }

    private void loginFalho(SessaoFixture fx, PasswordEncoder encoder, Usuario usuario, String email, String senha,
                            boolean existe, boolean bloqueio) {
        UsuarioRepositoryStub.preparar(fx, usuario, existe);
        when(encoder.matches(any(), any())).thenReturn(false);
        when(encoder.encode(any())).thenReturn("$2a$10$ficticio");
        ForcaBrutaService forca = mock(ForcaBrutaService.class);
        when(forca.registrarFalha(anyString())).thenReturn(bloqueio);
        AuthService auth = new AuthService(fx.usuarioRepository, encoder, fx.sessao, forca,
                new HashFicticio(encoder, new java.security.SecureRandom()), fx.auditoria);
        assertThatThrownBy(() -> auth.autenticar(new LoginRequest(email, senha), SessaoFixture.CLIENTE))
                .isInstanceOf(BadCredentialsException.class);
    }

    private void reuso(SessaoFixture fx, Usuario usuario, List<String> sensiveis) {
        TokenResponse r0 = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        guardar(r0, sensiveis);
        TokenResponse r1 = fx.sessao.renovar(r0.refreshToken(), SessaoFixture.CLIENTE);
        guardar(r1, sensiveis);
        assertThatThrownBy(() -> fx.sessao.renovar(r0.refreshToken(), SessaoFixture.CLIENTE))
                .isInstanceOf(TokenReutilizadoException.class);
    }

    private void trocaSenha(SessaoFixture fx, PasswordEncoder encoder, Usuario usuario, String atual, String nova) {
        when(encoder.matches(atual, usuario.getSenhaHash())).thenReturn(true);
        when(encoder.matches(nova, usuario.getSenhaHash())).thenReturn(false);
        when(encoder.encode(nova)).thenReturn("$2a$10$novoHashDistinto");
        new UsuarioService(fx.usuarioRepository, encoder, null, null, fx.sessao, fx.auditoria)
                .trocarSenha(usuario.getId(), atual, nova);
    }

    private void mudancaDePerfil(SessaoFixture fx, PasswordEncoder encoder, Usuario admin) {
        Usuario outro = fx.novoUsuario(Perfil.ADMIN);
        when(fx.usuarioRepository.travarPorPerfil(Perfil.ADMIN)).thenReturn(List.of(admin, outro));
        new UsuarioService(fx.usuarioRepository, encoder, null, null, fx.sessao, fx.auditoria)
                .alterarPerfil(admin.getId(), Perfil.USER, outro.getId());
    }

    /** Reproduz os eventos auditados no serviço real: gera a linha de log e o registro persistido. */
    private List<String> replicarEmEventoSegurancaService(SessaoFixture fx) {
        EventoSegurancaRepository repo = mock(EventoSegurancaRepository.class);
        EventoSegurancaService servico = new EventoSegurancaService(repo, mock(PlatformTransactionManager.class),
                new RelogioFalso());
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr(SessaoFixture.CLIENTE.ip());
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(req));

        fx.auditoria.eventos().forEach(e -> servico.registrar(e.tipo(), e.usuarioId(), e.detalhe()));

        ArgumentCaptor<EventoSeguranca> captor = ArgumentCaptor.forClass(EventoSeguranca.class);
        verify(repo, org.mockito.Mockito.times(fx.auditoria.eventos().size())).save(captor.capture());
        List<String> textos = new ArrayList<>();
        for (EventoSeguranca ev : captor.getAllValues()) {
            textos.add(ev.getTipo() + "|" + ev.getIp() + "|" + ev.getDetalhe());
        }
        return textos;
    }

    private static void definir(Usuario u, String campo, Object valor) throws ReflectiveOperationException {
        Field f = Usuario.class.getDeclaredField(campo);
        f.setAccessible(true);
        f.set(u, valor);
    }

    /** Ajusta o repositório do fixture para a busca por e-mail do fluxo de login. */
    private static final class UsuarioRepositoryStub {
        static void preparar(SessaoFixture fx, Usuario usuario, boolean existe) {
            when(fx.usuarioRepository.findByEmail(anyString()))
                    .thenReturn(existe ? Optional.of(usuario) : Optional.empty());
        }
    }

    @Provide
    Arbitrary<String> locais() {
        return Arbitraries.strings().withCharRange('a', 'z').withCharRange('0', '9').ofMinLength(8).ofMaxLength(14);
    }

    @Provide
    Arbitrary<String> senhas() {
        return Arbitraries.strings().withCharRange('a', 'z').withCharRange('A', 'Z').withCharRange('0', '9')
                .ofMinLength(12).ofMaxLength(20).map(s -> "Pw!" + s);
    }

    @Provide
    Arbitrary<String> hashes() {
        return Arbitraries.strings().withCharRange('a', 'z').withCharRange('A', 'Z').withCharRange('0', '9')
                .ofMinLength(24).ofMaxLength(50).map(s -> "$2a$10$" + s);
    }
}
