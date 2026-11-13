package dev.gilberto.gestaousuarios.usuario;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.gilberto.gestaousuarios.auditoria.AuditoriaSeguranca;

/** Testes do {@link AdminInicialInitializer} (R8.2, R8.3, R8.4, R8.6). */
class AdminInicialInitializerTest {

    private static final String EMAIL = "admin@example.com";
    private static final String NOME = "Administrador";
    private static final String SENHA = "Segredo#Forte2024";

    private UsuarioRepository repo;
    private PasswordEncoder encoder;
    private UsuarioService service;
    private ListAppender<ILoggingEvent> appender;
    private Logger root;
    private Level nivelOriginal;

    @BeforeEach
    void setUp() {
        repo = mock(UsuarioRepository.class);
        encoder = mock(PasswordEncoder.class);
        when(encoder.encode(any())).thenReturn("HASH");
        service = new UsuarioService(repo, encoder, new NoOpEventoPublisher(), PasswordPolicy.padrao(),
                RevogadorDeSessoes.semEfeito(), AuditoriaSeguranca.semEfeito());

        root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        nivelOriginal = root.getLevel();
        root.setLevel(Level.ALL);
        appender = new ListAppender<>();
        appender.start();
        root.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        root.detachAppender(appender);
        root.setLevel(nivelOriginal);
    }

    private AdminInicialInitializer initializer(String email, String senha, String nome) {
        return new AdminInicialInitializer(new AdminInicialProperties(email, senha, nome), service);
    }

    private void executar(AdminInicialInitializer init) {
        init.run(new DefaultApplicationArguments());
    }

    private String logsConcatenados() {
        List<ILoggingEvent> eventos = new ArrayList<>(appender.list);
        StringBuilder sb = new StringBuilder();
        for (ILoggingEvent e : eventos) {
            sb.append(e.getFormattedMessage()).append('\n');
            if (e.getThrowableProxy() != null) {
                sb.append(e.getThrowableProxy().getMessage()).append('\n');
            }
        }
        return sb.toString();
    }

    /** As 7 combinações em que pelo menos uma das três variáveis falta (nulo, vazio ou em branco). */
    static Stream<Arguments> combinacoesIncompletas() {
        String vazio = "";
        return Stream.of(
                Arguments.of(vazio, vazio, vazio),
                Arguments.of(EMAIL, vazio, vazio),
                Arguments.of(vazio, SENHA, vazio),
                Arguments.of(vazio, vazio, NOME),
                Arguments.of(EMAIL, SENHA, vazio),
                Arguments.of(EMAIL, vazio, NOME),
                Arguments.of(vazio, SENHA, NOME),
                Arguments.of(null, null, null),
                Arguments.of("   ", SENHA, NOME));
    }

    @ParameterizedTest
    @MethodSource("combinacoesIncompletas")
    void variaveisAusentesOuParciaisNaoCriamAdmin(String email, String senha, String nome) {
        executar(initializer(email, senha, nome));

        verify(repo, never()).saveAndFlush(any());
        verify(repo, never()).save(any());
        verify(repo, never()).existsByEmail(any());
    }

    @Test
    void variaveisCompletasCriamAdminUmaVez() {
        when(repo.existsByEmail(EMAIL)).thenReturn(false);
        when(repo.saveAndFlush(any(Usuario.class))).thenAnswer(i -> {
            Usuario u = i.getArgument(0);
            ReflectionTestUtils.setField(u, "id", UUID.randomUUID());
            return u;
        });

        executar(initializer(EMAIL, SENHA, NOME));

        verify(repo, times(1)).saveAndFlush(any(Usuario.class));
    }

    @Test
    void emailExistenteNaoAlteraNadaESemErro() {
        when(repo.existsByEmail(EMAIL)).thenReturn(true);
        AdminInicialInitializer init = initializer(EMAIL, SENHA, NOME);

        executar(init);
        executar(init);

        verify(repo, never()).saveAndFlush(any());
        verify(repo, never()).save(any());
        verify(encoder, never()).encode(any());
    }

    @Test
    void senhaInvalidaGeraIllegalStateExceptionSemExporASenha() {
        String senhaFraca = "password123";
        when(repo.existsByEmail(EMAIL)).thenReturn(false);

        assertThatThrownBy(() -> executar(initializer(EMAIL, senhaFraca, NOME)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ADMIN_SENHA")
                .satisfies(e -> {
                    assertThat(e.getMessage()).doesNotContain(senhaFraca);
                    assertThat(e.getMessage()).contains("senha.comum");
                });
        verify(repo, never()).saveAndFlush(any());
    }

    @Test
    void senhaCurtaGeraIllegalStateExceptionSemExporASenha() {
        String senhaCurta = "Ab#1xyz";

        assertThatThrownBy(() -> executar(initializer(EMAIL, senhaCurta, NOME)))
                .isInstanceOf(IllegalStateException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain(senhaCurta));
    }

    @Test
    void senhaNaoApareceNosLogsNemQuandoCriaNemQuandoExiste() {
        when(repo.existsByEmail(EMAIL)).thenReturn(false);
        when(repo.saveAndFlush(any(Usuario.class))).thenAnswer(i -> {
            Usuario u = i.getArgument(0);
            ReflectionTestUtils.setField(u, "id", UUID.randomUUID());
            return u;
        });
        AdminInicialInitializer init = initializer(EMAIL, SENHA, NOME);
        executar(init);
        when(repo.existsByEmail(EMAIL)).thenReturn(true);
        executar(init);
        // e-mail inexistente + senha inválida: falha sem registrar a senha
        when(repo.existsByEmail(EMAIL)).thenReturn(false);
        assertThatThrownBy(() -> executar(initializer(EMAIL, "password123", NOME)))
                .isInstanceOf(IllegalStateException.class);

        String logs = logsConcatenados();
        assertThat(logs).isNotBlank();
        assertThat(logs).doesNotContain(SENHA).doesNotContain("password123");
        assertThat(new AdminInicialProperties(EMAIL, SENHA, NOME).toString()).doesNotContain(SENHA);
    }
}
