package dev.gilberto.gestaousuarios.auditoria;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doThrow;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

class EventoSegurancaServiceTest {

    private static final Instant AGORA = Instant.parse("2025-03-04T05:06:07Z");

    private EventoSegurancaRepository repositorio;
    private PlatformTransactionManager tm;
    private EventoSegurancaService service;
    private ListAppender<ILoggingEvent> appender;
    private Logger logger;

    @BeforeEach
    void setUp() {
        repositorio = mock(EventoSegurancaRepository.class);
        tm = mock(PlatformTransactionManager.class);
        when(tm.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        service = new EventoSegurancaService(repositorio, tm, Clock.fixed(AGORA, ZoneOffset.UTC));
        logger = (Logger) LoggerFactory.getLogger(EventoSegurancaService.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.INFO);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
        RequestContextHolder.resetRequestAttributes();
    }

    private EventoSeguranca salvo() {
        ArgumentCaptor<EventoSeguranca> captor = ArgumentCaptor.forClass(EventoSeguranca.class);
        verify(repositorio).save(captor.capture());
        return captor.getValue();
    }

    @Test
    void persisteEventoComInstanteDoClock() {
        UUID usuario = UUID.randomUUID();
        service.registrar(TipoEventoSeguranca.LOGIN_SUCESSO, usuario, "detalhe");

        EventoSeguranca e = salvo();
        assertThat(e.getTipo()).isEqualTo(TipoEventoSeguranca.LOGIN_SUCESSO);
        assertThat(e.getUsuarioId()).isEqualTo(usuario);
        assertThat(e.getInstante()).isEqualTo(AGORA);
        assertThat(e.getDetalhe()).isEqualTo("detalhe");
        assertThat(e.getIp()).isNull();
    }

    @Test
    void usaTransacaoRequiresNew() {
        service.registrar(TipoEventoSeguranca.LOGOUT, null, null);

        ArgumentCaptor<TransactionDefinition> def = ArgumentCaptor.forClass(TransactionDefinition.class);
        verify(tm).getTransaction(def.capture());
        assertThat(def.getValue().getPropagationBehavior()).isEqualTo(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        verify(tm).commit(any());
    }

    @Test
    void ipVemDaRequisicaoCorrente() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("203.0.113.9");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(req));

        service.registrar(TipoEventoSeguranca.LOGIN_FALHA, null, null);

        assertThat(salvo().getIp()).isEqualTo("203.0.113.9");
    }

    @Test
    void detalheEhTruncadoEm500() {
        service.registrar(TipoEventoSeguranca.PERFIL_ALTERADO, null, "x".repeat(900));
        assertThat(salvo().getDetalhe()).hasSize(500);
    }

    @Test
    void detalheAte500NaoEhAlterado() {
        String d = "y".repeat(500);
        service.registrar(TipoEventoSeguranca.PERFIL_ALTERADO, null, d);
        assertThat(salvo().getDetalhe()).isEqualTo(d);
    }

    @Test
    void falhaNoSaveNaoPropagaELogaErroSemDadosSensiveis() {
        doThrow(new IllegalStateException("falha-db")).when(repositorio).save(any());

        assertThatCode(() -> service.registrar(TipoEventoSeguranca.SENHA_ALTERADA, UUID.randomUUID(),
                "SEGREDO-sensivel")).doesNotThrowAnyException();

        ILoggingEvent erro = appender.list.stream().filter(ev -> ev.getLevel() == Level.ERROR).findFirst()
                .orElseThrow();
        assertThat(erro.getFormattedMessage()).contains("SENHA_ALTERADA").doesNotContain("SEGREDO-sensivel");
    }

    @Test
    void falhaNoCommitNaoPropaga() {
        doThrow(new IllegalStateException("commit")).when(tm).commit(any());

        assertThatCode(() -> service.registrar(TipoEventoSeguranca.LOGOUT, null, null))
                .doesNotThrowAnyException();
        assertThat(appender.list).anyMatch(ev -> ev.getLevel() == Level.ERROR);
    }

    @Test
    void linhaDeLogEstruturadaTemTipoUsuarioIpEInstante() {
        UUID usuario = UUID.randomUUID();
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("198.51.100.7");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(req));

        service.registrar(TipoEventoSeguranca.LOGIN_SUCESSO, usuario, "d");

        ILoggingEvent info = appender.list.stream().filter(ev -> ev.getLevel() == Level.INFO).findFirst()
                .orElseThrow();
        assertThat(info.getFormattedMessage()).contains("evento_seguranca", "LOGIN_SUCESSO",
                usuario.toString(), "198.51.100.7", AGORA.toString());
    }
}
