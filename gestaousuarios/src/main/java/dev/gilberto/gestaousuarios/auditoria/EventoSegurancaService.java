package dev.gilberto.gestaousuarios.auditoria;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * Grava eventos de segurança em transação própria (REQUIRES_NEW, programática) e isola falhas:
 * nenhuma exceção da auditoria propaga para o fluxo principal. Não registra e-mail, token ou senha.
 */
@Service
public class EventoSegurancaService implements AuditoriaSeguranca {

    static final int LIMITE_DETALHE = 500;

    private static final Logger log = LoggerFactory.getLogger(EventoSegurancaService.class);

    private final EventoSegurancaRepository repositorio;
    private final Clock clock;
    private final TransactionTemplate transacao;

    public EventoSegurancaService(EventoSegurancaRepository repositorio, PlatformTransactionManager gerenteTransacao,
                                  Clock clock) {
        this.repositorio = repositorio;
        this.clock = clock;
        this.transacao = new TransactionTemplate(gerenteTransacao);
        this.transacao.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Override
    public void registrar(TipoEventoSeguranca tipo, UUID usuarioId, String detalhe) {
        try {
            Instant instante = clock.instant();
            String ip = ipDaRequisicaoAtual();
            String detalheTruncado = truncar(detalhe);

            log.atInfo()
                    .addKeyValue("tipo", tipo)
                    .addKeyValue("usuarioId", usuarioId)
                    .addKeyValue("ip", ip)
                    .addKeyValue("instante", instante)
                    .log("evento_seguranca tipo={} usuarioId={} ip={} instante={}", tipo, usuarioId, ip, instante);

            EventoSeguranca evento = new EventoSeguranca(tipo, usuarioId, instante, ip, detalheTruncado);
            transacao.executeWithoutResult(status -> repositorio.save(evento));
        } catch (RuntimeException e) {
            // Sem PII: apenas o tipo do evento e a classe da falha; a stack segue no log.
            log.error("Falha ao registrar evento de segurança tipo={} causa={}", tipo, e.getClass().getSimpleName(), e);
        }
    }

    private static String truncar(String detalhe) {
        if (detalhe == null || detalhe.length() <= LIMITE_DETALHE) {
            return detalhe;
        }
        return detalhe.substring(0, LIMITE_DETALHE);
    }

    private static String ipDaRequisicaoAtual() {
        RequestAttributes atributos = RequestContextHolder.getRequestAttributes();
        if (atributos instanceof ServletRequestAttributes servlet) {
            return servlet.getRequest().getRemoteAddr();
        }
        return null;
    }
}
