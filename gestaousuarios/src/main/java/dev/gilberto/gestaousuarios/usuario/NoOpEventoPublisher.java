package dev.gilberto.gestaousuarios.usuario;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Publicador no-op (R16.3).
 *
 * <p>Ativo quando {@code dispensaai.eventos.usuario-criado.enabled} está ausente ou {@code false}
 * (default). Conclui o cadastro sem publicar nada, apenas registrando em DEBUG, de modo que a
 * aplicação rode sem Kafka.</p>
 */
@Component
@ConditionalOnProperty(
        name = "dispensaai.eventos.usuario-criado.enabled",
        havingValue = "false",
        matchIfMissing = true)
public class NoOpEventoPublisher implements EventoPublisher {

    private static final Logger log = LoggerFactory.getLogger(NoOpEventoPublisher.class);

    @Override
    public void publicarUsuarioCriado(UsuarioCriadoEvent evento) {
        log.debug("Publicação de evento desabilitada; evento UsuarioCriado ignorado para id={}",
                evento != null ? evento.id() : null);
    }
}
