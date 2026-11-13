package dev.gilberto.gestaousuarios.usuario;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

/**
 * Publicador de eventos baseado em Kafka (R16.1).
 *
 * <p>Só é instanciado quando {@code dispensaai.eventos.usuario-criado.enabled=true}. Nesse
 * cenário, um broker Kafka deve estar disponível. No profile default (flag ausente/false)
 * este bean não é criado e a aplicação sobe sem depender de um broker.</p>
 */
@Component
@ConditionalOnProperty(name = "dispensaai.eventos.usuario-criado.enabled", havingValue = "true")
public class KafkaEventoPublisher implements EventoPublisher {

    static final String TOPICO_USUARIO_CRIADO = "gestaousuarios.usuario-criado";

    private static final Logger log = LoggerFactory.getLogger(KafkaEventoPublisher.class);

    private final KafkaTemplate<String, Object> kafkaTemplate;

    public KafkaEventoPublisher(KafkaTemplate<String, Object> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @Override
    public void publicarUsuarioCriado(UsuarioCriadoEvent evento) {
        kafkaTemplate.send(TOPICO_USUARIO_CRIADO, evento.id().toString(), evento);
        log.info("Evento UsuarioCriado publicado para id={}", evento.id());
    }
}
