package dev.gilberto.gestaousuarios.usuario;

/**
 * Abstração para publicação do evento de domínio {@link UsuarioCriadoEvent} (R16).
 *
 * <p>Existem duas implementações, selecionadas por configuração
 * ({@code dispensaai.eventos.usuario-criado.enabled}):</p>
 * <ul>
 *   <li>{@link KafkaEventoPublisher} — publica no tópico Kafka quando a flag está ligada;</li>
 *   <li>{@link NoOpEventoPublisher} — no-op quando a flag está ausente/false (default).</li>
 * </ul>
 */
public interface EventoPublisher {

    /**
     * Publica o evento de criação de usuário.
     *
     * @param evento evento de domínio a publicar; nunca {@code null}
     */
    void publicarUsuarioCriado(UsuarioCriadoEvent evento);
}
