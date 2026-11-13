package dev.gilberto.gestaousuarios.protecao;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Limite de requisições por IP em memória, com janela fixa iniciada na primeira requisição.
 * Mutações atômicas por IP via {@code compute}; a contagem satura em {@code max + 1}.
 */
@Service
public class RateLimitService {

    /** Estado imutável de um IP. */
    record Janela(Instant inicio, int contagem) {
    }

    private final ConcurrentHashMap<String, Janela> janelas = new ConcurrentHashMap<>();
    private final RateLimitProperties props;
    private final Clock clock;

    public RateLimitService(RateLimitProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
    }

    /** Vazio = permitido; presente = Retry-After (ceil, mínimo 1 s). */
    public Optional<Duration> registrar(String ip) {
        Instant agora = clock.instant();
        Duration[] retry = new Duration[1];
        janelas.compute(ip, (k, atual) -> {
            Janela j;
            if (atual == null || !agora.isBefore(atual.inicio().plus(props.window()))) {
                j = new Janela(agora, 1);
            } else {
                j = new Janela(atual.inicio(), Math.min(atual.contagem() + 1, props.maxRequests() + 1));
            }
            if (j.contagem() > props.maxRequests()) {
                retry[0] = retryAfter(Duration.between(agora, j.inicio().plus(props.window())));
            }
            return j;
        });
        return Optional.ofNullable(retry[0]);
    }

    /** Remove janelas vencidas, limitando o crescimento de memória. */
    @Scheduled(fixedDelayString = "${dispensaai.security.protecao.limpeza-intervalo:PT1M}")
    public void limpar() {
        Instant agora = clock.instant();
        janelas.entrySet().removeIf(e -> !agora.isBefore(e.getValue().inicio().plus(props.window())));
    }

    private static Duration retryAfter(Duration restante) {
        long segundos = restante.getSeconds() + (restante.getNano() > 0 ? 1 : 0);
        return Duration.ofSeconds(Math.max(1, segundos));
    }

    int tamanho() {
        return janelas.size();
    }
}
