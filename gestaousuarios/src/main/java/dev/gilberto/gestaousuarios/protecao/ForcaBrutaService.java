package dev.gilberto.gestaousuarios.protecao;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Contadores de falhas de login em memória, por chave de conta (ver {@link ChaveConta}).
 * Janela fixa iniciada na primeira falha; mutações atômicas por chave via {@code compute}.
 * O comportamento independe de o usuário existir.
 */
@Service
public class ForcaBrutaService {

    /** Estado imutável de uma chave. {@code bloqueadoAte} é nulo quando não há bloqueio. */
    record EstadoConta(int falhas, Instant inicioJanela, Instant bloqueadoAte) {
    }

    private final ConcurrentHashMap<String, EstadoConta> contas = new ConcurrentHashMap<>();
    private final LockoutProperties props;
    private final Clock clock;

    public ForcaBrutaService(LockoutProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
    }

    /** Vazio = liberado; presente = valor do Retry-After (segundos inteiros, mínimo 1, em {@link Duration}). */
    public Optional<Duration> verificarBloqueio(String chave) {
        Instant agora = clock.instant();
        Duration[] restante = new Duration[1];
        contas.computeIfPresent(chave, (k, estado) -> {
            if (estado.bloqueadoAte() == null) {
                return estado;
            }
            if (agora.isBefore(estado.bloqueadoAte())) {
                restante[0] = retryAfter(Duration.between(agora, estado.bloqueadoAte()));
                return estado;
            }
            return null; // bloqueio expirou: zera o contador
        });
        return Optional.ofNullable(restante[0]);
    }

    /** Registra uma falha; retorna {@code true} se ESTA falha iniciou o bloqueio. */
    public boolean registrarFalha(String chave) {
        Instant agora = clock.instant();
        boolean[] bloqueou = new boolean[1];
        contas.compute(chave, (k, estado) -> {
            if (estado != null && estado.bloqueadoAte() != null) {
                if (agora.isBefore(estado.bloqueadoAte())) {
                    return estado; // já bloqueada: não altera
                }
                estado = null; // bloqueio expirado
            }
            int falhas;
            Instant inicio;
            if (estado == null || !agora.isBefore(estado.inicioJanela().plus(props.window()))) {
                falhas = 1;
                inicio = agora;
            } else {
                falhas = estado.falhas() + 1;
                inicio = estado.inicioJanela();
            }
            if (falhas == props.maxAttempts()) {
                bloqueou[0] = true;
                return new EstadoConta(falhas, inicio, agora.plus(props.duration()));
            }
            return new EstadoConta(falhas, inicio, null);
        });
        return bloqueou[0];
    }

    /** Zera o contador (login bem-sucedido). */
    public void registrarSucesso(String chave) {
        contas.remove(chave);
    }

    /** Remove entradas com janela e bloqueio vencidos, limitando o crescimento de memória. */
    @Scheduled(fixedDelayString = "${dispensaai.security.protecao.limpeza-intervalo:PT1M}")
    public void limpar() {
        Instant agora = clock.instant();
        contas.entrySet().removeIf(e -> {
            EstadoConta s = e.getValue();
            if (s.bloqueadoAte() != null) {
                return !agora.isBefore(s.bloqueadoAte());
            }
            return !agora.isBefore(s.inicioJanela().plus(props.window()));
        });
    }

    /** max(1, ceil(restante em segundos)). */
    private static Duration retryAfter(Duration restante) {
        long segundos = restante.getSeconds() + (restante.getNano() > 0 ? 1 : 0);
        return Duration.ofSeconds(Math.max(1, segundos));
    }

    int tamanho() {
        return contas.size();
    }
}
