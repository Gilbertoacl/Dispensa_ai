package dev.gilberto.gestaousuarios.protecao;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import dev.gilberto.gestaousuarios.testsupport.RelogioFalso;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;

class RateLimitServicePropertyTest {

    private static final String IP = "203.0.113.7";

    /** Passo da sequência: {@code deltaMs < 0} significa requisição; caso contrário, avançar. */
    record Passo(long deltaMs) {
        boolean requisicao() {
            return deltaMs < 0;
        }
    }

    record Cfg(int max, Duration janela) {
        RateLimitProperties props() {
            return new RateLimitProperties(max, janela);
        }
    }

    @Provide
    Arbitrary<Cfg> configs() {
        return Combinators.combine(
                Arbitraries.integers().between(1, 15),
                Arbitraries.longs().between(1_000, 120_000))
                .as((m, w) -> new Cfg(m, Duration.ofMillis(w)));
    }

    @Provide
    Arbitrary<List<Passo>> passos() {
        Arbitrary<Passo> req = Arbitraries.just(new Passo(-1));
        Arbitrary<Passo> avancar = Arbitraries.longs().between(0, 150_000).map(Passo::new);
        return Arbitraries.frequencyOf(Tuple.of(6, req), Tuple.of(3, avancar)).list().ofMaxSize(80);
    }

    // Feature: endurecimento-autenticacao, Property 14: Rate limit por IP segue o modelo de janela fixa
    // Validates: Requirements 10.1, 10.2, 10.3
    @Property(tries = 200)
    void segueModeloDeJanelaFixa(@ForAll("configs") Cfg cfg, @ForAll("passos") List<Passo> passos) {
        RelogioFalso relogio = new RelogioFalso();
        RateLimitService service = new RateLimitService(cfg.props(), relogio);
        Instant inicio = null;
        int contagem = 0;
        for (Passo p : passos) {
            if (!p.requisicao()) {
                relogio.avancar(Duration.ofMillis(p.deltaMs()));
                continue;
            }
            Instant agora = relogio.instant();
            if (inicio == null || !agora.isBefore(inicio.plus(cfg.janela()))) {
                inicio = agora;
                contagem = 0;
            }
            contagem++;
            Optional<Duration> esperado = Optional.empty();
            if (contagem > cfg.max()) {
                long restanteMs = Duration.between(agora, inicio.plus(cfg.janela())).toMillis();
                esperado = Optional.of(Duration.ofSeconds(Math.max(1, (restanteMs + 999) / 1000)));
            }
            Optional<Duration> real = service.registrar(IP);
            assertThat(real).isEqualTo(esperado);
            real.ifPresent(d -> assertThat(d.getSeconds()).isGreaterThanOrEqualTo(1));
        }
    }

    // Feature: endurecimento-autenticacao, Property 14: Rate limit por IP segue o modelo de janela fixa
    // Validates: Requirements 10.1, 10.2, 10.3
    @Property(tries = 100)
    void asMPrimeirasPassamASeguinteEBloqueadaEDepoisDaJanelaVoltaAAceitar(
            @ForAll("configs") Cfg cfg, @ForAll @net.jqwik.api.constraints.IntRange(min = 0, max = 100_000) int decorridoMs) {
        net.jqwik.api.Assume.that(decorridoMs < cfg.janela().toMillis());
        RelogioFalso relogio = new RelogioFalso();
        RateLimitService service = new RateLimitService(cfg.props(), relogio);
        for (int i = 0; i < cfg.max(); i++) {
            assertThat(service.registrar(IP)).as("requisição %d", i + 1).isEmpty();
        }
        relogio.avancar(Duration.ofMillis(decorridoMs));
        long restanteMs = cfg.janela().toMillis() - decorridoMs;
        Optional<Duration> bloqueio = service.registrar(IP);
        assertThat(bloqueio).contains(Duration.ofSeconds(Math.max(1, (restanteMs + 999) / 1000)));
        assertThat(bloqueio.get().getSeconds()).isGreaterThanOrEqualTo(1);
        // contagem satura: muitas tentativas extras não alteram o Retry-After nem estendem a janela
        for (int i = 0; i < 5; i++) {
            assertThat(service.registrar(IP)).isEqualTo(bloqueio);
        }

        relogio.avancar(Duration.ofMillis(restanteMs)); // fim exato da janela
        for (int i = 0; i < cfg.max(); i++) {
            assertThat(service.registrar(IP)).as("nova janela, requisição %d", i + 1).isEmpty();
        }
        assertThat(service.registrar(IP)).isPresent();
    }

    // Feature: endurecimento-autenticacao, Property 14: Rate limit por IP segue o modelo de janela fixa
    // Validates: Requirements 10.3
    @Property(tries = 100)
    void limparRemoveSomenteJanelasVencidas(@ForAll("configs") Cfg cfg) {
        RelogioFalso relogio = new RelogioFalso();
        RateLimitService service = new RateLimitService(cfg.props(), relogio);
        service.registrar("10.0.0.1");
        service.registrar("10.0.0.2");
        relogio.avancar(cfg.janela().minusMillis(1));
        service.limpar();
        assertThat(service.tamanho()).isEqualTo(2);
        relogio.avancar(Duration.ofMillis(1));
        service.limpar();
        assertThat(service.tamanho()).isZero();
    }
}
