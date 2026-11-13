package dev.gilberto.gestaousuarios.protecao;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
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

class RateLimitIsolamentoPropertyTest {

    /** {@code ip < 0}: avançar o relógio global em {@code deltaMs}; caso contrário, requisição do IP. */
    record Passo(int ip, long deltaMs) {
    }

    record Cenario(int max, Duration janela, int ips, List<Passo> passos) {
    }

    @Provide
    Arbitrary<Cenario> cenarios() {
        return Combinators.combine(
                Arbitraries.integers().between(1, 8),
                Arbitraries.longs().between(1_000, 60_000),
                Arbitraries.integers().between(2, 5))
                .flatAs((m, w, n) -> {
                    Arbitrary<Passo> req = Arbitraries.integers().between(0, n - 1).map(i -> new Passo(i, 0));
                    Arbitrary<Passo> av = Arbitraries.longs().between(0, 80_000).map(d -> new Passo(-1, d));
                    return Arbitraries.frequencyOf(Tuple.of(7, req), Tuple.of(2, av)).list().ofMaxSize(100)
                            .map(l -> new Cenario(m, Duration.ofMillis(w), n, l));
                });
    }

    record Observacao(Instant instante, Optional<Duration> resultado) {
    }

    // Feature: endurecimento-autenticacao, Property 15: Janelas de rate limit são independentes por IP
    // Validates: Requirements 10.4
    @Property(tries = 150)
    void intercalacaoDeIpsEquivaleAExecucaoIsolada(@ForAll("cenarios") Cenario c) {
        RelogioFalso relogio = new RelogioFalso();
        RateLimitService compartilhado = new RateLimitService(new RateLimitProperties(c.max(), c.janela()), relogio);

        List<List<Observacao>> porIp = new ArrayList<>();
        for (int i = 0; i < c.ips(); i++) {
            porIp.add(new ArrayList<>());
        }
        for (Passo p : c.passos()) {
            if (p.ip() < 0) {
                relogio.avancar(Duration.ofMillis(p.deltaMs()));
            } else {
                porIp.get(p.ip()).add(new Observacao(relogio.instant(), compartilhado.registrar("198.51.100." + p.ip())));
            }
        }

        // reexecuta cada IP sozinho numa instância nova, reproduzindo os mesmos instantes
        for (int i = 0; i < c.ips(); i++) {
            RelogioFalso proprio = new RelogioFalso();
            RateLimitService isolado = new RateLimitService(new RateLimitProperties(c.max(), c.janela()), proprio);
            for (Observacao o : porIp.get(i)) {
                proprio.definir(o.instante());
                assertThat(isolado.registrar("198.51.100." + i)).as("ip %d em %s", i, o.instante()).isEqualTo(o.resultado());
            }
        }
    }
}
