package dev.gilberto.gestaousuarios.testsupport;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * Relógio mutável para testes. Começa em um instante fixo e só se move via {@link #avancar(Duration)}.
 */
public class RelogioFalso extends Clock {

    public static final Instant INSTANTE_PADRAO = Instant.parse("2026-01-01T00:00:00Z");

    private final ZoneId zona;
    private volatile Instant agora;

    public RelogioFalso() {
        this(INSTANTE_PADRAO);
    }

    public RelogioFalso(Instant inicial) {
        this(inicial, ZoneOffset.UTC);
    }

    private RelogioFalso(Instant inicial, ZoneId zona) {
        this.agora = inicial;
        this.zona = zona;
    }

    /** Avança (ou recua, se negativa) o relógio. */
    public synchronized void avancar(Duration duracao) {
        this.agora = this.agora.plus(duracao);
    }

    public synchronized void definir(Instant instante) {
        this.agora = instante;
    }

    @Override
    public ZoneId getZone() {
        return zona;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return new RelogioFalso(agora, zone);
    }

    @Override
    public Instant instant() {
        return agora;
    }
}
