package dev.gilberto.gestaousuarios.testsupport;

import dev.gilberto.gestaousuarios.auditoria.AuditoriaSeguranca;
import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** Fake de {@link AuditoriaSeguranca} que acumula os eventos registrados para asserções. */
public class AuditoriaFalsa implements AuditoriaSeguranca {

    public record Evento(TipoEventoSeguranca tipo, UUID usuarioId, String detalhe) { }

    private final List<Evento> eventos = new ArrayList<>();

    @Override
    public synchronized void registrar(TipoEventoSeguranca tipo, UUID usuarioId, String detalhe) {
        eventos.add(new Evento(tipo, usuarioId, detalhe));
    }

    public synchronized List<Evento> eventos() {
        return List.copyOf(eventos);
    }

    public synchronized List<Evento> eventosDo(TipoEventoSeguranca tipo) {
        return eventos.stream().filter(e -> e.tipo() == tipo).toList();
    }

    public synchronized long contar(TipoEventoSeguranca tipo) {
        return eventos.stream().filter(e -> e.tipo() == tipo).count();
    }
}
