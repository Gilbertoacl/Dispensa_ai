package dev.gilberto.gestaousuarios.testsupport;

import dev.gilberto.gestaousuarios.auth.MotivoRevogacao;
import dev.gilberto.gestaousuarios.auth.RefreshToken;
import dev.gilberto.gestaousuarios.auth.RefreshTokenStore;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Fake em memória de {@link RefreshTokenStore}. Os métodos são {@code synchronized}, espelhando a
 * atomicidade do UPDATE condicional usado em produção. O estado de revogação é alterado por reflexão
 * porque a entidade não expõe setters.
 */
public class RefreshTokenStoreEmMemoria implements RefreshTokenStore {

    private final Map<UUID, RefreshToken> porId = new LinkedHashMap<>();

    @Override
    public synchronized RefreshToken salvar(RefreshToken token) {
        porId.put(token.getId(), token);
        return token;
    }

    @Override
    public synchronized Optional<RefreshToken> buscarPorHash(String hash) {
        return porId.values().stream().filter(t -> t.getTokenHash().equals(hash)).findFirst();
    }

    @Override
    public synchronized int consumirSeAtivo(UUID id, Instant agora, UUID substitutoId) {
        RefreshToken t = porId.get(id);
        if (t == null || t.getRevogadoEm() != null || !t.getExpiraEm().isAfter(agora)) {
            return 0;
        }
        revogar(t, agora, MotivoRevogacao.ROTACAO, substitutoId);
        return 1;
    }

    @Override
    public synchronized int revogarFamilia(UUID familiaId, Instant agora, MotivoRevogacao motivo) {
        int n = 0;
        for (RefreshToken t : porId.values()) {
            if (t.getFamiliaId().equals(familiaId) && t.getRevogadoEm() == null) {
                revogar(t, agora, motivo, null);
                n++;
            }
        }
        return n;
    }

    @Override
    public synchronized int revogarTodosDoUsuario(UUID usuarioId, Instant agora, MotivoRevogacao motivo) {
        int n = 0;
        for (RefreshToken t : porId.values()) {
            if (t.getUsuarioId().equals(usuarioId) && t.getRevogadoEm() == null) {
                revogar(t, agora, motivo, null);
                n++;
            }
        }
        return n;
    }

    @Override
    public synchronized int removerTodosDoUsuario(UUID usuarioId) {
        int antes = porId.size();
        porId.values().removeIf(t -> t.getUsuarioId().equals(usuarioId));
        return antes - porId.size();
    }

    /** Todos os tokens armazenados, em ordem de inserção (para asserções). */
    public synchronized List<RefreshToken> todos() {
        return new ArrayList<>(porId.values());
    }

    public synchronized List<RefreshToken> daFamilia(UUID familiaId) {
        return porId.values().stream().filter(t -> t.getFamiliaId().equals(familiaId)).toList();
    }

    public synchronized List<RefreshToken> doUsuario(UUID usuarioId) {
        return porId.values().stream().filter(t -> t.getUsuarioId().equals(usuarioId)).toList();
    }

    public synchronized long ativos(Instant agora) {
        return porId.values().stream().filter(t -> t.ativoEm(agora)).count();
    }

    private static void revogar(RefreshToken t, Instant agora, MotivoRevogacao motivo, UUID substitutoId) {
        definir(t, "revogadoEm", agora);
        definir(t, "motivoRevogacao", motivo);
        if (substitutoId != null) {
            definir(t, "substituidoPorId", substitutoId);
        }
    }

    private static void definir(RefreshToken t, String campo, Object valor) {
        try {
            Field f = RefreshToken.class.getDeclaredField(campo);
            f.setAccessible(true);
            f.set(t, valor);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Falha ao definir " + campo + " em RefreshToken", e);
        }
    }
}
