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
import net.jqwik.api.constraints.IntRange;

class ForcaBrutaServicePropertyTest {

    private static final String CHAVE = ChaveConta.de("alguem@exemplo.com");

    enum Tipo { FALHA, SUCESSO, VERIFICAR, AVANCAR }

    record Op(Tipo tipo, long deltaMs) {
    }

    record Cfg(int max, Duration janela, Duration bloqueio) {
        LockoutProperties props() {
            return new LockoutProperties(max, janela, bloqueio);
        }
    }

    @Provide
    Arbitrary<Cfg> configs() {
        return Combinators.combine(
                Arbitraries.integers().between(1, 8),
                Arbitraries.longs().between(60, 600),
                Arbitraries.longs().between(60, 600))
                .as((m, j, d) -> new Cfg(m, Duration.ofSeconds(j), Duration.ofSeconds(d)));
    }

    @Provide
    Arbitrary<List<Op>> operacoes() {
        Arbitrary<Op> falha = Arbitraries.just(new Op(Tipo.FALHA, 0));
        Arbitrary<Op> sucesso = Arbitraries.just(new Op(Tipo.SUCESSO, 0));
        Arbitrary<Op> verificar = Arbitraries.just(new Op(Tipo.VERIFICAR, 0));
        // deltas de 0 a 400 s em milissegundos (inclui frações de segundo)
        Arbitrary<Op> avancar = Arbitraries.longs().between(0, 400_000)
                .map(d -> new Op(Tipo.AVANCAR, d));
        return Arbitraries.frequencyOf(
                net.jqwik.api.Tuple.of(5, falha),
                net.jqwik.api.Tuple.of(1, sucesso),
                net.jqwik.api.Tuple.of(3, verificar),
                net.jqwik.api.Tuple.of(4, avancar)).list().ofMaxSize(60);
    }

    /** Modelo de referência: janela fixa iniciada na primeira falha; bloqueio no N-ésimo erro. */
    static final class Modelo {
        final Cfg cfg;
        int falhas;
        Instant inicio;
        Instant ate;

        Modelo(Cfg cfg) {
            this.cfg = cfg;
        }

        private void expirarBloqueio(Instant agora) {
            if (ate != null && !agora.isBefore(ate)) {
                falhas = 0;
                inicio = null;
                ate = null;
            }
        }

        Optional<Duration> verificar(Instant agora) {
            expirarBloqueio(agora);
            if (ate == null) {
                return Optional.empty();
            }
            long ms = Duration.between(agora, ate).toMillis();
            return Optional.of(Duration.ofSeconds(Math.max(1, (ms + 999) / 1000)));
        }

        boolean falha(Instant agora) {
            expirarBloqueio(agora);
            if (ate != null) {
                return false;
            }
            if (inicio == null || !agora.isBefore(inicio.plus(cfg.janela()))) {
                inicio = agora;
                falhas = 0;
            }
            falhas++;
            if (falhas >= cfg.max()) {
                ate = agora.plus(cfg.bloqueio());
                return true;
            }
            return false;
        }

        void sucesso() {
            falhas = 0;
            inicio = null;
            ate = null;
        }
    }

    // Feature: endurecimento-autenticacao, Property 12: Contador de força bruta segue o modelo de referência
    // Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.9
    @Property(tries = 200)
    void contadorSegueModeloDeReferencia(@ForAll("configs") Cfg cfg, @ForAll("operacoes") List<Op> ops) {
        RelogioFalso relogio = new RelogioFalso();
        ForcaBrutaService service = new ForcaBrutaService(cfg.props(), relogio);
        Modelo modelo = new Modelo(cfg);
        for (Op op : ops) {
            Instant agora = relogio.instant();
            switch (op.tipo()) {
                case FALHA -> assertThat(service.registrarFalha(CHAVE)).isEqualTo(modelo.falha(agora));
                case SUCESSO -> {
                    service.registrarSucesso(CHAVE);
                    modelo.sucesso();
                }
                case VERIFICAR -> assertThat(service.verificarBloqueio(CHAVE)).isEqualTo(modelo.verificar(agora));
                case AVANCAR -> relogio.avancar(Duration.ofMillis(op.deltaMs()));
            }
        }
        assertThat(service.verificarBloqueio(CHAVE)).isEqualTo(modelo.verificar(relogio.instant()));
    }

    // Feature: endurecimento-autenticacao, Property 12: Contador de força bruta segue o modelo de referência
    // Validates: Requirements 9.1, 9.2, 9.3
    @Property(tries = 100)
    void bloqueioIniciaExatamenteNaFalhaDeNumeroIgualAoLimiar(@ForAll("configs") Cfg cfg,
            @ForAll @IntRange(min = 0, max = 59) int passoSeg) {
        RelogioFalso relogio = new RelogioFalso();
        ForcaBrutaService service = new ForcaBrutaService(cfg.props(), relogio);
        // todas as falhas ficam dentro da janela (max <= 8, passo < 60 s, janela >= 60 s => soma < janela se passo*7 < 60... limitamos)
        Duration passo = Duration.ofMillis(Math.min(passoSeg * 1000L, (cfg.janela().toMillis() - 1) / cfg.max()));
        for (int i = 1; i < cfg.max(); i++) {
            assertThat(service.registrarFalha(CHAVE)).as("falha %d não bloqueia", i).isFalse();
            assertThat(service.verificarBloqueio(CHAVE)).isEmpty();
            relogio.avancar(passo);
        }
        assertThat(service.registrarFalha(CHAVE)).isTrue();
        assertThat(service.verificarBloqueio(CHAVE)).contains(cfg.bloqueio());
        // falhas adicionais durante o bloqueio não o iniciam de novo nem o estendem
        assertThat(service.registrarFalha(CHAVE)).isFalse();
        assertThat(service.verificarBloqueio(CHAVE)).contains(cfg.bloqueio());
    }

    // Feature: endurecimento-autenticacao, Property 12: Contador de força bruta segue o modelo de referência
    // Validates: Requirements 9.4, 9.5
    @Property(tries = 100)
    void retryAfterEhRestanteArredondadoParaCimaComMinimoUm(@ForAll("configs") Cfg cfg,
            @ForAll @IntRange(min = 0, max = 700_000) int decorridoMs) {
        RelogioFalso relogio = new RelogioFalso();
        ForcaBrutaService service = new ForcaBrutaService(cfg.props(), relogio);
        for (int i = 0; i < cfg.max(); i++) {
            service.registrarFalha(CHAVE);
        }
        relogio.avancar(Duration.ofMillis(decorridoMs));
        long restanteMs = cfg.bloqueio().toMillis() - decorridoMs;
        Optional<Duration> r = service.verificarBloqueio(CHAVE);
        if (restanteMs > 0) {
            assertThat(r).contains(Duration.ofSeconds(Math.max(1, (restanteMs + 999) / 1000)));
            assertThat(r.get().getSeconds()).isGreaterThanOrEqualTo(1);
        } else {
            assertThat(r).isEmpty();
        }
    }

    // Feature: endurecimento-autenticacao, Property 12: Contador de força bruta segue o modelo de referência
    // Validates: Requirements 9.6
    @Property(tries = 100)
    void sucessoZeraOContador(@ForAll("configs") Cfg cfg) {
        RelogioFalso relogio = new RelogioFalso();
        ForcaBrutaService service = new ForcaBrutaService(cfg.props(), relogio);
        for (int i = 1; i < cfg.max(); i++) {
            service.registrarFalha(CHAVE);
        }
        service.registrarSucesso(CHAVE);
        // depois do sucesso são necessárias max falhas novamente
        for (int i = 1; i < cfg.max(); i++) {
            assertThat(service.registrarFalha(CHAVE)).isFalse();
        }
        assertThat(service.registrarFalha(CHAVE)).isTrue();
        // sucesso também libera uma chave bloqueada
        service.registrarSucesso(CHAVE);
        assertThat(service.verificarBloqueio(CHAVE)).isEmpty();
    }

    // Feature: endurecimento-autenticacao, Property 12: Contador de força bruta segue o modelo de referência
    // Validates: Requirements 9.3, 9.4
    @Property(tries = 100)
    void expiracaoDoBloqueioZeraEAceitaDeNovo(@ForAll("configs") Cfg cfg,
            @ForAll @IntRange(min = 0, max = 300) int extraSeg) {
        RelogioFalso relogio = new RelogioFalso();
        ForcaBrutaService service = new ForcaBrutaService(cfg.props(), relogio);
        for (int i = 0; i < cfg.max(); i++) {
            service.registrarFalha(CHAVE);
        }
        relogio.avancar(cfg.bloqueio().minusMillis(1));
        assertThat(service.verificarBloqueio(CHAVE)).contains(Duration.ofSeconds(1));
        relogio.avancar(Duration.ofMillis(1).plusSeconds(extraSeg));
        assertThat(service.verificarBloqueio(CHAVE)).isEmpty();
        // contador zerado: precisa de max falhas para bloquear de novo
        for (int i = 1; i < cfg.max(); i++) {
            assertThat(service.registrarFalha(CHAVE)).isFalse();
        }
        assertThat(service.registrarFalha(CHAVE)).isTrue();
    }

    // Feature: endurecimento-autenticacao, Property 12: Contador de força bruta segue o modelo de referência
    // Validates: Requirements 9.2, 9.9
    @Property(tries = 100)
    void janelaEhFixaEReiniciaSomenteAoVencer(@ForAll("configs") Cfg cfg) {
        Assume_maxAtLeast2(cfg);
        RelogioFalso relogio = new RelogioFalso();
        ForcaBrutaService service = new ForcaBrutaService(cfg.props(), relogio);
        service.registrarFalha(CHAVE); // inicia a janela
        // última falha aceita dentro da janela: faltando 1 ms para vencer; não reinicia (janela fixa)
        relogio.avancar(cfg.janela().minusMillis(1));
        for (int i = 2; i < cfg.max(); i++) {
            assertThat(service.registrarFalha(CHAVE)).isFalse();
        }
        assertThat(service.registrarFalha(CHAVE)).isTrue();

        // contraprova: se a falha chega no vencimento exato da janela, a contagem recomeça em 1
        ForcaBrutaService outro = new ForcaBrutaService(cfg.props(), relogio);
        outro.registrarFalha(CHAVE);
        relogio.avancar(cfg.bloqueio().plus(cfg.janela())); // bem depois de qualquer bloqueio/janela
        for (int i = 1; i < cfg.max(); i++) {
            assertThat(outro.registrarFalha(CHAVE)).isFalse();
        }
        assertThat(outro.registrarFalha(CHAVE)).isTrue();
    }

    private static void Assume_maxAtLeast2(Cfg cfg) {
        net.jqwik.api.Assume.that(cfg.max() >= 2);
    }

    // Feature: endurecimento-autenticacao, Property 12: Contador de força bruta segue o modelo de referência
    // Validates: Requirements 9.2
    @Property(tries = 100)
    void falhasForaDaJanelaNaoSeAcumulam(@ForAll("configs") Cfg cfg) {
        net.jqwik.api.Assume.that(cfg.max() >= 2);
        RelogioFalso relogio = new RelogioFalso();
        ForcaBrutaService service = new ForcaBrutaService(cfg.props(), relogio);
        for (int i = 1; i < cfg.max(); i++) {
            service.registrarFalha(CHAVE);
        }
        relogio.avancar(cfg.janela()); // janela vence exatamente
        assertThat(service.registrarFalha(CHAVE)).isFalse(); // recomeça em 1
        assertThat(service.verificarBloqueio(CHAVE)).isEmpty();
    }

    // Feature: endurecimento-autenticacao, Property 12: Contador de força bruta segue o modelo de referência
    // Validates: Requirements 9.9
    @Property(tries = 100)
    void chaveEhHashNormalizadoEIndependeDeExistenciaDoUsuario(
            @ForAll @net.jqwik.api.constraints.AlphaChars @net.jqwik.api.constraints.StringLength(min = 1, max = 20) String local,
            @ForAll @IntRange(min = 0, max = 3) int espacos) {
        String email = local + "@Exemplo.com";
        String variante = " ".repeat(espacos) + email.toUpperCase() + " ".repeat(espacos);
        String chave = ChaveConta.de(email);
        assertThat(chave).matches("[0-9a-f]{64}").doesNotContain(local.toLowerCase() + "@");
        assertThat(ChaveConta.de(variante)).isEqualTo(chave);

        // o serviço só enxerga a chave: o comportamento é idêntico para qualquer e-mail
        List<Boolean> a = new ArrayList<>();
        List<Boolean> b = new ArrayList<>();
        RelogioFalso r1 = new RelogioFalso();
        RelogioFalso r2 = new RelogioFalso();
        ForcaBrutaService s1 = new ForcaBrutaService(new LockoutProperties(3, Duration.ofMinutes(5), Duration.ofMinutes(5)), r1);
        ForcaBrutaService s2 = new ForcaBrutaService(new LockoutProperties(3, Duration.ofMinutes(5), Duration.ofMinutes(5)), r2);
        for (int i = 0; i < 5; i++) {
            a.add(s1.registrarFalha(ChaveConta.de(email)));
            b.add(s2.registrarFalha(ChaveConta.de("inexistente-" + local + "@outro.com")));
        }
        assertThat(a).isEqualTo(b).containsExactly(false, false, true, false, false);
        assertThat(s1.verificarBloqueio(chave)).isEqualTo(s2.verificarBloqueio(ChaveConta.de("inexistente-" + local + "@outro.com")));
    }

    // Feature: endurecimento-autenticacao, Property 12: Contador de força bruta segue o modelo de referência
    // Validates: Requirements 9.10
    @Property(tries = 100)
    void limparRemoveSomenteEntradasVencidas(@ForAll("configs") Cfg cfg, @ForAll @IntRange(min = 1, max = 10) int contas) {
        RelogioFalso relogio = new RelogioFalso();
        ForcaBrutaService service = new ForcaBrutaService(cfg.props(), relogio);
        for (int c = 0; c < contas; c++) {
            service.registrarFalha(ChaveConta.de("u" + c + "@x.com")); // em janela, sem bloqueio (ou bloqueada se max=1)
        }
        assertThat(service.tamanho()).isEqualTo(contas);
        Duration vigencia = cfg.max() == 1 ? cfg.bloqueio() : cfg.janela();
        relogio.avancar(vigencia.minusMillis(1));
        service.limpar();
        assertThat(service.tamanho()).isEqualTo(contas); // ainda vigentes
        relogio.avancar(Duration.ofMillis(1));
        service.limpar();
        assertThat(service.tamanho()).isZero();
    }
}
