package dev.gilberto.gestaousuarios.integration;

import dev.gilberto.gestaousuarios.auth.MotivoRevogacao;
import dev.gilberto.gestaousuarios.auth.RefreshToken;
import dev.gilberto.gestaousuarios.auth.RefreshTokenRepository;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Risco 10 do design (tarefa 19.2): compatibilidade {@code Instant} x coluna {@code TIMESTAMP}
 * (sem fuso). Prova que o instante gravado volta idêntico pelo JPA, que o valor cru no banco é o
 * instante em UTC (independente do fuso da JVM e do servidor) e que a comparação
 * {@code expira_em > :agora} do UPDATE condicional da rotação respeita o instante.
 *
 * <p>Deve ser executado com fusos de JVM diferentes (-Duser.timezone=UTC e America/Sao_Paulo).
 */
@SpringBootTest
class InstantTimestampIT extends AbstractPostgresIT {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private UsuarioRepository usuarioRepository;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private TransactionTemplate tx;

    /** O @Modifying exige transação (em produção vem do @Transactional do SessaoService). */
    private int consumir(UUID id, Instant agora, UUID novoId, MotivoRevogacao motivo) {
        return tx.execute(s -> refreshTokenRepository.consumirSeAtivo(id, agora, novoId, motivo));
    }

    private RefreshToken novoToken(Instant criadoEm, Instant expiraEm) {
        Usuario u = usuarioRepository.save(new Usuario(
                "instant." + UUID.randomUUID() + "@fuso.it", "Fuso IT", "hash-irrelevante", Perfil.USER));
        return refreshTokenRepository.save(new RefreshToken(UUID.randomUUID(), u.getId(),
                UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", ""),
                UUID.randomUUID(), criadoEm, expiraEm, "ua", "127.0.0.1"));
    }

    @Test
    void instantGravadoVoltaIdenticoEOValorCruNoBancoEEmUtc() {
        Instant criado = Instant.parse("2030-06-15T23:30:45.123456Z");
        Instant expira = criado.plus(Duration.ofDays(7));
        RefreshToken salvo = novoToken(criado, expira);

        RefreshToken lido = refreshTokenRepository.findById(salvo.getId()).orElseThrow();
        assertThat(lido.getCriadoEm()).isEqualTo(criado);
        assertThat(lido.getExpiraEm()).isEqualTo(expira);

        // Valor cru da coluna (texto): deve ser o relógio de parede em UTC, sem conversão de fuso.
        String cru = jdbc.queryForObject(
                "SELECT to_char(criado_em, 'YYYY-MM-DD\"T\"HH24:MI:SS.US') FROM refresh_tokens WHERE id = ?",
                String.class, salvo.getId());
        assertThat(cru).isEqualTo("2030-06-15T23:30:45.123456");
    }

    @Test
    void comparacaoDeExpiracaoDoUpdateCondicionalRespeitaOInstante() {
        Instant base = Instant.now().truncatedTo(ChronoUnit.MICROS);
        Instant expira = base.plus(Duration.ofMinutes(10));
        RefreshToken token = novoToken(base, expira);

        // agora = expira - 1s (ainda ativo): consome.
        int consumido = consumir(
                token.getId(), expira.minusSeconds(1), UUID.randomUUID(), MotivoRevogacao.ROTACAO);
        assertThat(consumido).isEqualTo(1);

        // agora = expira + 1s (expirado): não consome. Token novo, pois o anterior já foi revogado.
        RefreshToken outro = novoToken(base, expira);
        assertThat(consumir(
                outro.getId(), expira.plusSeconds(1), UUID.randomUUID(), MotivoRevogacao.ROTACAO)).isZero();

        // agora == expira: a condição é estrita (expira_em > agora), logo não consome.
        RefreshToken igual = novoToken(base, expira);
        assertThat(consumir(
                igual.getId(), expira, UUID.randomUUID(), MotivoRevogacao.ROTACAO)).isZero();

        // Um desvio de fuso apareceria como diferença de horas: expira - 3h ou + 3h trocaria o resultado.
        RefreshToken tres = novoToken(base, expira);
        assertThat(consumir(
                tres.getId(), expira.plus(Duration.ofHours(3)), UUID.randomUUID(), MotivoRevogacao.ROTACAO)).isZero();
        RefreshToken quatro = novoToken(base, expira);
        assertThat(consumir(
                quatro.getId(), expira.minus(Duration.ofHours(3)), UUID.randomUUID(), MotivoRevogacao.ROTACAO))
                .isEqualTo(1);
    }

    @Test
    void relidoRevogadoEmVoltaIdentico() {
        Instant base = Instant.parse("2031-01-01T02:59:59.999999Z");
        RefreshToken token = novoToken(base, base.plus(Duration.ofDays(1)));
        Instant agora = base.plusSeconds(5);

        assertThat(consumir(
                token.getId(), agora, UUID.randomUUID(), MotivoRevogacao.ROTACAO)).isEqualTo(1);

        assertThat(refreshTokenRepository.findById(token.getId()).orElseThrow().getRevogadoEm())
                .isEqualTo(agora);
    }
}
