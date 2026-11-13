package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;
import dev.gilberto.gestaousuarios.protecao.ForcaBrutaService;
import dev.gilberto.gestaousuarios.protecao.LockoutProperties;
import dev.gilberto.gestaousuarios.shared.exceptions.LimiteExcedidoException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import dev.gilberto.gestaousuarios.testsupport.AuditoriaFalsa;
import dev.gilberto.gestaousuarios.testsupport.RelogioFalso;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class AuthServiceEnumeracaoPropertyTest {

    private static final ContextoCliente CLIENTE = new ContextoCliente("127.0.0.1", "JUnit");
    private static final String SENHA_CORRETA = "SenhaCorreta#123";
    private static final String HASH_USUARIO = "HASH_USUARIO";
    private static final String HASH_FICTICIO = "HASH_FICTICIO";

    /** Encoder espião: conta execuções de matches; só a senha correta confere com o hash do usuário. */
    static final class EncoderContador implements PasswordEncoder {
        final AtomicInteger matches = new AtomicInteger();

        @Override
        public String encode(CharSequence raw) {
            return "enc:" + raw;
        }

        @Override
        public boolean matches(CharSequence raw, String encoded) {
            matches.incrementAndGet();
            return HASH_USUARIO.equals(encoded) && SENHA_CORRETA.contentEquals(raw);
        }
    }

    /** Observação externa de uma tentativa. */
    record Observacao(String tipo, String mensagem, Duration retryAfter, int execucoesMatches) { }

    /** Cenário completo: serviço + dependências reais/fakes. */
    static final class Cenario {
        final EncoderContador encoder = new EncoderContador();
        final RelogioFalso relogio = new RelogioFalso();
        final AuditoriaFalsa auditoria = new AuditoriaFalsa();
        final AuthService service;

        Cenario(String email, boolean existe, int maxAttempts) {
            UsuarioRepository repo = mock(UsuarioRepository.class);
            if (existe) {
                when(repo.findByEmail(email)).thenReturn(Optional.of(new Usuario(email, "Nome", HASH_USUARIO, Perfil.USER)));
            } else {
                when(repo.findByEmail(email)).thenReturn(Optional.empty());
            }
            HashFicticio hashFicticio = mock(HashFicticio.class);
            when(hashFicticio.valor()).thenReturn(HASH_FICTICIO);
            SessaoService sessao = mock(SessaoService.class);
            when(sessao.iniciar(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
                    .thenReturn(new TokenResponse("T", "R", "Bearer", 900L, 604800L));
            ForcaBrutaService fb = new ForcaBrutaService(
                    new LockoutProperties(maxAttempts, Duration.ofMinutes(15), Duration.ofMinutes(15)), relogio);
            this.service = new AuthService(repo, encoder, sessao, fb, hashFicticio, auditoria);
        }

    }

    @Provide
    Arbitrary<String> emails() {
        return Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(12).map(s -> s.toLowerCase() + "@mail.com");
    }

    @Provide
    Arbitrary<List<String>> senhasInvalidas() {
        return Arbitraries.strings().ascii().ofMinLength(1).ofMaxLength(20)
                .filter(s -> !s.equals(SENHA_CORRETA)).list().ofMinSize(1).ofMaxSize(12);
    }

    @Provide
    Arbitrary<List<Integer>> avancosSegundos() {
        return Arbitraries.integers().between(0, 30).list().ofSize(12);
    }

    private static List<Observacao> executar(Cenario c, String email, List<String> senhas, List<Integer> avancos) {
        List<Observacao> obs = new ArrayList<>();
        for (int i = 0; i < senhas.size(); i++) {
            c.relogio.avancar(Duration.ofSeconds(avancos.get(i)));
            obs.add(tentarComEmail(c, email, senhas.get(i)));
        }
        return obs;
    }

    private static Observacao tentarComEmail(Cenario c, String email, String senha) {
        int antes = c.encoder.matches.get();
        try {
            c.service.autenticar(new LoginRequest(email, senha), CLIENTE);
            return new Observacao("OK", null, null, c.encoder.matches.get() - antes);
        } catch (BadCredentialsException e) {
            return new Observacao("BAD_CREDENTIALS", e.getMessage(), null, c.encoder.matches.get() - antes);
        } catch (LimiteExcedidoException e) {
            return new Observacao("BLOQUEADO", e.getMessage(), e.getRetryAfter(), c.encoder.matches.get() - antes);
        }
    }

    // Feature: endurecimento-autenticacao, Property 13: Login não distingue e-mail existente de inexistente
    // Validates: Requirements 9.7, 11.2, 11.5
    @Property(tries = 200)
    void mesmaSequenciaInvalidaProduzMesmaRespostaObservavel(
            @ForAll("emails") String email,
            @ForAll("senhasInvalidas") List<String> senhas,
            @ForAll("avancosSegundos") List<Integer> avancos,
            @ForAll @net.jqwik.api.constraints.IntRange(min = 1, max = 6) int maxAttempts) {
        Cenario existente = new Cenario(email, true, maxAttempts);
        Cenario inexistente = new Cenario(email, false, maxAttempts);

        List<Observacao> obsExistente = executar(existente, email, senhas, avancos);
        List<Observacao> obsInexistente = executar(inexistente, email, senhas, avancos);

        // Resposta idêntica (tipo, mensagem, Retry-After e nº de execuções de matches) a cada tentativa
        assertThat(obsExistente).isEqualTo(obsInexistente);

        String msgCredenciais = Mensagens.get("user.invalid.credentials");
        boolean bloqueada = false;
        int falhasNaJanela = 0;
        for (Observacao o : obsExistente) {
            if (o.tipo().equals("BLOQUEADO")) {
                bloqueada = true;
                assertThat(o.execucoesMatches()).isZero();
                assertThat(o.retryAfter()).isNotNull();
                assertThat(o.retryAfter().getSeconds()).isGreaterThanOrEqualTo(1);
            } else if (!bloqueada) {
                assertThat(o.tipo()).isEqualTo("BAD_CREDENTIALS");
                assertThat(o.mensagem()).isEqualTo(msgCredenciais);
                assertThat(o.execucoesMatches()).isEqualTo(1);
                falhasNaJanela++;
            }
        }
        // As avanços totais (<= 360 s) ficam dentro da janela de 15 min: o bloqueio inicia exatamente em maxAttempts falhas
        if (senhas.size() > maxAttempts) {
            assertThat(obsExistente.get(maxAttempts).tipo()).isEqualTo("BLOQUEADO");
            assertThat(obsExistente.get(maxAttempts - 1).tipo()).isEqualTo("BAD_CREDENTIALS");
        }
        assertThat(falhasNaJanela).isLessThanOrEqualTo(maxAttempts);

        // Auditoria equivalente (mesmos tipos, mesma ordem) nos dois cenários
        assertThat(existente.auditoria.eventos().stream().map(e -> e.tipo()).toList())
                .isEqualTo(inexistente.auditoria.eventos().stream().map(e -> e.tipo()).toList());
        assertThat(existente.auditoria.contar(TipoEventoSeguranca.LOGIN_BLOQUEADO))
                .isEqualTo(inexistente.auditoria.contar(TipoEventoSeguranca.LOGIN_BLOQUEADO));
    }

    // Feature: endurecimento-autenticacao, Property 13: Login não distingue e-mail existente de inexistente
    // Validates: Requirements 9.7, 11.2, 11.5
    @Property(tries = 100)
    void contaBloqueadaRejeitaMesmoComSenhaCorretaSemExecutarBcrypt(
            @ForAll("emails") String email,
            @ForAll @net.jqwik.api.constraints.IntRange(min = 1, max = 6) int maxAttempts,
            @ForAll boolean existe) {
        Cenario c = new Cenario(email, existe, maxAttempts);
        for (int i = 0; i < maxAttempts; i++) {
            assertThat(tentarComEmail(c, email, "errada-" + i).tipo()).isEqualTo("BAD_CREDENTIALS");
        }
        int antes = c.encoder.matches.get();
        Observacao o = tentarComEmail(c, email, SENHA_CORRETA);
        assertThat(o.tipo()).isEqualTo("BLOQUEADO");
        assertThat(o.mensagem()).isEqualTo(Mensagens.get("login.bloqueado"));
        assertThat(c.encoder.matches.get()).isEqualTo(antes);
        assertThat(o.retryAfter()).isEqualTo(Duration.ofMinutes(15));
    }
}
