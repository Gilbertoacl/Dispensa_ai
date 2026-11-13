package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;
import dev.gilberto.gestaousuarios.shared.exceptions.TokenInvalidoException;
import dev.gilberto.gestaousuarios.shared.exceptions.TokenReutilizadoException;
import dev.gilberto.gestaousuarios.testsupport.SessaoFixture;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;

// Validates: Requirements 1.9, 2.8, 2.9, 3.3, 4.6, 16.4
class SessaoServiceTest {

    private SessaoFixture fx;
    private Usuario usuario;

    @BeforeEach
    void preparar() {
        fx = new SessaoFixture();
        usuario = fx.novoUsuario(Perfil.USER);
    }

    private RefreshToken tokenDe(String claro) {
        return fx.store.buscarPorHash(TokenOpaco.hash(claro)).orElseThrow();
    }

    @Test
    void loginCriaFamiliaNovaEPersisteSoOHash() {
        TokenResponse a = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        TokenResponse b = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);

        RefreshToken ta = tokenDe(a.refreshToken());
        RefreshToken tb = tokenDe(b.refreshToken());
        assertThat(ta.getFamiliaId()).isNotEqualTo(tb.getFamiliaId());
        assertThat(ta.getTokenHash()).isNotEqualTo(a.refreshToken()).hasSize(64);
        assertThat(ta.getExpiraEm()).isEqualTo(fx.relogio.instant().plus(Duration.ofDays(7)));
        assertThat(a.tokenType()).isEqualTo("Bearer");
        assertThat(a.expiraEm()).isEqualTo(900L);
        assertThat(a.refreshExpiraEm()).isEqualTo(Duration.ofDays(7).toSeconds());
    }

    @Test
    void loginRegistraUltimoLoginEEvento() {
        fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);

        assertThat(fx.ultimosLogins).containsEntry(usuario.getId(), fx.relogio.instant());
        assertThat(fx.auditoria.eventosDo(TipoEventoSeguranca.LOGIN_SUCESSO)).hasSize(1);
    }

    @Test
    void refreshRotacionaMantendoAFamilia() {
        TokenResponse login = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        UUID familia = tokenDe(login.refreshToken()).getFamiliaId();

        TokenResponse novo = fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE);

        assertThat(novo.refreshToken()).isNotEqualTo(login.refreshToken());
        RefreshToken antigo = tokenDe(login.refreshToken());
        RefreshToken atual = tokenDe(novo.refreshToken());
        assertThat(atual.getFamiliaId()).isEqualTo(familia);
        assertThat(antigo.getRevogadoEm()).isNotNull();
        assertThat(antigo.getMotivoRevogacao()).isEqualTo(MotivoRevogacao.ROTACAO);
        assertThat(antigo.getSubstituidoPorId()).isEqualTo(atual.getId());
        assertThat(atual.ativoEm(fx.relogio.instant())).isTrue();
        assertThat(fx.auditoria.contar(TipoEventoSeguranca.REFRESH_SUCESSO)).isEqualTo(1);
    }

    @Test
    void refreshExpiradoNoInstanteExatoELogoDepois() {
        TokenResponse login = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        fx.relogio.avancar(Duration.ofDays(7));

        assertThatThrownBy(() -> fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE))
                .isInstanceOf(TokenInvalidoException.class)
                .isNotInstanceOf(TokenReutilizadoException.class)
                .extracting(e -> ((TokenInvalidoException) e).getChave()).isEqualTo("refresh.expirado");

        fx.relogio.avancar(Duration.ofSeconds(1));
        assertThatThrownBy(() -> fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE))
                .extracting(e -> ((TokenInvalidoException) e).getChave()).isEqualTo("refresh.expirado");
    }

    @Test
    void refreshUmSegundoAntesDeExpirarFunciona() {
        TokenResponse login = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        fx.relogio.avancar(Duration.ofDays(7).minusSeconds(1));

        assertThatCode(() -> fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE))
                .doesNotThrowAnyException();
    }

    @Test
    void tokenInexistenteEInvalido() {
        assertThatThrownBy(() -> fx.sessao.renovar("nao-existe", SessaoFixture.CLIENTE))
                .isInstanceOf(TokenInvalidoException.class)
                .extracting(e -> ((TokenInvalidoException) e).getChave()).isEqualTo("refresh.invalido");
    }

    @Test
    void usuarioRemovidoEInvalido() {
        TokenResponse login = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        fx.removerUsuario(usuario.getId());

        assertThatThrownBy(() -> fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE))
                .isInstanceOf(TokenInvalidoException.class)
                .extracting(e -> ((TokenInvalidoException) e).getChave()).isEqualTo("refresh.invalido");
    }

    @Test
    void reusoRevogaFamiliaRegistraEventoEPreservaOutrasFamilias() {
        TokenResponse outra = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        TokenResponse login = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        UUID familia = tokenDe(login.refreshToken()).getFamiliaId();
        TokenResponse novo = fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE);

        assertThatThrownBy(() -> fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE))
                .isInstanceOf(TokenReutilizadoException.class);

        assertThat(tokenDe(novo.refreshToken()).getRevogadoEm()).isNotNull();
        assertThat(tokenDe(novo.refreshToken()).getMotivoRevogacao()).isEqualTo(MotivoRevogacao.REUSO);
        assertThat(fx.store.daFamilia(familia)).allMatch(t -> !t.ativoEm(fx.relogio.instant()));
        assertThat(tokenDe(outra.refreshToken()).ativoEm(fx.relogio.instant())).isTrue();
        List<?> eventos = fx.auditoria.eventosDo(TipoEventoSeguranca.REFRESH_REUSO_DETECTADO);
        assertThat(eventos).hasSize(1);
        assertThat(fx.auditoria.eventosDo(TipoEventoSeguranca.REFRESH_REUSO_DETECTADO).get(0).detalhe())
                .contains(familia.toString());
        // o token novo (da família revogada) também não renova mais
        assertThatThrownBy(() -> fx.sessao.renovar(novo.refreshToken(), SessaoFixture.CLIENTE))
                .isInstanceOf(TokenInvalidoException.class);
    }

    @Test
    void reusoTemPrecedenciaSobreExpiracao() {
        TokenResponse login = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE);
        fx.relogio.avancar(Duration.ofDays(8));

        assertThatThrownBy(() -> fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE))
                .isInstanceOf(TokenReutilizadoException.class);
    }

    @Test
    void logoutRevogaFamiliaEEIdempotente() {
        TokenResponse login = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        TokenResponse outra = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);

        fx.sessao.encerrar(login.refreshToken());
        fx.sessao.encerrar(login.refreshToken());
        fx.sessao.encerrar("desconhecido");

        assertThat(tokenDe(login.refreshToken()).getMotivoRevogacao()).isEqualTo(MotivoRevogacao.LOGOUT);
        assertThat(tokenDe(outra.refreshToken()).ativoEm(fx.relogio.instant())).isTrue();
        assertThat(fx.auditoria.contar(TipoEventoSeguranca.LOGOUT)).isEqualTo(1);
        assertThatThrownBy(() -> fx.sessao.renovar(login.refreshToken(), SessaoFixture.CLIENTE))
                .isInstanceOf(TokenInvalidoException.class);
    }

    @Test
    void logoutDeTokenExpiradoNaoFazNada() {
        TokenResponse login = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        fx.relogio.avancar(Duration.ofDays(8));

        fx.sessao.encerrar(login.refreshToken());

        assertThat(tokenDe(login.refreshToken()).getRevogadoEm()).isNull();
        assertThat(fx.auditoria.contar(TipoEventoSeguranca.LOGOUT)).isZero();
    }

    @Test
    void logoutGlobalIncrementaTokenVersionERevogaTudo() {
        TokenResponse a = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        TokenResponse b = fx.sessao.iniciar(usuario, SessaoFixture.CLIENTE);
        Usuario outro = fx.novoUsuario(Perfil.USER);
        TokenResponse c = fx.sessao.iniciar(outro, SessaoFixture.CLIENTE);
        int tv = usuario.getTokenVersion();

        fx.sessao.encerrarTodas(usuario.getId());

        assertThat(usuario.getTokenVersion()).isEqualTo(tv + 1);
        assertThat(outro.getTokenVersion()).isZero();
        assertThat(tokenDe(a.refreshToken()).getMotivoRevogacao()).isEqualTo(MotivoRevogacao.LOGOUT_TODOS);
        assertThat(tokenDe(b.refreshToken()).getMotivoRevogacao()).isEqualTo(MotivoRevogacao.LOGOUT_TODOS);
        assertThat(tokenDe(c.refreshToken()).ativoEm(fx.relogio.instant())).isTrue();
        assertThat(fx.auditoria.contar(TipoEventoSeguranca.LOGOUT_TODOS)).isEqualTo(1);
    }
}
