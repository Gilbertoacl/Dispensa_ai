package dev.gilberto.gestaousuarios.auth;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import dev.gilberto.gestaousuarios.auditoria.AuditoriaSeguranca;
import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;
import dev.gilberto.gestaousuarios.shared.exceptions.TokenInvalidoException;
import dev.gilberto.gestaousuarios.shared.exceptions.TokenReutilizadoException;
import dev.gilberto.gestaousuarios.usuario.RevogadorDeSessoes;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;

/**
 * Ciclo de vida das sessões: emissão do par de tokens, rotação do refresh token com detecção de
 * reuso, logout e logout global. Só o hash SHA-256 do refresh token é persistido.
 */
@Service
public class SessaoService implements RevogadorDeSessoes {

    private final RefreshTokenStore store;
    private final UsuarioRepository usuarioRepository;
    private final TokenService tokenService;
    private final RefreshProperties refreshProperties;
    private final AuditoriaSeguranca auditoria;
    private final Clock clock;
    private final SecureRandom secureRandom;

    public SessaoService(RefreshTokenStore store, UsuarioRepository usuarioRepository, TokenService tokenService,
                         RefreshProperties refreshProperties, AuditoriaSeguranca auditoria, Clock clock,
                         SecureRandom secureRandom) {
        this.store = store;
        this.usuarioRepository = usuarioRepository;
        this.tokenService = tokenService;
        this.refreshProperties = refreshProperties;
        this.auditoria = auditoria == null ? AuditoriaSeguranca.semEfeito() : auditoria;
        this.clock = clock;
        this.secureRandom = secureRandom;
    }

    /** Login: abre uma nova família de refresh tokens e emite o par de tokens. */
    @Transactional
    public TokenResponse iniciar(Usuario usuario, ContextoCliente cliente) {
        Instant agora = clock.instant();
        TokenResponse resposta = emitirPar(usuario, UUID.randomUUID(), agora, cliente);
        usuarioRepository.registrarUltimoLogin(usuario.getId(), agora);
        auditoria.registrar(TipoEventoSeguranca.LOGIN_SUCESSO, usuario.getId(), null);
        return resposta;
    }

    /**
     * Rotação do refresh token. A revogação da família em caso de reuso é confirmada mesmo com a
     * resposta 401 ({@code noRollbackFor}).
     */
    @Transactional(noRollbackFor = TokenInvalidoException.class)
    public TokenResponse renovar(String refreshClaro, ContextoCliente cliente) {
        String hash = TokenOpaco.hash(refreshClaro);
        // Duas passagens no máximo: se perder a corrida do UPDATE, relê o token uma vez.
        for (int tentativa = 0; tentativa < 2; tentativa++) {
            Instant agora = clock.instant();
            RefreshToken atual = store.buscarPorHash(hash)
                    .orElseThrow(() -> new TokenInvalidoException("refresh.invalido"));
            if (atual.getSubstituidoPorId() != null) {
                store.revogarFamilia(atual.getFamiliaId(), agora, MotivoRevogacao.REUSO);
                auditoria.registrar(TipoEventoSeguranca.REFRESH_REUSO_DETECTADO, atual.getUsuarioId(),
                        "familiaId=" + atual.getFamiliaId());
                throw new TokenReutilizadoException();
            }
            if (atual.getRevogadoEm() != null) {
                throw new TokenInvalidoException("refresh.invalido");
            }
            if (!atual.getExpiraEm().isAfter(agora)) {
                throw new TokenInvalidoException("refresh.expirado");
            }
            Optional<Usuario> usuario = usuarioRepository.findById(atual.getUsuarioId());
            if (usuario.isEmpty()) {
                throw new TokenInvalidoException("refresh.invalido");
            }
            UUID novoId = UUID.randomUUID();
            if (store.consumirSeAtivo(atual.getId(), agora, novoId) == 1) {
                TokenResponse resposta = emitirPar(usuario.get(), atual.getFamiliaId(), novoId, agora, cliente);
                auditoria.registrar(TipoEventoSeguranca.REFRESH_SUCESSO, usuario.get().getId(),
                        "familiaId=" + atual.getFamiliaId());
                return resposta;
            }
        }
        throw new TokenInvalidoException("refresh.invalido");
    }

    /** Logout: revoga a família do token, se ele estiver ativo; caso contrário não faz nada. */
    @Transactional
    public void encerrar(String refreshClaro) {
        Instant agora = clock.instant();
        store.buscarPorHash(TokenOpaco.hash(refreshClaro))
                .filter(t -> t.ativoEm(agora))
                .ifPresent(t -> {
                    store.revogarFamilia(t.getFamiliaId(), agora, MotivoRevogacao.LOGOUT);
                    auditoria.registrar(TipoEventoSeguranca.LOGOUT, t.getUsuarioId(), null);
                });
    }

    /** Logout global: revoga todos os refresh tokens e invalida os access tokens via {@code tokenVersion}. */
    @Transactional
    public void encerrarTodas(UUID usuarioId) {
        store.revogarTodosDoUsuario(usuarioId, clock.instant(), MotivoRevogacao.LOGOUT_TODOS);
        usuarioRepository.incrementarTokenVersion(usuarioId);
        auditoria.registrar(TipoEventoSeguranca.LOGOUT_TODOS, usuarioId, null);
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public void revogarTodas(UUID usuarioId, MotivoRevogacao motivo) {
        store.revogarTodosDoUsuario(usuarioId, clock.instant(), motivo);
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public void removerTodas(UUID usuarioId) {
        store.removerTodosDoUsuario(usuarioId);
    }

    private TokenResponse emitirPar(Usuario usuario, UUID familiaId, Instant agora, ContextoCliente cliente) {
        return emitirPar(usuario, familiaId, UUID.randomUUID(), agora, cliente);
    }

    private TokenResponse emitirPar(Usuario usuario, UUID familiaId, UUID tokenId, Instant agora,
                                    ContextoCliente cliente) {
        String claro = TokenOpaco.gerar(secureRandom);
        Instant expiraEm = agora.plus(refreshProperties.expiration());
        String ip = cliente == null ? null : cliente.ip();
        String userAgent = cliente == null ? null : cliente.userAgent();
        store.salvar(new RefreshToken(tokenId, usuario.getId(), TokenOpaco.hash(claro), familiaId, agora,
                expiraEm, userAgent, ip));
        String accessToken = tokenService.emitir(usuario);
        return new TokenResponse(accessToken, claro, "Bearer", tokenService.getExpirationSeconds(),
                refreshProperties.expiration().toSeconds());
    }
}
