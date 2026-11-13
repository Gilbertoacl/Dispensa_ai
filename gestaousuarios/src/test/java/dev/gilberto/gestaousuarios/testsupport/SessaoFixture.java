package dev.gilberto.gestaousuarios.testsupport;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.mockito.invocation.InvocationOnMock;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

import dev.gilberto.gestaousuarios.auth.ContextoCliente;
import dev.gilberto.gestaousuarios.auth.RefreshProperties;
import dev.gilberto.gestaousuarios.auth.SessaoService;
import dev.gilberto.gestaousuarios.auth.TokenService;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;

/**
 * Monta um {@link SessaoService} real sobre fakes em memória (store, auditoria, relógio) e um
 * {@link UsuarioRepository} simulado com estado em mapa. Sem BCrypt e sem banco.
 */
public class SessaoFixture {

    public static final ContextoCliente CLIENTE = new ContextoCliente("203.0.113.7", "teste-agent");

    public final RelogioFalso relogio = new RelogioFalso();
    public final RefreshTokenStoreEmMemoria store = new RefreshTokenStoreEmMemoria();
    public final AuditoriaFalsa auditoria = new AuditoriaFalsa();
    public final UsuarioRepository usuarioRepository = mock(UsuarioRepository.class);
    public final Map<UUID, Usuario> usuarios = new HashMap<>();
    public final Map<UUID, java.time.Instant> ultimosLogins = new HashMap<>();
    public final Duration refreshDuracao;
    public final SessaoService sessao;

    public SessaoFixture() {
        this(Duration.ofDays(7));
    }

    public SessaoFixture(Duration refreshDuracao) {
        this.refreshDuracao = refreshDuracao;
        SecretKey key = new SecretKeySpec(
                "0123456789-0123456789-0123456789-xx".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        TokenService tokenService = new TokenService(encoder, 900L);

        when(usuarioRepository.findById(any(UUID.class)))
                .thenAnswer(inv -> Optional.ofNullable(usuarios.get(inv.getArgument(0, UUID.class))));
        when(usuarioRepository.buscarTokenVersion(any(UUID.class))).thenAnswer(inv -> Optional
                .ofNullable(usuarios.get(inv.getArgument(0, UUID.class))).map(Usuario::getTokenVersion));
        when(usuarioRepository.incrementarTokenVersion(any(UUID.class))).thenAnswer(this::incrementar);
        when(usuarioRepository.registrarUltimoLogin(any(UUID.class), any(java.time.Instant.class)))
                .thenAnswer(inv -> {
                    UUID id = inv.getArgument(0, UUID.class);
                    ultimosLogins.put(id, inv.getArgument(1, java.time.Instant.class));
                    return usuarios.containsKey(id) ? 1 : 0;
                });

        this.sessao = new SessaoService(store, usuarioRepository, tokenService,
                new RefreshProperties(refreshDuracao), auditoria, relogio, new SecureRandom());
    }

    public Usuario novoUsuario(Perfil perfil) {
        Usuario u = new Usuario("u" + UUID.randomUUID() + "@teste.com", "Nome", "hash", perfil);
        definir(u, "id", UUID.randomUUID());
        usuarios.put(u.getId(), u);
        return u;
    }

    public void removerUsuario(UUID id) {
        usuarios.remove(id);
    }

    public void definirTokenVersion(Usuario u, int valor) {
        definir(u, "tokenVersion", valor);
    }

    private Object incrementar(InvocationOnMock inv) {
        Usuario u = usuarios.get(inv.getArgument(0, UUID.class));
        if (u == null) {
            return 0;
        }
        definir(u, "tokenVersion", u.getTokenVersion() + 1);
        return 1;
    }

    private static void definir(Usuario u, String campo, Object valor) {
        try {
            Field f = Usuario.class.getDeclaredField(campo);
            f.setAccessible(true);
            f.set(u, valor);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }
}
