package dev.gilberto.gestaousuarios.auth;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import dev.gilberto.gestaousuarios.auditoria.AuditoriaSeguranca;
import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;
import dev.gilberto.gestaousuarios.protecao.ChaveConta;
import dev.gilberto.gestaousuarios.protecao.ForcaBrutaService;
import dev.gilberto.gestaousuarios.shared.exceptions.LimiteExcedidoException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;

/**
 * Autentica usuários por email/senha e delega a emissão da sessão ao {@link SessaoService}.
 *
 * <p>Email inexistente e senha incorreta resultam na MESMA {@link BadCredentialsException}
 * ({@code user.invalid.credentials}, HTTP 401), com exatamente uma execução de BCrypt por
 * tentativa (hash do usuário ou hash fictício). O bloqueio por força bruta é verificado ANTES
 * do BCrypt. Não é {@code @Transactional}: o BCrypt não deve segurar conexão do pool; a
 * transação (e o evento LOGIN_SUCESSO) ficam em {@link SessaoService#iniciar}.
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessaoService sessaoService;
    private final ForcaBrutaService forcaBruta;
    private final HashFicticio hashFicticio;
    private final AuditoriaSeguranca auditoria;

    public AuthService(UsuarioRepository usuarioRepository,
                       PasswordEncoder passwordEncoder,
                       SessaoService sessaoService,
                       ForcaBrutaService forcaBruta,
                       HashFicticio hashFicticio,
                       AuditoriaSeguranca auditoria) {
        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessaoService = sessaoService;
        this.forcaBruta = forcaBruta;
        this.hashFicticio = hashFicticio;
        this.auditoria = auditoria;
    }

    /**
     * Valida as credenciais e inicia a sessão.
     *
     * @throws LimiteExcedidoException se a conta está bloqueada (429, mesmo com senha correta)
     * @throws BadCredentialsException se o email não existir ou a senha estiver incorreta (401)
     */
    public TokenResponse autenticar(LoginRequest req, ContextoCliente cliente) {
        String emailNormalizado = Usuario.normalizarEmail(req.email());
        String chave = ChaveConta.de(emailNormalizado);

        Optional<java.time.Duration> bloqueio = forcaBruta.verificarBloqueio(chave);
        if (bloqueio.isPresent()) {
            throw new LimiteExcedidoException("login.bloqueado", bloqueio.get());
        }

        Optional<Usuario> encontrado = usuarioRepository.findByEmail(emailNormalizado);
        String hash = encontrado.map(Usuario::getSenhaHash).orElseGet(hashFicticio::valor);
        boolean senhaConfere = passwordEncoder.matches(req.senha(), hash);

        if (encontrado.isEmpty() || !senhaConfere) {
            boolean iniciouBloqueio = forcaBruta.registrarFalha(chave);
            java.util.UUID usuarioId = encontrado.map(Usuario::getId).orElse(null);
            auditoria.registrar(TipoEventoSeguranca.LOGIN_FALHA, usuarioId, null);
            if (iniciouBloqueio) {
                auditoria.registrar(TipoEventoSeguranca.LOGIN_BLOQUEADO, usuarioId, null);
            }
            throw new BadCredentialsException(Mensagens.get("user.invalid.credentials"));
        }

        Usuario user = encontrado.get();
        forcaBruta.registrarSucesso(chave);
        TokenResponse resposta = sessaoService.iniciar(user, cliente);
        log.info("Usuário autenticado com id={}", user.getId());
        return resposta;
    }
}
