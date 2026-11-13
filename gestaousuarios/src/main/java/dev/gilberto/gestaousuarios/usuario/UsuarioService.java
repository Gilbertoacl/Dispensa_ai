package dev.gilberto.gestaousuarios.usuario;

import dev.gilberto.gestaousuarios.auditoria.AuditoriaSeguranca;
import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;
import dev.gilberto.gestaousuarios.auth.MotivoRevogacao;
import dev.gilberto.gestaousuarios.shared.exceptions.ConflitoException;
import dev.gilberto.gestaousuarios.shared.exceptions.RecursoNaoEncontradoException;
import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UsuarioService {

    private static final Logger log = LoggerFactory.getLogger(UsuarioService.class);

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final EventoPublisher eventoPublisher;
    private final PasswordPolicy passwordPolicy;
    private final RevogadorDeSessoes revogadorDeSessoes;
    private final AuditoriaSeguranca auditoria;

    /**
     * Construtor principal usado pelo Spring. Dependências nulas (ex.: {@code @InjectMocks} sem
     * mock correspondente) são trocadas por implementações padrão/sem efeito.
     */
    @Autowired
    public UsuarioService(UsuarioRepository usuarioRepository,
                          PasswordEncoder passwordEncoder,
                          EventoPublisher eventoPublisher,
                          PasswordPolicy passwordPolicy,
                          RevogadorDeSessoes revogadorDeSessoes,
                          AuditoriaSeguranca auditoria) {
        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
        this.eventoPublisher = eventoPublisher != null ? eventoPublisher : new NoOpEventoPublisher();
        this.passwordPolicy = passwordPolicy != null ? passwordPolicy : PasswordPolicy.padrao();
        this.revogadorDeSessoes = revogadorDeSessoes != null ? revogadorDeSessoes : RevogadorDeSessoes.semEfeito();
        this.auditoria = auditoria != null ? auditoria : AuditoriaSeguranca.semEfeito();
    }

    /** Construtor de compatibilidade (3 argumentos): política padrão, sem revogação e sem auditoria. */
    public UsuarioService(UsuarioRepository usuarioRepository,
                          PasswordEncoder passwordEncoder,
                          EventoPublisher eventoPublisher) {
        this(usuarioRepository, passwordEncoder, eventoPublisher, null, null, null);
    }

    /** Construtor de compatibilidade (2 argumentos): usa {@link NoOpEventoPublisher}. */
    public UsuarioService(UsuarioRepository usuarioRepository, PasswordEncoder passwordEncoder) {
        this(usuarioRepository, passwordEncoder, new NoOpEventoPublisher());
    }

    /** Cadastro público: o perfil é sempre USER e o tokenVersion inicial é 0. */
    @Transactional
    public UsuarioResponse criarUsuario(UsuarioRequest req) {
        String emailNormalizado = Usuario.normalizarEmail(req.email());
        if (usuarioRepository.existsByEmail(emailNormalizado)) {
            throw new ConflitoException(Mensagens.get("user.email.registrado"));
        }
        passwordPolicy.validar(req.senha(), emailNormalizado, "senha");

        String hash = passwordEncoder.encode(req.senha());
        Usuario user = usuarioRepository.save(new Usuario(req.email(), req.nome(), hash, Perfil.USER));

        log.info("Usuário criado com id={}", user.getId());

        eventoPublisher.publicarUsuarioCriado(
                new UsuarioCriadoEvent(user.getId(), user.getEmail(), user.getDataCriacao()));

        return toResponse(user);
    }

    /**
     * Cria o administrador inicial de forma idempotente. Devolve o id criado, ou vazio se o e-mail
     * já existe (inclusive em corrida). Não é transacional: a violação de unicidade é tratada fora
     * da transação do repositório.
     */
    public Optional<UUID> criarAdminInicial(String email, String nome, String senha) {
        String emailNormalizado = Usuario.normalizarEmail(email);
        if (usuarioRepository.existsByEmail(emailNormalizado)) {
            return Optional.empty();
        }
        passwordPolicy.validar(senha, emailNormalizado, "senha");

        Usuario admin;
        try {
            admin = usuarioRepository.saveAndFlush(
                    new Usuario(email, nome, passwordEncoder.encode(senha), Perfil.ADMIN));
        } catch (DataIntegrityViolationException e) {
            return Optional.empty();
        }
        eventoPublisher.publicarUsuarioCriado(
                new UsuarioCriadoEvent(admin.getId(), admin.getEmail(), admin.getDataCriacao()));
        auditoria.registrar(TipoEventoSeguranca.ADMIN_INICIAL_CRIADO, admin.getId(), null);
        return Optional.of(admin.getId());
    }

    @Transactional(readOnly = true)
    public UsuarioResponse buscarPorId(UUID id) {
        Usuario user = usuarioRepository.findById(id)
                .orElseThrow(() -> new RecursoNaoEncontradoException(Mensagens.get("user.nao.encontrado")));
        return toResponse(user);
    }

    public boolean verificarSenha(String senha, String hash) {
        return passwordEncoder.matches(senha, hash);
    }

    @Transactional(readOnly = true)
    public Page<UsuarioResponse> listar(Pageable pageable) {
        return usuarioRepository.findAll(pageable).map(this::toResponse);
    }

    @Transactional
    public UsuarioResponse atualizarNome(UUID id, String nome) {
        Usuario user = usuarioRepository.findById(id)
                .orElseThrow(() -> new RecursoNaoEncontradoException(Mensagens.get("user.nao.encontrado")));
        user.alterarNome(nome);
        user = usuarioRepository.save(user);
        return toResponse(user);
    }

    @Transactional
    public void trocarSenha(UUID id, String senhaAtual, String novaSenha) {
        Usuario user = usuarioRepository.findById(id)
                .orElseThrow(() -> new RecursoNaoEncontradoException(Mensagens.get("user.nao.encontrado")));

        if (!passwordEncoder.matches(senhaAtual, user.getSenhaHash())) {
            throw new RegraNegocioException("user.password.invalid", "senhaAtual");
        }

        passwordPolicy.validar(novaSenha, user.getEmail(), "novaSenha");

        if (passwordEncoder.matches(novaSenha, user.getSenhaHash())) {
            throw new RegraNegocioException("password.nova.igual", "novaSenha");
        }

        user.alterarSenhaHash(passwordEncoder.encode(novaSenha));
        usuarioRepository.save(user);
        usuarioRepository.incrementarTokenVersion(id);
        revogadorDeSessoes.revogarTodas(id, MotivoRevogacao.SENHA_ALTERADA);
        auditoria.registrar(TipoEventoSeguranca.SENHA_ALTERADA, id, null);
    }

    /**
     * Altera o perfil de um usuário. Rebaixar o último ADMIN é recusado (409); a verificação usa
     * lock pessimista sobre os ADMIN para ser segura sob concorrência. Invalida os access tokens
     * (tokenVersion) e revoga os refresh tokens na mesma transação.
     */
    @Transactional
    public UsuarioResponse alterarPerfil(UUID alvoId, Perfil novo, UUID executorId) {
        Usuario user = usuarioRepository.findById(alvoId)
                .orElseThrow(() -> new RecursoNaoEncontradoException(Mensagens.get("user.nao.encontrado")));
        Perfil anterior = user.getPerfil();
        if (anterior == novo) {
            return toResponse(user);
        }
        if (anterior == Perfil.ADMIN) {
            List<Usuario> admins = usuarioRepository.travarPorPerfil(Perfil.ADMIN);
            if (admins.size() <= 1) {
                throw new ConflitoException(Mensagens.get("perfil.ultimo.admin"));
            }
        }
        user.alterarPerfil(novo);
        usuarioRepository.save(user);
        usuarioRepository.incrementarTokenVersion(alvoId);
        revogadorDeSessoes.revogarTodas(alvoId, MotivoRevogacao.PERFIL_ALTERADO);
        auditoria.registrar(TipoEventoSeguranca.PERFIL_ALTERADO, alvoId,
                "executor=" + executorId + ", anterior=" + anterior + ", novo=" + novo);
        return toResponse(user);
    }

    @Transactional
    public void excluir(UUID id) {
        if (!usuarioRepository.existsById(id)) {
            throw new RecursoNaoEncontradoException(Mensagens.get("user.nao.encontrado"));
        }
        revogadorDeSessoes.removerTodas(id);
        usuarioRepository.deleteById(id);
    }

    private UsuarioResponse toResponse(Usuario u) {
        return new UsuarioResponse(u.getId(), u.getEmail(), u.getNome(), u.getPerfil(), u.getDataCriacao());
    }
}
