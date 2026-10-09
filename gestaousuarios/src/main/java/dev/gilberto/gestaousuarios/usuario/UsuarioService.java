package dev.gilberto.gestaousuarios.usuario;

import dev.gilberto.gestaousuarios.shared.exceptions.RecursoNaoEncontradoException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    public Usuario buscarUsuarioPorId(UUID id) {
        return usuarioRepository.findById(id).orElseThrow(() -> new RecursoNaoEncontradoException("{user.notfound}"));
    }

    public Usuario criarUsuario(UsuarioRequest req) {
        if (usuarioRepository.findByEmail(req.email()).isPresent()) {
            throw new RecursoNaoEncontradoException("{user.email.invalid}");
        }

        Usuario user = new Usuario(req.email(), req.nome(), req.senha());

        return usuarioRepository.save(user);
    }
}
