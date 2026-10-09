package dev.gilberto.gestaousuarios.usuario;

import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    public Usuario buscarUsuarioPorId(UUID id) {
        return usuarioRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("Usuario Não encontrado"));
    }

    public Usuario criarUsuario(UsuarioRequest req) {
        if (usuarioRepository.findByEmail(req.email()).isPresent()) {
            throw new IllegalArgumentException("Email ja castrado");
        }

        Usuario user = new Usuario(req.email(), req.nome(), req.senha());

        return usuarioRepository.save(user);
    }
}
