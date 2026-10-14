package dev.gilberto.gestaousuarios.usuario;

import dev.gilberto.gestaousuarios.shared.exceptions.RecursoNaoEncontradoException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    public UsuarioResponse buscarUsuarioPorId(UUID id) {
        Usuario user = usuarioRepository.findById(id).orElseThrow(() -> new RecursoNaoEncontradoException(Mensagens.get("user.nao.encontrado")));
        return  new UsuarioResponse(user.getEmail(), user.getNome(), user.getDataCriacao());
    }

    public UsuarioResponse criarUsuario(UsuarioRequest req) {
        if (usuarioRepository.findByEmail(req.email()).isPresent()) {
            throw new RecursoNaoEncontradoException(Mensagens.get("user.email.registrado"));
        }

        Usuario user = usuarioRepository.save(new Usuario(req.email(), req.nome(), req.senha()));

        return  new UsuarioResponse(user.getEmail(), user.getNome(), user.getDataCriacao());
    }
}
