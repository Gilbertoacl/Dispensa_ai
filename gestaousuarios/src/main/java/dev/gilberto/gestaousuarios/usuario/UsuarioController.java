package dev.gilberto.gestaousuarios.usuario;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/v1")
public class UsuarioController {
    private final UsuarioService usuarioService;

    public UsuarioController(UsuarioService usuarioService) {
        this.usuarioService = usuarioService;
    }

    @PostMapping("/usuarios")
    public ResponseEntity<UsuarioResponse> criarUsuario(@Valid @RequestBody UsuarioRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(usuarioService.criarUsuario(request));
    }

    @GetMapping("/me")
    public ResponseEntity<UsuarioResponse> getUsuarioLogado(@AuthenticationPrincipal Jwt jwt) {
        UUID id = UUID.fromString(jwt.getSubject());
        return ResponseEntity.ok(usuarioService.buscarPorId(id));
    }

    @PutMapping("/me")
    public ResponseEntity<UsuarioResponse> atualizarPerfil(@AuthenticationPrincipal Jwt jwt,
                                                           @Valid @RequestBody AtualizarPerfilRequest req) {
        UUID id = UUID.fromString(jwt.getSubject());
        return ResponseEntity.ok(usuarioService.atualizarNome(id, req.nome()));
    }

    @PutMapping("/me/senha")
    public ResponseEntity<Void> trocarSenha(@AuthenticationPrincipal Jwt jwt,
                                            @Valid @RequestBody TrocarSenhaRequest req) {
        UUID id = UUID.fromString(jwt.getSubject());
        usuarioService.trocarSenha(id, req.senhaAtual(), req.novaSenha());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/usuarios")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UsuarioResponse>> listar(@PageableDefault(size = 20) Pageable pageable) {
        return ResponseEntity.ok(usuarioService.listar(pageable));
    }

    @GetMapping("/usuarios/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Consulta um usuário pelo id (ADMIN)")
    @ApiResponse(responseCode = "200", description = "Usuário encontrado")
    @ApiResponse(responseCode = "400", description = "Id inválido")
    @ApiResponse(responseCode = "401", description = "Não autenticado")
    @ApiResponse(responseCode = "403", description = "Acesso negado")
    @ApiResponse(responseCode = "404", description = "Usuário não encontrado")
    public ResponseEntity<UsuarioResponse> buscarPorId(@PathVariable UUID id) {
        return ResponseEntity.ok(usuarioService.buscarPorId(id));
    }

    @PutMapping("/usuarios/{id}/perfil")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Altera o perfil de um usuário (ADMIN)")
    @ApiResponse(responseCode = "200", description = "Perfil alterado")
    @ApiResponse(responseCode = "400", description = "Id ou perfil inválido")
    @ApiResponse(responseCode = "401", description = "Não autenticado")
    @ApiResponse(responseCode = "403", description = "Acesso negado")
    @ApiResponse(responseCode = "404", description = "Usuário não encontrado")
    @ApiResponse(responseCode = "409", description = "Não é possível rebaixar o último ADMIN")
    public ResponseEntity<UsuarioResponse> alterarPerfil(@PathVariable UUID id,
                                                         @Valid @RequestBody AlterarPerfilRequest req,
                                                         @AuthenticationPrincipal Jwt jwt) {
        // O @Pattern do request garante ADMIN|USER, então valueOf não lança exceção.
        Perfil novo = Perfil.valueOf(req.perfil());
        return ResponseEntity.ok(usuarioService.alterarPerfil(id, novo, UUID.fromString(jwt.getSubject())));
    }

    @DeleteMapping("/usuarios/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> excluir(@PathVariable UUID id) {
        usuarioService.excluir(id);
        return ResponseEntity.noContent().build();
    }
}
