package dev.gilberto.gestaousuarios.auth;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;
import dev.gilberto.gestaousuarios.shared.util.ClienteIpResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

/**
 * Endpoints de autenticação: login, renovação (refresh), logout e logout global. Delega ao
 * {@link AuthService} e ao {@link SessaoService}.
 */
@RestController
@RequestMapping("/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final SessaoService sessaoService;
    private final ClienteIpResolver clienteIpResolver;

    public AuthController(AuthService authService, SessaoService sessaoService,
                          ClienteIpResolver clienteIpResolver) {
        this.authService = authService;
        this.sessaoService = sessaoService;
        this.clienteIpResolver = clienteIpResolver;
    }

    @PostMapping("/login")
    @SecurityRequirements
    @Operation(summary = "Autentica o usuário e emite o par de tokens")
    @ApiResponse(responseCode = "200", description = "Par de tokens emitido")
    @ApiResponse(responseCode = "400", description = "Requisição inválida")
    @ApiResponse(responseCode = "401", description = "Credenciais inválidas")
    @ApiResponse(responseCode = "429", description = "Limite excedido",
            headers = @Header(name = "Retry-After", schema = @Schema(type = "integer"),
                    description = "Segundos até a próxima tentativa"))
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletRequest http) {
        return ResponseEntity.ok(authService.autenticar(request, contexto(http)));
    }

    @PostMapping("/refresh")
    @SecurityRequirements
    @Operation(summary = "Renova o par de tokens (rotação do refresh token)")
    @ApiResponse(responseCode = "200", description = "Novo par de tokens emitido")
    @ApiResponse(responseCode = "400", description = "refreshToken ausente ou em branco")
    @ApiResponse(responseCode = "401", description = "Refresh token inválido, expirado ou reutilizado")
    @ApiResponse(responseCode = "429", description = "Limite excedido",
            headers = @Header(name = "Retry-After", schema = @Schema(type = "integer"),
                    description = "Segundos até a próxima tentativa"))
    public ResponseEntity<TokenResponse> refresh(@RequestBody(required = false) RefreshTokenRequest request,
                                                 HttpServletRequest http) {
        return ResponseEntity.ok(sessaoService.renovar(exigirRefresh(request), contexto(http)));
    }

    @PostMapping("/logout")
    @SecurityRequirements
    @Operation(summary = "Encerra a sessão do refresh token informado")
    @ApiResponse(responseCode = "204", description = "Sessão encerrada (ou token desconhecido)")
    @ApiResponse(responseCode = "400", description = "refreshToken ausente ou em branco")
    public ResponseEntity<Void> logout(@RequestBody(required = false) RefreshTokenRequest request) {
        sessaoService.encerrar(exigirRefresh(request));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    @Operation(summary = "Encerra todas as sessões do usuário autenticado")
    @ApiResponse(responseCode = "204", description = "Todas as sessões encerradas")
    @ApiResponse(responseCode = "401", description = "Não autenticado")
    public ResponseEntity<Void> logoutAll(@AuthenticationPrincipal Jwt jwt) {
        sessaoService.encerrarTodas(UUID.fromString(jwt.getSubject()));
        return ResponseEntity.noContent().build();
    }

    private ContextoCliente contexto(HttpServletRequest http) {
        return new ContextoCliente(clienteIpResolver.resolver(http), http.getHeader("User-Agent"));
    }

    private static String exigirRefresh(RefreshTokenRequest request) {
        if (request == null || request.refreshToken() == null || request.refreshToken().isBlank()) {
            throw new RegraNegocioException("refresh.obrigatorio", "refreshToken");
        }
        return request.refreshToken();
    }
}
