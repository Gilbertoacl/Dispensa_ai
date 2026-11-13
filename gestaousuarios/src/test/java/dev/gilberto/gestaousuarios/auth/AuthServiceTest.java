package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import dev.gilberto.gestaousuarios.auditoria.AuditoriaSeguranca;
import dev.gilberto.gestaousuarios.auditoria.TipoEventoSeguranca;
import dev.gilberto.gestaousuarios.protecao.ChaveConta;
import dev.gilberto.gestaousuarios.protecao.ForcaBrutaService;
import dev.gilberto.gestaousuarios.shared.exceptions.LimiteExcedidoException;
import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import dev.gilberto.gestaousuarios.usuario.Perfil;
import dev.gilberto.gestaousuarios.usuario.Usuario;
import dev.gilberto.gestaousuarios.usuario.UsuarioRepository;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final ContextoCliente CLIENTE = new ContextoCliente("127.0.0.1", "JUnit");
    private static final String CHAVE = ChaveConta.de("mail@mail.com");

    @Mock
    private UsuarioRepository usuarioRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private SessaoService sessaoService;

    @Mock
    private ForcaBrutaService forcaBruta;

    @Mock
    private HashFicticio hashFicticio;

    @Mock
    private AuditoriaSeguranca auditoria;

    @InjectMocks
    private AuthService authService;

    @Test
    void deveAutenticarComSucessoEDelegarASessao() {
        Usuario user = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        TokenResponse esperado = new TokenResponse("TOKEN123", "REFRESH", "Bearer", 900L, 604800L);
        when(forcaBruta.verificarBloqueio(CHAVE)).thenReturn(Optional.empty());
        when(usuarioRepository.findByEmail("mail@mail.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("12345678", "HASH")).thenReturn(true);
        when(sessaoService.iniciar(user, CLIENTE)).thenReturn(esperado);

        TokenResponse resp = authService.autenticar(new LoginRequest("mail@mail.com", "12345678"), CLIENTE);

        assertThat(resp).isSameAs(esperado);
        assertThat(resp.accessToken()).isEqualTo("TOKEN123");
        assertThat(resp.tokenType()).isEqualTo("Bearer");
        assertThat(resp.expiraEm()).isEqualTo(900L);
        assertThat(resp.toString()).doesNotContain("TOKEN123").doesNotContain("REFRESH");
        verify(forcaBruta).registrarSucesso(CHAVE);
        verify(forcaBruta, never()).registrarFalha(anyString());
        // LOGIN_SUCESSO é auditado no SessaoService.iniciar, não aqui
        verify(auditoria, never()).registrar(any(), any(), any());
    }

    @Test
    void deveLancarQuandoEmailNaoExisteComUmaExecucaoContraHashFicticio() {
        when(forcaBruta.verificarBloqueio(CHAVE)).thenReturn(Optional.empty());
        when(usuarioRepository.findByEmail("mail@mail.com")).thenReturn(Optional.empty());
        when(hashFicticio.valor()).thenReturn("FAKE");
        when(passwordEncoder.matches("12345678", "FAKE")).thenReturn(false);
        when(forcaBruta.registrarFalha(CHAVE)).thenReturn(false);

        assertThatThrownBy(() -> authService.autenticar(new LoginRequest("mail@mail.com", "12345678"), CLIENTE))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage(Mensagens.get("user.invalid.credentials"));

        verify(passwordEncoder, times(1)).matches(anyString(), anyString());
        verify(passwordEncoder).matches("12345678", "FAKE");
        verify(forcaBruta).registrarFalha(CHAVE);
        verify(auditoria).registrar(TipoEventoSeguranca.LOGIN_FALHA, null, null);
        verify(sessaoService, never()).iniciar(any(Usuario.class), any(ContextoCliente.class));
    }

    @Test
    void deveLancarQuandoSenhaIncorretaComUmaExecucaoDeMatches() {
        Usuario user = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(forcaBruta.verificarBloqueio(CHAVE)).thenReturn(Optional.empty());
        when(usuarioRepository.findByEmail("mail@mail.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("12345678", "HASH")).thenReturn(false);

        assertThatThrownBy(() -> authService.autenticar(new LoginRequest("mail@mail.com", "12345678"), CLIENTE))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage(Mensagens.get("user.invalid.credentials"));

        verify(passwordEncoder, times(1)).matches(anyString(), anyString());
        verify(forcaBruta).registrarFalha(CHAVE);
        verify(forcaBruta, never()).registrarSucesso(anyString());
        verify(auditoria).registrar(TipoEventoSeguranca.LOGIN_FALHA, user.getId(), null);
        verify(sessaoService, never()).iniciar(any(Usuario.class), any(ContextoCliente.class));
    }

    @Test
    void deveRegistrarLoginBloqueadoQuandoFalhaIniciaBloqueio() {
        Usuario user = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(forcaBruta.verificarBloqueio(CHAVE)).thenReturn(Optional.empty());
        when(usuarioRepository.findByEmail("mail@mail.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("errada", "HASH")).thenReturn(false);
        when(forcaBruta.registrarFalha(CHAVE)).thenReturn(true);

        assertThatThrownBy(() -> authService.autenticar(new LoginRequest("mail@mail.com", "errada"), CLIENTE))
                .isInstanceOf(BadCredentialsException.class);

        verify(auditoria).registrar(TipoEventoSeguranca.LOGIN_FALHA, user.getId(), null);
        verify(auditoria).registrar(TipoEventoSeguranca.LOGIN_BLOQUEADO, user.getId(), null);
    }

    @Test
    void contaBloqueadaRejeitaSemExecutarBcryptMesmoComSenhaCorreta() {
        when(forcaBruta.verificarBloqueio(CHAVE)).thenReturn(Optional.of(Duration.ofSeconds(42)));

        assertThatThrownBy(() -> authService.autenticar(new LoginRequest("mail@mail.com", "12345678"), CLIENTE))
                .isInstanceOfSatisfying(LimiteExcedidoException.class, e -> {
                    assertThat(e.getMessage()).isEqualTo(Mensagens.get("login.bloqueado"));
                    assertThat(e.getRetryAfter()).isEqualTo(Duration.ofSeconds(42));
                });

        verify(passwordEncoder, never()).matches(any(), any());
        verify(usuarioRepository, never()).findByEmail(anyString());
        verify(sessaoService, never()).iniciar(any(Usuario.class), any(ContextoCliente.class));
    }

    @Test
    void deveNormalizarEmailAntesDeBuscar() {
        Usuario user = new Usuario("mail@mail.com", "João", "HASH", Perfil.USER);
        when(forcaBruta.verificarBloqueio(CHAVE)).thenReturn(Optional.empty());
        when(usuarioRepository.findByEmail("mail@mail.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("12345678", "HASH")).thenReturn(true);
        when(sessaoService.iniciar(user, CLIENTE)).thenReturn(new TokenResponse("T", "R", "Bearer", 900L, 604800L));

        assertThatCode(() -> authService.autenticar(new LoginRequest("  MAIL@MAIL.COM  ", "12345678"), CLIENTE))
                .doesNotThrowAnyException();

        ArgumentCaptor<String> emailCaptor = ArgumentCaptor.forClass(String.class);
        verify(usuarioRepository).findByEmail(emailCaptor.capture());
        assertThat(emailCaptor.getValue()).isEqualTo("mail@mail.com");
    }
}
