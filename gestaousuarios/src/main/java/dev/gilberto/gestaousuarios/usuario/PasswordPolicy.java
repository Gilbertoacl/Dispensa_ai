package dev.gilberto.gestaousuarios.usuario;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import org.springframework.stereotype.Component;

import dev.gilberto.gestaousuarios.shared.exceptions.RegraNegocioException;

/**
 * Política de senha: tamanho 8 a 64, no máximo 72 bytes UTF-8, diferente do e-mail
 * e fora da lista de senhas comuns (sem distinção de maiúsculas).
 */
@Component
public class PasswordPolicy {

    static final int TAMANHO_MIN = 8;
    static final int TAMANHO_MAX = 64;
    static final int BYTES_MAX = 72;

    private final Set<String> comuns;

    public PasswordPolicy(PasswordPolicyProperties props) {
        Set<String> conjunto = new HashSet<>();
        for (String s : props.senhasComuns()) {
            if (s != null) {
                conjunto.add(s.toLowerCase(Locale.ROOT));
            }
        }
        this.comuns = Set.copyOf(conjunto);
    }

    public static PasswordPolicy padrao() {
        return new PasswordPolicy(PasswordPolicyProperties.padrao());
    }

    /**
     * Valida a senha; a primeira regra violada define a chave da exceção.
     *
     * @param emailNormalizado e-mail já normalizado (pode ser nulo)
     * @param campo            campo associado ao erro
     */
    public void validar(String senha, String emailNormalizado, String campo) {
        if (senha == null || senha.length() < TAMANHO_MIN || senha.length() > TAMANHO_MAX) {
            throw new RegraNegocioException("password.tamanho", campo);
        }
        if (!dentroDoLimiteDeBytes(senha)) {
            throw new RegraNegocioException("senha.bytes.excedido", campo);
        }
        if (emailNormalizado != null && normalizar(senha).equals(emailNormalizado)) {
            throw new RegraNegocioException("senha.igual.email", campo);
        }
        if (comuns.contains(senha.toLowerCase(Locale.ROOT))) {
            throw new RegraNegocioException("senha.comum", campo);
        }
    }

    static boolean dentroDoLimiteDeBytes(String senha) {
        return senha.getBytes(StandardCharsets.UTF_8).length <= BYTES_MAX;
    }

    private static String normalizar(String valor) {
        return valor.trim().toLowerCase(Locale.ROOT);
    }
}
