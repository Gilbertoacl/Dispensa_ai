package dev.gilberto.gestaousuarios.usuario;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propriedades da política de senha ({@code dispensaai.security.senha.*}).
 *
 * @param senhasComuns lista de senhas proibidas; quando ausente ou vazia usa {@link #PADRAO}
 */
@ConfigurationProperties(prefix = "dispensaai.security.senha")
public record PasswordPolicyProperties(List<String> senhasComuns) {

    /** Lista padrão de senhas comuns (todas com 8 ou mais caracteres). */
    public static final List<String> PADRAO = List.of(
            "12345678", "123456789", "1234567890", "87654321", "11111111", "00000000",
            "12341234", "123123123", "password", "password1", "password123", "senha123",
            "senha1234", "mudar123", "trocar123", "qwerty123", "qwertyui", "1q2w3e4r",
            "q1w2e3r4", "abc12345", "abcd1234", "iloveyou", "admin123", "administrador",
            "brasil123", "dispensaai");

    public PasswordPolicyProperties {
        senhasComuns = (senhasComuns == null || senhasComuns.isEmpty()) ? PADRAO : List.copyOf(senhasComuns);
    }

    public static PasswordPolicyProperties padrao() {
        return new PasswordPolicyProperties(PADRAO);
    }
}
