package dev.gilberto.gestaousuarios.usuario;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Credenciais do administrador inicial ({@code dispensaai.admin-inicial.*}), vindas das variáveis
 * de ambiente ADMIN_EMAIL, ADMIN_SENHA e ADMIN_NOME. A senha nunca aparece em {@link #toString()}.
 */
@ConfigurationProperties(prefix = "dispensaai.admin-inicial")
public record AdminInicialProperties(String email, String senha, String nome) {

    /** Verdadeiro somente quando as três propriedades estão definidas e não vazias. */
    public boolean completo() {
        return preenchido(email) && preenchido(senha) && preenchido(nome);
    }

    private static boolean preenchido(String valor) {
        return valor != null && !valor.isBlank();
    }

    @Override
    public String toString() {
        return "AdminInicialProperties[email=" + email + ", senha=****, nome=" + nome + "]";
    }
}
