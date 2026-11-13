package dev.gilberto.gestaousuarios.config;

import dev.gilberto.gestaousuarios.shared.util.Mensagens;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Impede o startup em produção com um segredo JWT fraco ou com o segredo padrão de desenvolvimento.
 * Nem a mensagem de falha nem logs contêm o valor do segredo.
 */
@Component
public class JwtSecretValidator implements InitializingBean {

    static final String PREFIXO_DEV = "dev-only-secret-";
    static final int TAMANHO_MINIMO_BYTES = 32;

    private final Environment environment;
    private final JwtProperties props;

    public JwtSecretValidator(Environment environment, JwtProperties props) {
        this.environment = environment;
        this.props = props;
    }

    static boolean aceitoEmProducao(String segredo) {
        return segredo != null
                && !segredo.isBlank()
                && segredo.getBytes(StandardCharsets.UTF_8).length >= TAMANHO_MINIMO_BYTES
                && !segredo.startsWith(PREFIXO_DEV);
    }

    @Override
    public void afterPropertiesSet() {
        if (environment.acceptsProfiles(Profiles.of("prod")) && !aceitoEmProducao(props.secret())) {
            throw new IllegalStateException(Mensagens.get("jwt.segredo.invalido.producao"));
        }
    }
}
