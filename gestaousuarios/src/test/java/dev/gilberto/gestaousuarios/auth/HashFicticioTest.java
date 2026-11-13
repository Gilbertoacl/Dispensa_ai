package dev.gilberto.gestaousuarios.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class HashFicticioTest {

    /** Encoder que delega e conta as chamadas a encode. */
    private static final class EncoderContador implements PasswordEncoder {
        final PasswordEncoder delegate;
        final AtomicInteger encodes = new AtomicInteger();

        EncoderContador(PasswordEncoder delegate) {
            this.delegate = delegate;
        }

        @Override
        public String encode(CharSequence raw) {
            encodes.incrementAndGet();
            return delegate.encode(raw);
        }

        @Override
        public boolean matches(CharSequence raw, String encoded) {
            return delegate.matches(raw, encoded);
        }
    }

    @Test
    void hashEGeradoUmaVezEValorEEstavel() {
        EncoderContador encoder = new EncoderContador(new BCryptPasswordEncoder(4));
        HashFicticio hf = new HashFicticio(encoder, new SecureRandom());

        String primeiro = hf.valor();
        for (int i = 0; i < 20; i++) {
            assertThat(hf.valor()).isSameAs(primeiro);
        }
        assertThat(encoder.encodes.get()).isEqualTo(1);
    }

    @Test
    void hashEValidoParaOEncoderENaoEASenhaDeNinguem() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
        String hash = new HashFicticio(encoder, new SecureRandom()).valor();

        assertThat(hash).matches("\\$2[aby]\\$04\\$[./A-Za-z0-9]{53}");
        // Senhas comuns/de usuários não conferem; o hash é de um segredo aleatório descartado
        for (String senha : new String[] {"", "password", "12345678", "SenhaCorreta#123", "admin", "Senha@Forte1"}) {
            assertThat(encoder.matches(senha, hash)).isFalse();
        }
    }

    @Test
    void hashsDeInstanciasDistintasSaoDiferentes() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
        String a = new HashFicticio(encoder, new SecureRandom()).valor();
        String b = new HashFicticio(encoder, new SecureRandom()).valor();
        assertThat(a).isNotEqualTo(b);
    }

    /** Único teste lento: BCrypt com custo 12. */
    @Test
    void usaBcryptComCusto12QuandoEncoderEBCryptDeCusto12() {
        EncoderContador encoder = new EncoderContador(new BCryptPasswordEncoder(12));
        HashFicticio hf = new HashFicticio(encoder, new SecureRandom());

        assertThat(hf.valor()).startsWith("$2a$12$").hasSize(60);
        assertThat(encoder.encodes.get()).isEqualTo(1);
        assertThat(hf.valor()).isSameAs(hf.valor());
    }
}
