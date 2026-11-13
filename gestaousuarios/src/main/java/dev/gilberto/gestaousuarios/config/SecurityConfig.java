package dev.gilberto.gestaousuarios.config;

import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;

import dev.gilberto.gestaousuarios.auth.TokenVersionValidator;
import dev.gilberto.gestaousuarios.protecao.RateLimitFilter;
import dev.gilberto.gestaousuarios.protecao.RateLimitService;
import dev.gilberto.gestaousuarios.shared.exceptions.ErroResponseWriter;
import dev.gilberto.gestaousuarios.shared.util.ClienteIpResolver;

/**
 * Beans de segurança da feature de gestão de usuários e autenticação.
 *
 * <p>Esta classe reúne os beans transversais de segurança e a cadeia de filtros HTTP:
 * <ul>
 *   <li>{@link PasswordEncoder} — BCrypt com custo 12 (R2.1);</li>
 *   <li>{@link JwtEncoder} — emissão de JWT assinado com segredo simétrico HMAC-SHA256 (R4.2);</li>
 *   <li>{@link JwtDecoder} — validação de assinatura e expiração do JWT (R4.7);</li>
 *   <li>{@link JwtAuthenticationConverter} — mapeia a claim {@code perfil} para authority
 *       {@code ROLE_<perfil>} (R6.4);</li>
 *   <li>{@code SecurityFilterChain} — rotas públicas/protegidas, resource server JWT stateless
 *       e handlers de 401/403 (R4.7, R5.3, R6.4, R6.6, R11).</li>
 * </ul>
 *
 * <p>O {@code @EnableMethodSecurity} habilita {@code @PreAuthorize} nos controllers (R6.4).
 *
 * <p><strong>Segredo HMAC:</strong> o segredo configurado em
 * {@code dispensaai.security.jwt.secret} é usado tanto para assinar (encoder) quanto para
 * validar (decoder) o token, garantindo que a mesma {@link SecretKey} seja empregada nos dois
 * sentidos. Para o algoritmo HS256 o segredo precisa ter no mínimo 32 bytes (256 bits);
 * segredos menores são rejeitados pelo Nimbus ao assinar/validar. Forneça sempre um valor
 * com pelo menos 32 caracteres ASCII (ou 32 bytes UTF-8).
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Nome da claim que carrega o perfil do usuário no JWT emitido pelo serviço.
     */
    private static final String CLAIM_PERFIL = "perfil";

    /**
     * Prefixo exigido pelo Spring Security para que {@code hasRole('X')} em
     * {@code @PreAuthorize} corresponda à authority {@code ROLE_X}.
     */
    private static final String PREFIXO_ROLE = "ROLE_";

    /**
     * Segredo simétrico (HMAC) usado para assinar e validar o JWT emitido pelo próprio serviço.
     * Deve ter pelo menos 32 bytes para suportar HS256.
     */
    private final String jwtSecret;

    /**
     * O {@link JwtSecretValidator} é recebido apenas para garantir que a validação do segredo
     * (falha de startup em produção) ocorra antes da criação do encoder/decoder.
     */
    public SecurityConfig(JwtProperties jwtProperties, JwtSecretValidator jwtSecretValidator) {
        this.jwtSecret = jwtProperties.secret();
    }

    /**
     * Codificador de senhas BCrypt com fator de custo 12 (dentro do intervalo 10–12 de R2.1).
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Deriva a {@link SecretKey} HMAC-SHA256 a partir do segredo configurado. A mesma chave é
     * compartilhada pelo {@link #jwtEncoder()} e pelo decoder.
     */
    private SecretKey secretKey() {
        return new SecretKeySpec(jwtSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    /**
     * Emissor de JWT (Nimbus) que assina tokens com a chave simétrica HMAC (R4.2). O algoritmo
     * HS256 é selecionado automaticamente a partir do tipo da {@link SecretKey} informada.
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(new ImmutableSecret<>(secretKey()));
    }

    /**
     * Decodificador de JWT que valida assinatura e expiração usando a MESMA chave simétrica do
     * encoder, com o algoritmo HS256 (R4.7).
     */
    @Bean
    public JwtDecoder jwtDecoder(TokenVersionValidator tokenVersionValidator) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey())
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        OAuth2TokenValidator<Jwt> padrao = JwtValidators.createDefaultWithIssuer("gestaousuarios");
        // Sequencial: o banco só é consultado para tokens já aprovados nos validadores padrão.
        decoder.setJwtValidator(jwt -> {
            OAuth2TokenValidatorResult r = padrao.validate(jwt);
            return r.hasErrors() ? r : tokenVersionValidator.validate(jwt);
        });
        return decoder;
    }

    /** Rotas públicas (POST de cadastro/login/refresh/logout e documentação). */
    private static RequestMatcher rotasPublicas() {
        PathPatternRequestMatcher.Builder m = PathPatternRequestMatcher.withDefaults();
        return new OrRequestMatcher(
                m.matcher(HttpMethod.POST, "/v1/usuarios"),
                m.matcher(HttpMethod.POST, "/v1/auth/login"),
                m.matcher(HttpMethod.POST, "/v1/auth/refresh"),
                m.matcher(HttpMethod.POST, "/v1/auth/logout"),
                m.matcher("/v3/api-docs/**"),
                m.matcher("/swagger-ui/**"),
                m.matcher("/swagger-ui.html"));
    }

    /**
     * Ignora o cabeçalho Authorization nas rotas públicas: um cliente com access token expirado
     * deve conseguir chamar refresh/login sem receber 401 do filtro bearer.
     */
    private static BearerTokenResolver bearerTokenResolver() {
        DefaultBearerTokenResolver padrao = new DefaultBearerTokenResolver();
        RequestMatcher publicas = rotasPublicas();
        return request -> publicas.matches(request) ? null : padrao.resolve(request);
    }

    /**
     * Conversor que mapeia o JWT validado para um token de autenticação do Spring Security,
     * extraindo a claim única {@code perfil} (ex.: {@code "ADMIN"}, {@code "USER"}) e
     * traduzindo-a para a authority {@code ROLE_<perfil>}. O prefixo {@code ROLE_} é
     * obrigatório para que {@code @PreAuthorize("hasRole('ADMIN')")} funcione (R6.4).
     *
     * <p>Diferentemente do padrão {@code scope}/{@code scp} (lista de escopos), aqui o perfil
     * é um valor escalar, por isso usamos um {@code authoritiesConverter} próprio em vez do
     * {@code JwtGrantedAuthoritiesConverter}.</p>
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(SecurityConfig::extrairAuthorities);
        return converter;
    }

    /**
     * Extrai a authority {@code ROLE_<perfil>} a partir da claim {@code perfil} do JWT.
     * Quando a claim está ausente ou em branco, nenhuma authority é concedida.
     */
    private static List<GrantedAuthority> extrairAuthorities(Jwt jwt) {
        String perfil = jwt.getClaimAsString(CLAIM_PERFIL);
        if (perfil == null || perfil.isBlank()) {
            return List.of();
        }
        return List.of(new SimpleGrantedAuthority(PREFIXO_ROLE + perfil));
    }

    /**
     * Cadeia de filtros de segurança da API (R4.7, R5.3, R6.4, R6.6, R11).
     *
     * <ul>
     *   <li>CSRF desabilitado — API stateless autenticada por JWT (sem cookies/sessão).</li>
     *   <li>Sessão {@code STATELESS} — nenhuma sessão HTTP é criada.</li>
     *   <li>Rotas públicas: cadastro ({@code POST /v1/usuarios}), login
     *       ({@code POST /v1/auth/login}) e a documentação OpenAPI.</li>
     *   <li>Demais rotas exigem autenticação.</li>
     *   <li>Resource server OAuth2 valida o JWT via o decoder (padrão + tokenVersion) e converte o perfil
     *       em authority {@code ROLE_} via {@link #jwtAuthenticationConverter()}.</li>
     *   <li>Respostas de 401/403 padronizadas via {@link RestAuthenticationEntryPoint} e
     *       {@link RestAccessDeniedHandler}.</li>
     * </ul>
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           RestAuthenticationEntryPoint entryPoint,
                                           RestAccessDeniedHandler accessDeniedHandler,
                                           RateLimitService rateLimitService,
                                           ClienteIpResolver ipResolver,
                                           ErroResponseWriter erroWriter) throws Exception {
        // Criado aqui (não é bean/@Component) para não ser registrado também como filtro de servlet.
        RateLimitFilter rateLimitFilter = new RateLimitFilter(rateLimitService, ipResolver, erroWriter);
        http
                .addFilterBefore(rateLimitFilter, BearerTokenAuthenticationFilter.class)
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/v1/usuarios").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/auth/login",
                                "/v1/auth/refresh", "/v1/auth/logout").permitAll()
                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/swagger-ui/api-docs").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenResolver(bearerTokenResolver())
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler));

        return http.build();
    }
}
