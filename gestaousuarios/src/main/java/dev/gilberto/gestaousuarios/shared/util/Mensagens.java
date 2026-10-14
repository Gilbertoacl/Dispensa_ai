package dev.gilberto.gestaousuarios.shared.util;

import org.springframework.context.MessageSource;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

public final class Mensagens {

    private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("messages", Locale.getDefault());

    private Mensagens() {}

    /**
     * Busca a mensagem pela chave.
     */
    public static String get(String chave) {
        try {
            return BUNDLE.getString(chave);
        } catch (MissingResourceException e) {
            return "???" + chave + "???";
        }
    }

    /**
     * Busca a mensagem com parâmetros formatados.
     * Ex: get("usuario.nao.encontrado", "joao") → "Usuário joao não encontrado"
     */
    public static String get(String chave, Object... params) {
        String template = get(chave);
        return MessageFormat.format(template, params);
    }

    /**
     * Busca com locale específico (útil se a app troca de idioma em runtime).
     */
    public static String get(String chave, Locale locale, Object... params) {
        ResourceBundle bundle = ResourceBundle.getBundle("messages", locale);
        String template = bundle.getString(chave);
        return MessageFormat.format(template, params);
    }

}
