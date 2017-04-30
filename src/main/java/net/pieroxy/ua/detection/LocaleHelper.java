package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
class LocaleHelper {
    static Map<String,Language> allLangs;
    static Map<String,Country> allCountries;
    static {
        allLangs = new HashMap<String,Language>();
        for (Language l : Language.values()) {
            allLangs.put(l.name().toLowerCase(),l);
            allLangs.put(l.name().toUpperCase(),l);
        }
        allCountries = new HashMap<String,Country>();
        for (Country l : Country.values()) {
            allCountries.put(l.name().toLowerCase(),l);
            allCountries.put(l.name().toUpperCase(),l);
        }
    }
    /**
    * Gets the language from its 2 character ISO code. The ISO code must be provided either in uppercase or lowercase, but not a mix of both.
    * For example <code>getLanguage("LA")</code> and <code>getLanguage("la")</code> will both return the Latin language.
    */
    public static Language getLanguage(String code) {
        return allLangs.get(code);
    }
    /**
    * Gets the country from its 2 character ISO code. The ISO code must be provided either in uppercase or lowercase, but not a mix of both.
    * For example <code>getCountry("BE")</code> and <code>getCountry("be")</code> will both return the Belgium language.
    */
    public static Country getCountry(String code) {
        return allCountries.get(code);
    }
}