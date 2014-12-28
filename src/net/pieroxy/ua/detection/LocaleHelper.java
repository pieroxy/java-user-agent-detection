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

    public static Language getLanguage(String code) {
        return allLangs.get(code);
    }
    public static Country getCountry(String code) {
        return allCountries.get(code);
    }
}