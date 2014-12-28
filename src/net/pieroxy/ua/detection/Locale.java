package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
public class Locale {
    public Language lang;
    public Country country;

    public int hashCode() {
        return (lang +"-"+ country).hashCode();
    }
    public boolean equals(Object o) {
        if (o==null) return false;
        if (o instanceof Locale) {
            Locale r = (Locale)o;
            return r.lang == lang && r.country == country;
        } else return false;
    }
    public Locale() {
        lang = Language.UNKNOWN;
        country = Country.UNKNOWN;
    }
    public Locale(Language l) {
        country = Country.UNKNOWN;
        this.lang = l;
    }
    public Locale(Language l, Country c) {
        this.lang = l;
        this.country = c;
    }
    public Locale(String l, String c) {
        this.lang = LocaleHelper.getLanguage(l);
        if (this.lang == null) this.lang = Language.UNKNOWN;
        this.country = LocaleHelper.getCountry(c);
        if (this.country == null) this.country = Country.UNKNOWN;
    }

}