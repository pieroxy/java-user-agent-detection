package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* The Locale class is made of a Language and a Country. It can helpful to help build statistics about your audience. While not all user agents report these two values, some do and it can give a statistically significant trend.
*/
public class Locale {
    private Language lang;
    private Country country;

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

    /** This constructor will set both <code>language</code> and <code>country</code> to their respective <code>UNKNOWN</code> value. */
    public Locale() {
        lang = Language.UNKNOWN;
        country = Country.UNKNOWN;
    }
    /** This constructor defines the <code>language</code> and sets the <code>country</code> to UNKNOWN.
     * @param l The language of this locale
     */
    public Locale(Language l) {
        country = Country.UNKNOWN;
        this.lang = l;
    }
    /** This constructor defines both <code>kanguage</code> and <code>country</code>.
     * @param l The language of this locale
     * @param c The country of this locale
     */
    public Locale(Language l, Country c) {
        this.lang = l;
        this.country = c;
    }


    /** This constructor defines both <code>kanguage</code> and <code>country</code> from their string representation.
     * Their string representation is the 2-letter ISO code for the country and the language. Thay can be provided
     * in either uppercase or lowercase form but not in a mixed-case form. If one or both parameters cannot be found
     * in the known languages/countries, they are set to their respective UNKNOWN value.
     * @param l The language of this locale
     * @param c The country of this locale
     */
    public Locale(String l, String c) {
        this.lang = LocaleHelper.getLanguage(l);
        if (this.lang == null) this.lang = Language.UNKNOWN;
        this.country = LocaleHelper.getCountry(c);
        if (this.country == null) this.country = Country.UNKNOWN;
    }

    /** @return The language of this locale */
    public Language getLanguage() {
        return lang;
    }
    /** @return The country of this locale */
    public Country getCountry() {
        return country;
    }

}