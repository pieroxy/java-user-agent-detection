package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describe a bot, which is a program that access sites automatically rather than a human browsing the web.
*/
public class Bot {
    private Brand vendor;
    private BotFamily family;
    private String description;
    private String version;
    private String url;

    /**
     * This is the most detailed constructor of the Bot object. You can specifiy all of its fields.
     * @param  _brand           The vendor of this bot.
     * @param  _family          The family of this bot.
     * @param  _description     The text description of this bot.
     * @param  _version         The version of this bot.
     * @param  _url             The url describing this bot.
    */
    public Bot(Brand _brand, BotFamily _family, String _description, String _version, String _url) {
        this(_brand,_family,_description,_version);
        url = _url==null ? "" : _url;
    }

    /**
     * This constructor of the Bot  object does not specify the url of the bot, initializing it to an empty string.
     * @param  _brand           The vendor of this bot.
     * @param  _family          The family of this bot.
     * @param  _description     The text description of this bot.
     * @param  _version         The version of this bot.
    */
    public Bot(Brand _brand, BotFamily _family, String _description, String _version) {
        family = _family;
        description = _description;
        version = _version;
        vendor = _brand;
        url = "";
    }
    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof Bot)) return false;
        Bot d = (Bot) o;
        if (d.vendor==null && vendor!=d.vendor) return false;
        if (d.getFamily()==null && family!=d.getFamily()) return false;
        if (d.description==null && description!=d.description) return false;
        if (d.version==null && version!=d.version) return false;
        if (d.url==null && url!=d.url) return false;
        return
            ( (d.getFamily()==null && family==null) || d.getFamily().equals(family) ) &&
            ( (d.description==null && description==null) || d.description.equals(description) ) &&
            ( (d.vendor==null && vendor==null) || d.vendor.equals(vendor) ) &&
            ( (d.url==null && url==null) || d.url.equals(url) ) &&
            ( (d.version==null && version==null) || d.version.equals(version) );
    }
    public int hashCode() {
        int res = 0;
        if (family != null) {
            res *= 3;
            res += family.hashCode();
        }
        if (version != null) {
            res *= 3;
            res += version.hashCode();
        }
        if (vendor!= null) {
            res *= 3;
            res += vendor.hashCode();
        }
        if (url!= null) {
            res *= 3;
            res += url.hashCode();
        }
        if (description != null) {
            res *= 3;
            res += description.hashCode();
        }
        return res;
    }

    /**
     * @return The vendor, usually the company that operates the bot, if known.
     */
    public Brand getVendor() {
        return vendor;
    }
    /** @return The family of the bot. SPAMBOT, WEB_CRAWLER, ... */
    public BotFamily getFamily() {
        return family;
    }
    /** @return The description of the bot. For example "Google Bot" or "Flipboard Proxy".  */
    public String getDescription() {
        return description;
    }
    /** @return The version number */
    public String getVersion() {
        return version;
    }
    /** @return The URL the bot points at or a url describing the bot. */
    public String getUrl() {
        return url;
    }
    /** @param u The URL the bot points at or a url describing the bot. */
    public void setUrl(String u) {
        url = u;
    }

}