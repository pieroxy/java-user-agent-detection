package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describe a bot, which is a program that access sites automatically rather than a human browsing the web.
*/
public class Bot {
    public Brand vendor;
    public BotFamily family;
    public String description;
    public String version;
    public Bot(Brand b, BotFamily f, String d, String v) {
        family = f;
        description = d;
        version = v;
        vendor = b;
    }
    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof Bot)) return false;
        Bot d = (Bot) o;
        if (d.vendor==null && vendor!=d.vendor) return false;
        if (d.family==null && family!=d.family) return false;
        if (d.description==null && description!=d.description) return false;
        if (d.version==null && version!=d.version) return false;
        return
            ( (d.family==null && family==null) || d.family.equals(family) ) &&
            ( (d.description==null && description==null) || d.description.equals(description) ) &&
            ( (d.vendor==null && vendor==null) || d.vendor.equals(vendor) ) &&
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
        if (description != null) {
            res *= 3;
            res += description.hashCode();
        }
        return res;
    }
}