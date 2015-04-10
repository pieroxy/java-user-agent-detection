package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* A Browser is made of a Brand, a BrowserFamily, a description and a rendering engine. Description and rendering engine are defined as a String as of today.
*/
public class Browser {
    public Brand vendor;
    public BrowserFamily family;
    public String description;
    public String version;
    public String fullVersion;
    public String renderingEngine;
    public Browser(Brand v, BrowserFamily f, String d, String r, String ver, String fullVer) {
        family = f;
        description = d;
        renderingEngine = r;
        vendor = v;
        version = ver;
        fullVersion = fullVer;
    }
    public Browser(Brand v, BrowserFamily f, String d, String r) {
        this(v, f, d, r, "", "");
    }
    public Browser(Brand v, BrowserFamily f, String d, String r, String oneVersion) {
        this(v, f, d, r, "", "");
        setFullVersionOneShot(oneVersion);
    }
    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof Browser)) return false;
        Browser d = (Browser) o;
        if (d.family==null && family!=d.family) return false;
        if (d.description==null && description!=d.description) return false;
        if (d.version==null && version!=d.version) return false;
        if (d.vendor==null && vendor!=d.vendor) return false;
        if (d.fullVersion==null && fullVersion!=d.fullVersion) return false;
        if (d.renderingEngine==null && renderingEngine!=d.renderingEngine) return false;
        return
            ( (d.family==null && family==null) || d.family.equals(family) ) &&
            ( (d.description==null && description==null) || d.description.equals(description) ) &&
            ( (d.version==null && version==null) || d.version.equals(version) ) &&
            ( (d.vendor==null && vendor==null) || d.vendor.equals(vendor) ) &&
            ( (d.description==null && description==null) || d.description.equals(description) ) &&
            ( (d.fullVersion==null && fullVersion==null) || d.fullVersion.equals(fullVersion) ) &&
            ( (d.renderingEngine==null && renderingEngine==null) || d.renderingEngine.equals(renderingEngine) );
    }
    public int hashCode() {
        int res = 0;
        if (family != null) {
            res *= 3;
            res += family.hashCode();
        }
        if (renderingEngine != null) {
            res *= 3;
            res += renderingEngine.hashCode();
        }
        if (vendor!= null) {
            res *= 3;
            res += vendor.hashCode();
        }
        if (description != null) {
            res *= 3;
            res += description.hashCode();
        }
        if (version != null) {
            res *= 3;
            res += version.hashCode();
        }
        if (fullVersion != null) {
            res *= 3;
            res += fullVersion.hashCode();
        }
        return res;
    }

    public void setFullVersionOneShot(String version) {
        this.fullVersion = version;
        String sv = "";
        boolean dot = false;
        for (int i=0 ; i<version.length() ; i++) {
            char c = version.charAt(i);
            if (c == '.') {
                if (dot) break;
                dot = true;
                sv += c;
            } else if (Character.isDigit(c)) {
                sv += c;
            } else break;
        }
        this.version = sv;
    }
}