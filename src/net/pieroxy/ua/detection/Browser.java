package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
public class Browser {
    public Brand vendor;
    public BrowserFamily family;
    public String description;
    public String renderingEngine;
    public Browser(Brand v, BrowserFamily f, String d, String r) {
        family = f;
        description = d;
        renderingEngine = r;
        vendor = v;
    }
    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof Browser)) return false;
        Browser d = (Browser) o;
        if (d.family==null && family!=d.family) return false;
        if (d.description==null && description!=d.description) return false;
        if (d.renderingEngine==null && renderingEngine!=d.renderingEngine) return false;
        return
            ( (d.family==null && family==null) || d.family.equals(family) ) &&
            ( (d.description==null && description==null) || d.description.equals(description) ) &&
            ( (d.vendor==null && vendor==null) || d.vendor.equals(vendor) ) &&
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
        return res;
    }
}