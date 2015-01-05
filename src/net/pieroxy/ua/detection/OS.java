package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describes an Operating System. It is made of a Brand, a family, a description and a version.
*/
public class OS {
    public Brand vendor;
    public OSFamily family;
    public String description;
    public String version;
    public OS(Brand ve, OSFamily f, String d, String v) {
        family = f;
        description = d;
        version = v;
        vendor = ve;
    }
    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof OS)) return false;
        OS d = (OS) o;
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
        if (version!= null) {
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