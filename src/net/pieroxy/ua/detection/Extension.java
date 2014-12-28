package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
public class Extension {
    private String version,name;
    public String getName() {
        return name;
    }
    public String getVersion() {
        return version;
    }
    public Extension(String n, String v) {
        name = (n==null) ? "" : n;
        version = (v==null) ? "" : v;
    }
    public Extension(String s) {
        if (s.contains("#")) {
            String[]ss = s.split("#");
            name=ss[0];
            version = ss[1];
        } else {
            name = s;
            version = "";
        }
    }

    public String toString() {
        if (version == null || version.length()==0) {
            return name;
        } else {
            return name + " " + version;
        }
    }
    public String serialize() {
        if (version == null || version.length()==0) {
            return name.replaceAll("#","-").replaceAll("\\^","-");
        } else {
            return (name.replaceAll("#","-") + "#" + version.replaceAll("#","-")).replaceAll("\\^","-");
        }
    }

    public boolean equals(Object o) {
        if (!(o instanceof Extension)) return false;
        Extension oo = (Extension)o;
        return oo.name.equals(name) && oo.version.equals(version);
    }
    public int hashCode() {
        return name.hashCode()  + 3 * version.hashCode();
    }

    public static Set<Extension> deserialize(String exs) {
        Set<Extension> res = new HashSet<Extension>();
        String[]array = exs.split("\\^");
        for (String s : array) {
            s = s.trim();
            if (s.length()>0) res.add(new Extension(s));
        }
        return res;
    }
}