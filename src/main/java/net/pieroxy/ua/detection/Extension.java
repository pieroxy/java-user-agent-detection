package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Represents an extension of the system or browser. These extensions represent a piece of software that might be of some interest for the server (parental control, java version, etc).
*/
public class Extension {
    private String version,name;

    /** @return The name of this extension */
    public String getName() {
        return name;
    }
    /** @return The version of this extension, if applicable. */
    public String getVersion() {
        return version;
    }

    /** Builds a new extension with a name and a version
     * @param  n The name
     * @param  v The version
     */
    public Extension(String n, String v) {
        name = (n==null) ? "" : n;
        version = (v==null) ? "" : v;
    }

    /** Will try to find both name and version in the string, separated by a '#' character. If the separator is not found
     * sets the <code>version</code> to an empty string.
     * @param  s The String containing the name and optionally the version.
     */
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

    @Override
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
            String trimmed = s.trim();
            if (trimmed.length()>0) res.add(new Extension(trimmed));
        }
        return res;
    }
}