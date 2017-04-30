package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describes an Operating System. It is made of a Brand, a family, a description and a version.
*/
public class OS {
    Brand vendor;
    OSFamily family;
    String description;
    String version;

    /**
     * This constructor of the OS object allows to set all of its fields.
     */
    public OS(Brand _brand, OSFamily _family, String _description, String _version) {
        family = _family;
        description = _description;
        version = _version;
        vendor = _brand;
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

    /** The vendor, usually the company that ships (or shipped) the operating system. */
    public Brand getVendor() {
        return vendor;
    }
    /** The family of this OS, like WINDOWS, LINUX, ANDROID, etc... */
    public OSFamily getFamily() {
        return family;
    }
    /** The description is the name of the OS. For example: "Windows" or "Ubuntu" or "iOS" */
    public String getDescription() {
        return description;
    }
    /** The version is precising which version of the OS is used. It can be "Vista" or "XP SP2" (for windows) or "7.1.2" for iOS. */
    public String getVersion() {
        return version;
    }

}