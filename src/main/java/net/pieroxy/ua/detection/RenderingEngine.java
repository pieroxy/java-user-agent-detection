package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* A RenderingEngine is made of a Brand, a RenderingEngineFamily and two versions.
*/
public class RenderingEngine extends VersionedObject {
    private Brand vendor;
    private RenderingEngineFamily family;

    /**
     * This is the most detailed constructor of the RenderingEngine object, where everything can be specified.
     * @param  _brand           The vendor of this browser.
     * @param  _family          The family of this browser.
     * @param  _version         The version of this browser.
     * @param  _fullVersion     The full version of this browser.
    */
    public RenderingEngine(Brand _brand, RenderingEngineFamily _family, String _version, String _fullVersion) {
        family = _family;
        vendor = _brand;
        version = _version;
        fullVersion = _fullVersion;
    }

    /**
     * This is the constructor that does not specify a version.
     * @param  _brand           The vendor of this browser.
     * @param  _family          The family of this browser.
    */
    public RenderingEngine(Brand _brand, RenderingEngineFamily _family) {
        family = _family;
        vendor = _brand;
        version = "";
        fullVersion = "";
    }


    /**
     * This constructor of the RenderingEngine object only specifies the <code>fullVersion</code>. The <code>version</code> is deduced by calling <code>setFullVersionOneShot(oneVersion)</code>.
     * @param  _brand           The vendor of this browser.
     * @param  _family          The family of this browser.
     * @param  _oneVersion      The full version of this browser.
     * @param  _nbChunks        How many chunks of numbers should the small version keep.
    */
    public RenderingEngine(Brand _brand, RenderingEngineFamily _family, String _oneVersion, int _nbChunks) {
        this(_brand, _family, "", "");
        setFullVersionOneShot(_oneVersion, _nbChunks);
    }

    /**
     * This constructor of the RenderingEngine object only specifies the <code>fullVersion</code> as a float. The <code>version</code> is deduced by calling <code>setFullVersionOneShot(oneVersion)</code>.
     * @param  _brand           The vendor of this browser.
     * @param  _family          The family of this browser.
     * @param  _oneVersion      The full version of this browser, as a floating-point number.
     * @param  _nbChunks        How many chunks of numbers should the small version keep.
    */
    public RenderingEngine(Brand _brand, RenderingEngineFamily _family, float _oneVersion, int _nbChunks) {
        this(_brand, _family, "", "");
        String version = String.valueOf(_oneVersion);
        if (version.indexOf(".")==-1) version += ".0";
        setFullVersionOneShot(version, _nbChunks);
    }

    public static RenderingEngine getUnknown() {
        return new RenderingEngine(Brand.UNKNOWN, RenderingEngineFamily.UNKNOWN);
    }

    public static RenderingEngine getOther(Brand brand) {
        return new RenderingEngine(brand, RenderingEngineFamily.OTHER);
    }

    public static RenderingEngine getText() {
        return new RenderingEngine(Brand.UNKNOWN, RenderingEngineFamily.TEXT);
    }

    public static RenderingEngine getNone() {
        return new RenderingEngine(Brand.UNKNOWN, RenderingEngineFamily.NONE);
    }

    @Override
    public String toString() {
        String res = family + " " + version;
        if (fullVersion != null && fullVersion.length()>0) {
            res += " " + fullVersion;
        }
        return res;
    }

    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof RenderingEngine)) return false;
        RenderingEngine d = (RenderingEngine) o;
        if (d.getFamily()==null && family!=d.getFamily()) return false;
        if (d.version==null && version!=d.version) return false;
        if (d.vendor==null && vendor!=d.vendor) return false;
        if (d.fullVersion==null && fullVersion!=d.fullVersion) return false;
        return
            ( (d.getFamily()==null && family==null) || d.getFamily().equals(family) ) &&
            ( (d.version==null && version==null) || d.version.equals(version) ) &&
            ( (d.vendor==null && vendor==null) || d.vendor.equals(vendor) ) &&
            ( (d.fullVersion==null && fullVersion==null) || d.fullVersion.equals(fullVersion) ) ;
    }

    public int hashCode() {
        int res = 0;
        if (family != null) {
            res *= 3;
            res += family.hashCode();
        }
        if (vendor!= null) {
            res *= 3;
            res += vendor.hashCode();
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

    /** @return The main company behind the browser */
    public Brand getVendor() {
        return vendor;
    }
    /** @return The general family of the rendering engine. Could be GECKO, TRIDENT, WEBKIT, ... */
    public RenderingEngineFamily getFamily() {
        return family;
    }

}