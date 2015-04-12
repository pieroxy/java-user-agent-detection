package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* A Browser is made of a Brand, a BrowserFamily, a description and a rendering engine. Description and rendering engine are defined as a String as of today.
*/
public class Browser { /** The company shipping the browser */
    public Brand vendor;
    /** The general family of the browser. Could be FIREFOX, IE, CHROME, LIBRARY (means a program not being a browser), ... */
    public BrowserFamily family;
    /** The precise description of the browser. Can be "Firefox" or "Galeon" or "Seamonkey", ... */
    public String description;
    /** The two first numbers in the version of the browser. Ex: 10.3 or 35.1 */
    public String version;
    /** The full version number of the browser. Ex: 1.6.0.04 or 41.0.2272.76 */
    public String fullVersion;
    /**
     * A text description of the rendering engine. It is usually made of the name of the
     * rendering engine and its version, separated by a space. For example "WebKit 537.36" or "Gecko 6.0.2".
     * Empty if no rendering engine could be found (for example a library) */
    public String renderingEngine;

    /**
     * This is the most detailed constructor of the Browser object, where everything can be specified.
     * @param  _brand           The vendor of this browser.
     * @param  _family          The family of this browser.
     * @param  _description     The text description of this browser.
     * @param  _renderingEngine The rendering engine of this browser.
     * @param  _version         The vendor of this browser.
     * @param  _fullVersion     The vendor of this browser.
    */
    public Browser(Brand _brand, BrowserFamily _family, String _description, String _renderingEngine, String _version, String _fullVersion) {
        family = _family;
        description = _description;
        renderingEngine = _renderingEngine;
        vendor = _brand;
        version = _version;
        fullVersion = _fullVersion;
    }


    /**
     * This constructor of the Browser object does not specifie any of the version fields. They will be left as empty strings.
     * @param  _brand           The vendor of this browser.
     * @param  _family          The family of this browser.
     * @param  _description     The text description of this browser.
     * @param  _renderingEngine The rendering engine of this browser.
     * @param  _version         The vendor of this browser.
     * @param  _fullVersion     The vendor of this browser.
    */
    public Browser(Brand _brand, BrowserFamily _family, String _description, String _renderingEngine) {
        this(_brand, _family, _description, _renderingEngine, "", "");
    }

    /**
     * This constructor of the Browser object only specifies the <code>fullVersion</code>. The <code>version</code> is deduced by calling <code>setFullVersionOneShot(oneVersion)</code>.
     * @param  _brand           The vendor of this browser.
     * @param  _family          The family of this browser.
     * @param  _description     The text description of this browser.
     * @param  _renderingEngine The rendering engine of this browser.
     * @param  _version         The vendor of this browser.
     * @param  _fullVersion     The vendor of this browser.
    */
    public Browser(Brand _brand, BrowserFamily _family, String _description, String _renderingEngine, String _oneVersion) {
        this(_brand, _family, _description, _renderingEngine, "", "");
        setFullVersionOneShot(_oneVersion);
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

    /**
     * This method sets both <code>version</code> and <code>fullVersion</code> attributes of this Browser object.
     * It will set the <code>version</code> as the full version truncated to the first non numeric character, leaving the first '.' character in the mix.
     * @param  version The full version number.
    */
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