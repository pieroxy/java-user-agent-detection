package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* A Browser is made of a Brand, a BrowserFamily, a description and a rendering engine. Description is defined as a String as of today.
*/
public class Browser extends VersionedObject {
    private Brand vendor;
    private BrowserFamily family;
    private String description;
    private RenderingEngine renderingEngine;
    private boolean inWebView;

    /**
     * This is the most detailed constructor of the Browser object, where everything can be specified.
     * @param  _brand           The vendor of this browser.
     * @param  _family          The family of this browser.
     * @param  _description     The text description of this browser.
     * @param  _renderingEngine The rendering engine of this browser.
     * @param  _version         The version of this browser.
     * @param  _fullVersion     The full version of this browser.
    */
    public Browser(Brand _brand, BrowserFamily _family, String _description, RenderingEngine _renderingEngine, String _version, String _fullVersion) {
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
    */
    public Browser(Brand _brand, BrowserFamily _family, String _description, RenderingEngine _renderingEngine) {
        this(_brand, _family, _description, _renderingEngine, "", "");
    }

    /**
     * This constructor of the Browser object only specifies the <code>fullVersion</code>. The <code>version</code> is deduced by calling <code>setFullVersionOneShot(oneVersion)</code>.
     * @param  _brand           The vendor of this browser.
     * @param  _family          The family of this browser.
     * @param  _description     The text description of this browser.
     * @param  _renderingEngine The rendering engine of this browser.
     * @param  _oneVersion      The full version of this browser.
    */
    public Browser(Brand _brand, BrowserFamily _family, String _description, RenderingEngine _renderingEngine, String _oneVersion) {
        this(_brand, _family, _description, _renderingEngine, "", "");
        setFullVersionOneShot(_oneVersion, 2);
    }

    /**
    * This constructor of the Browser object only specifies the <code>fullVersion</code>. The <code>version</code> is deduced by calling <code>setFullVersionOneShot(oneVersion)</code>.
    * @param  _brand           The vendor of this browser.
    * @param  _family          The family of this browser.
    * @param  _description     The text description of this browser.
    * @param  _renderingEngine The rendering engine of this browser.
    * @param  _oneVersion      The full version of this browser.
    * @param  _nbChunks        Number of chunks of digits to keep in the short version.
    */
    public Browser(Brand _brand, BrowserFamily _family, String _description, RenderingEngine _renderingEngine, String _oneVersion, int _nbChunks) {
        this(_brand, _family, _description, _renderingEngine, "", "");
        setFullVersionOneShot(_oneVersion, _nbChunks);
    }

    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof Browser)) return false;
        Browser d = (Browser) o;
        if (d.getFamily()==null && family!=d.getFamily()) return false;
        if (d.description==null && description!=d.description) return false;
        if (d.version==null && version!=d.version) return false;
        if (d.vendor==null && vendor!=d.vendor) return false;
        if (d.fullVersion==null && fullVersion!=d.fullVersion) return false;
        if (d.renderingEngine==null && renderingEngine!=d.renderingEngine) return false;
        return
            ( (d.getFamily()==null && family==null) || d.getFamily().equals(family) ) &&
            ( (d.version==null && version==null) || d.version.equals(version) ) &&
            ( (d.vendor==null && vendor==null) || d.vendor.equals(vendor) ) &&
            ( (d.description==null && description==null) || d.description.equals(description) ) &&
            ( (d.fullVersion==null && fullVersion==null) || d.fullVersion.equals(fullVersion) ) &&
            ( (d.renderingEngine==null && renderingEngine==null) || d.renderingEngine.equals(renderingEngine) ) &&
            d.inWebView == inWebView;
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
        if (inWebView) {
            res ++;
        }
        return res;
    }

    /** @return The company shipping the browser */
    public Brand getVendor() {
        return vendor;
    }
    /** @param v The company shipping the browser */
    public void setVendor(Brand v) {
        vendor = v;
    }
    /** @return The general family of the browser. Could be FIREFOX, IE, CHROME, LIBRARY (means a program not being a browser), ... */
    public BrowserFamily getFamily() {
        return family;
    }
    /** @param f The general family of the browser. Could be FIREFOX, IE, CHROME, LIBRARY (means a program not being a browser), ... */
    public void setFamily(BrowserFamily f) {
        family = f;
    }
    /** @return The precise description of the browser. Can be "Firefox" or "Galeon" or "Seamonkey", ... */
    public String getDescription() {
        return description;
    }
    /** @param d The precise description of the browser. Can be "Firefox" or "Galeon" or "Seamonkey", ... */
    public void setDescription(String d) {
        description = d;
    }
    /** @return The rendering engine */
    public RenderingEngine getRenderingEngine() {
        return renderingEngine;
    }
    /** @param re The rendering engine */
    public void setRenderingEngine(RenderingEngine re) {
        renderingEngine = re;
    }
    /** @return true if the browser is a webview, false if not or unknown */
    public boolean isInWebView() {
        return inWebView;
    }
    /** @param value true if the browser is a webview, false if not or unknown */
    public void setInWebView(boolean value) {
        inWebView = value;
    }

}