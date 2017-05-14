package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describes the family of an Operating System. This is a category of OSes which will make it easier to categorize them.
*/
public enum RenderingEngineFamily {
    /**
    * BLINK is the rendering engine of modenr Chrome and Opera browsers.
    */
    BLINK("Blink",true,false),
    /**
    * Edge is the rendering engine of modern IEs, starting at version 12.
    */
    EDGE("EDGE",false,true),
    /**
    * KHTML is for Konqueror, the browser for KDE.
    */
    KHTML("KHTML",false,false),
    /**
    * Trident is the rendering engine of Internet Explorer
    */
    TRIDENT("Trident",false,true),
    /**
    * Webkit if a fork of KHTML, used in Safari and old Chromes.
    */
    WEBKIT("WebKit",true,false),
    /**
    * Presto is the historical rendering engine of Opera.
    */
    PRESTO("Presto",false,false),
    /**
    * Gecko is the rendering engine of Firefox.
    */
    GECKO("Gecko",false,false),
    /**
    * Rendering engine used by text-based browsers such as Lynx, Links or ELinks.
    */
    TEXT("Text based",false,false),
    /**
    * The rendering engine specifics are unknown.
    */
    UNKNOWN("Unknown",false,false),
    /**
    * The rendering engine specifics are unknown.
    */
    OTHER("Other",false,false),
    /**
    * No rendering engine could be detected.
    */
    NONE("",false,false);

    private boolean webkitDerivative;
    private boolean tridentDerivative;
    private String label;
    RenderingEngineFamily(String _label, boolean _webkitlike, boolean _tridentlike) {
        this.webkitDerivative = _webkitlike;
        this.tridentDerivative = _tridentlike;
        this.label = _label;
    }

    /**
    * @return true if the rendering engine is based on WebKit. As of this writing, only WEBKIT and BLINK returns true.
    */
    public boolean isWebkitBased() {
        return webkitDerivative;
    }
    /**
    * @return true if the rendering engine is based on Trident. As of this writing, only TRIDENT and EDGE returns true.
    */
    public boolean isTridentBased() {
        return tridentDerivative;
    }
    @Override
    public String toString() {
        return name();
    }
    /**
    * @return the text representation of this family.
    */
    public String getLabel() {
        return label;
    }
}