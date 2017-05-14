package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describes the family of the browser.
*/
public enum BrowserFamily {
    /**
    * The Internet Explorer browser, default one on Windows, by Microsoft.
    */
    IE("Internet Explorer",false, true, false, false),
    /**
    * The Firefox browser by Mozilla.
    */
    FIREFOX("Firefox",true, false, false, false),
    /**
    * The Chrome browser by Google.
    */
    CHROME("Chrome",false, false, true, false),
    /**
    * Opera, by Opera Software
    */
    OPERA("Opera",false, false, false, false),
    /**
    * Opera, by Opera Software, with the WebKit/Blink rendering engine
    */
    NEW_OPERA("Opera",false, false, true, false),
    /**
    * Mobile Safari, the default browser on iPhones and iPads, by Apple.
    */
    IOS("iOS's default browser",false, false, true, false),
    /**
    * The default Android browser, by Google.
    */
    ANDROID("Android's default browser",false, false, true, false),
    /**
    * Safari, the browser by Apple
    */
    SAFARI("Safari",false, false, true, false),
    /**
    * A browser based on Firefox's rendering engine, Gecko.
    */
    OTHER_GECKO("Gecko-based",true, false, false, false),
    /**
    * A browser based on the WebKit rendering engine other than Safari or Chrome.
    */
    OTHER_WEBKIT("WebKit-based",false, false, true, false),
    /**
    * A browser based on Internet Explorer's rendering engine, Trident.
    */
    OTHER_TRIDENT("IE-based",false, true, false, false),
    /**
    * A browser based on KHTML, an ancestor of WebKit.
    */
    KHTML("KHTML-based",false, false, false, false),
    /**
    * NetFront, the mobile web browser by Access Co., Ltd.
    */
    NETFRONT("NetFront",false, false, false, false),
    /**
    * A text-based browser, such as Links or Lynx.
    */
    TEXTBASED("Text Based",false, false, false, false),
    /**
    * Another browser not popular enough to warrant a place in this enum.
    */
    LIBRARY("Library",false, false, false, true),
    /**
    * Another browser not popular enough to warrant a place in this enum.
    */
    OTHER("Other",false, false, false, false),
    /**
    * Unknown browser
    */
    UNKNOWN("",false, false, false, false);

    private boolean gecko;
    private boolean trident;
    private boolean webkit;
    private boolean robot;
    private String label;
    BrowserFamily(String _label, boolean _gecko, boolean _trident, boolean _webkit, boolean _robot) {
        gecko=_gecko;
        trident=_trident;
        webkit=_webkit;
        robot=_robot;
        this.label = _label;
    }

    /**
    * @return true if the browser is based on Gecko - Firefox's rendering engine.
    */
    public boolean isGecko() {
        return gecko;
    }
    /**
    * @return true if the browser is based on Trident - Internet Explorer's rendering engine.
    */
    public boolean isTrident() {
        return trident;
    }
    /**
    * @return true if the browser is based on WebKit or Blink - Chrome, Safari, new Opera
    */
    public boolean isWebKit() {
        return webkit;
    }
    /**
    * @return true if the browser is a robot - not operated by a human being
    */
    public boolean isRobot() {
        return robot;
    }
    @Override
    public String toString() {
        return name();
    }
    /**
    * @return the text-based description of this browser.
    */
    public String getLabel() {
        return label;
    }
}