package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
public enum BrowserFamily {  IE("Internet Explorer",false, true, false, false),
                             FIREFOX("Firefox",true, false, false, false),
                             CHROME("Chrome",false, false, true, false),
                             OPERA("Opera",false, false, false, false),
                             IOS("iOS's default browser",false, false, true, false),
                             ANDROID("Android's default browser",false, false, true, false),
                             SAFARI("Safari",false, false, true, false),
                             OTHER_GECKO("Gecko-based",true, false, false, false),
                             OTHER_WEBKIT("WebKit-based",false, false, true, false),
                             OTHER_TRIDENT("IE-based",false, true, false, false),
                             KHTML("KHTML-based",false, false, false, false),
                             NETFRONT("NetFront",false, false, false, false),
                             TEXTBASED("Text Based",false, false, false, false),
                             ROBOT("Other Robot/Program",false, false, false,true ),
                             SPAMBOT("Spam bot",false, false, false,true ),
                             CRAWLER("Web Crawler",false, false, false,true ),
                             OTHER("Other",false, false, false, false),
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
public String toString() {
    return name();
}
public String getLabel() {
    return label;
}
                          }