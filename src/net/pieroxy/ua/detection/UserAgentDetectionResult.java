package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
public class UserAgentDetectionResult {
    public Device device;
    public Browser browser;
    public OS operatingSystem;
    Locale locale;
    private Set<Extension> extensions = new HashSet<Extension>();
    public String ignoredTokens;
    public String unknownTokens;
    String debug;
    private boolean objectEquals(Object a, Object b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.equals(b);
    }

    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof UserAgentDetectionResult)) return false;
        UserAgentDetectionResult d = (UserAgentDetectionResult) o;
        return
            objectEquals(d.device,device) &&
            objectEquals(d.browser,browser) &&
            objectEquals(d.locale,locale) &&
            objectEquals(d.getExtensions(),getExtensions()) &&
            ( d.ignoredTokens.equals(ignoredTokens) ) &&
            ( d.unknownTokens.equals(unknownTokens) ) &&
            objectEquals(d.operatingSystem,operatingSystem);
    }
    public String diff(Object o) {
        if (o == null) return "null";
        if (! (o instanceof UserAgentDetectionResult)) return "!this.class";
        UserAgentDetectionResult d = (UserAgentDetectionResult) o;
        if (!objectEquals(d.device,device)) return "device";
        if (!objectEquals(d.browser,browser)) return "browser";
        if (!objectEquals(d.locale,locale)) return "locale";
        if (!objectEquals(d.getExtensions().size(),getExtensions().size())) return "extensions " + d.getExtensions().size() + " " +  getExtensions().size();
        if (!objectEquals(d.getExtensions(),getExtensions())) return "extensions " + d.getExtensions().size() + " " +  getExtensions().size() + " " + getExtensions().iterator().next().getName() + " " + d.getExtensions().iterator().next().getVersion() + " " + getExtensions().iterator().next().getVersion();


        if (!objectEquals(d.operatingSystem,operatingSystem)) return "os";
        return "==";
    }
    public int hashCode() {
        int res = 0;
        if (getExtensions()!= null) {
            res *= 3;
            res += getExtensions().hashCode();
        }
        if (ignoredTokens!= null) {
            res *= 3;
            res += ignoredTokens.hashCode();
        }
        if (unknownTokens!= null) {
            res *= 3;
            res += unknownTokens.hashCode();
        }
        if (device!= null) {
            res *= 3;
            res += device.hashCode();
        }
        if (operatingSystem!= null) {
            res *= 3;
            res += operatingSystem.hashCode();
        }
        if (browser!= null) {
            res *= 3;
            res += browser.hashCode();
        }
        if (locale!= null) {
            res *= 3;
            res += locale.hashCode();
        }
        return res;
    }
    public UserAgentDetectionResult() {
        locale = new Locale();
        extensions = new HashSet<Extension>();
        ignoredTokens = "";
        unknownTokens = "";
    }
    public UserAgentDetectionResult(Device _device, Browser _browser, OS _os, Locale _locale, String _extensions) {
        this(_device,_browser, _os, _locale);
        this.extensions = Extension.deserialize(_extensions);
    }
    public UserAgentDetectionResult(Device _device, Browser _browser, OS _os, Locale _locale, String _extensions, String ignored, String unknown) {
        this(_device,_browser, _os, _locale, _extensions);
        ignoredTokens = ignored;
        unknownTokens = unknown;
    }
    public UserAgentDetectionResult(Device _device, Browser _browser, OS _os, Locale _locale) {
        this(_device,_browser, _os);
        if (locale != null) this.locale = _locale;
    }
    public UserAgentDetectionResult(Device _device, Browser _browser, OS _os) {
        this();
        device = _device;
        browser = _browser;
        operatingSystem = _os;
    }

    public UserAgentDetectionResult wrapUp (UserAgentContext context) {
        this.ignoredTokens = context.getIgnoredTokens();
        this.unknownTokens = context.getRemainingTokens();
        this.debug = context.getDebug();
        return this;
    }

    public void addExtension(Extension e) {
        if (extensions == null) extensions = new HashSet<Extension>();
        extensions.add(e);
    }
    public void addAllExtensions(Collection<Extension> ee) {
        if (extensions == null) extensions = new HashSet<Extension>();
        extensions.addAll(ee);
    }
    public Set<Extension> getExtensions() {
        return extensions;
    }
    public String getExtensionsAsString() {
        StringBuilder sb = new StringBuilder();
        for (Extension e : getExtensions()) {
            if (sb.length()>0) sb.append(", ");
            sb.append(e.toString());
        }
        return sb.toString();
    }
    public String serializeExtensions() {
        StringBuilder sb = new StringBuilder();
        for (Extension e : getExtensions()) {
            if (sb.length()>0) sb.append("^");
            sb.append(e.serialize());
        }
        return sb.toString();
    }


    public Device getDevice() {
        return device;
    }
    public Browser getBrowser() {
        return browser;
    }
    public OS getOperatingSystem() {
        return operatingSystem;
    }
    public Locale getLocale() {
        return locale;
    }
    public String getIgnoredTokens() {
        return ignoredTokens;
    }
    public String getUnknownTokens() {
        return unknownTokens;
    }



}