package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* This is the class returned by the detection API.
*/
public class UserAgentDetectionResult {
    private String debug;
    private Set<Extension> extensions = new HashSet<Extension>();

    private String ignoredTokens;
    private String unknownTokens;

    private Locale locale;
    private Device device;
    private Bot bot;
    private Browser browser;
    private OS operatingSystem;

    private boolean objectEquals(Object a, Object b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.equals(b);
    }
    private boolean botEquals(Bot a, Bot b) {
        if ((a == null || a.getFamily() == null)  && (b == null || b.getFamily() == null)) return true;
        if ((a == null || a.getFamily() == null)  || (b == null || b.getFamily() == null)) return false;
        return a.equals(b);
    }

    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof UserAgentDetectionResult)) return false;
        UserAgentDetectionResult d = (UserAgentDetectionResult) o;
        return
            botEquals(d.bot,bot) &&
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
        if (!botEquals(d.bot,bot)) return "bot";
        if (!objectEquals(d.browser,browser)) return "browser";
        if (!objectEquals(d.locale,locale)) return "locale";
        if (!objectEquals(d.unknownTokens,unknownTokens)) return "unknownTokens";
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
        if (bot!= null) {
            res *= 3;
            res += bot.hashCode();
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
    public UserAgentDetectionResult(Device _device, Browser _browser, OS _os, Locale _locale, String _extensions, String ignored, String unknown, Bot bot) {
        this(_device,_browser, _os, _locale, _extensions, ignored, unknown);
        this.bot = bot;
    }
    public UserAgentDetectionResult(Device _device, Browser _browser, OS _os, Locale _locale) {
        this(_device,_browser, _os);
        if (locale != null) this.locale = _locale;
    }
    public UserAgentDetectionResult(Device _device, Browser _browser, OS _os, Bot _bot) {
        this(_device, _browser, _os);
        this.bot = _bot;
    }
    public UserAgentDetectionResult(Device _device, Browser _browser, OS _os) {
        this();
        device = _device;
        browser = _browser;
        operatingSystem = _os;
    }

    UserAgentDetectionResult wrapUp (UserAgentContext context) {
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
    private List<Extension> getSortedExtensions() {
        ArrayList<Extension> le = new ArrayList<Extension>();
        le.addAll(getExtensions());
        Collections.sort(le, new Comparator<Extension>() {
            public int compare(Extension a, Extension b) {
                return a.serialize().compareTo(b.serialize());
            }
        });
        return le;
    }
    public String getExtensionsAsString() {
        StringBuilder sb = new StringBuilder();
        for (Extension e : getSortedExtensions()) {
            if (sb.length()>0) sb.append(", ");
            sb.append(e.toString());
        }
        return sb.toString();
    }
    public String serializeExtensions() {
        StringBuilder sb = new StringBuilder();
        for (Extension e : getSortedExtensions()) {
            if (sb.length()>0) sb.append("^");
            sb.append(e.serialize());
        }
        return sb.toString();
    }


    public Bot getBot() {
        return bot;
    }
    public void setBot(Bot b) {
        bot=b;
    }
    public Device getDevice() {
        return device;
    }
    public void setDevice(Device d) {
        device = d;
    }
    public Browser getBrowser() {
        return browser;
    }
    public void setBrowser(Browser b) {
        browser = b;
    }
    public OS getOperatingSystem() {
        return operatingSystem;
    }
    public void setOperatingSystem(OS os) {
        operatingSystem=os;
    }
    public Locale getLocale() {
        return locale;
    }
    public void setLocale(Locale l) {
        locale = l;
    }
    public String getIgnoredTokens() {
        return ignoredTokens;
    }
    public String getUnknownTokens() {
        return unknownTokens;
    }



}