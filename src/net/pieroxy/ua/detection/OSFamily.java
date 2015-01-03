package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
public enum OSFamily {
    /**
    * An OS of the Windows NT Family (NT3.51, NT4, Windows 2000, XP, Vista, Seven, Windows 8...)
    */
    WINDOWS_NT("Windows NT",false),
    /**
    * Windows on a mobile device (Windows CE, Windows Phone OS, ...)
    */
    WINDOWS_MOBILE("Windows Mobile",false),
    /**
    * Windows pre-NT (Windows 3.x, 95, 98, ME)
    */
    WINDOWS("Windows",false),
    LINUX("Linux",true),
    MEEGO("MeeGo",true),
    ANDROID("Android",true),
    MACOSX("Mac OS X",false),
    MACOS("Mac OS",false),
    IOS("iOS",false),
    RIM_TABLET("Tablet OS",false),
    BBOS("BB OS",false),
    OTHER("Other",false),
    SERIES40("Nokia Series 40",false),
    BSD("*BSD",false),
    OS2("IBM OS/2",false),
    BEOS("BeOS",false),
    WEBOS("Web OS",true),
    BADA("Bada",false),
    RISC("RISC OS",false),
    UNIX("Unix",false),
    CHROMEOS("Chrome OS",true),
    SYMBIAN("Nokia Symbian",false),
    PLAYSTATION("Playstation",false),
    UNKNOWN("",false);

    private boolean linuxKernel;
    private String label;
    OSFamily(String _label, boolean _linux) {
        this.linuxKernel = _linux;
        this.label = _label;
    }

    /**
    * @return true if the OS has a Linux Kernel, such as Android, ChromeOS or a Linux desktop.
    */
    public boolean isLinuxKernel() {
        return linuxKernel;
    }
    public String toString() {
        return name();
    }
    public String getLabel() {
        return label;
    }
}