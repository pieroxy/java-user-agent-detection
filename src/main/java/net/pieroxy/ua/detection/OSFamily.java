package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describes the family of an Operating System. This is a category of OSes which will make it easier to categorize them.
*/
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
    /**
    * Desktop Linux, such as Debian, Ubuntu, RedHat, etc.
    */
    LINUX("Linux",true),
    /**
    * MeeGo, the mobile OS by Nokia and The Linux Foundation.
    */
    MEEGO("MeeGo",true),
    /**
    * Android, the mobile OS by Google.
    */
    ANDROID("Android",true),
    /**
    * Mac OS X, by Apple.
    */
    MACOSX("Mac OS X",false),
    /**
    * Mac OS, by Apple, before Mac OS X.
    */
    MACOS("Mac OS",false),
    /**
    * iOS, by Apple, the OS for iPhones, iPads and iPods Touch.
    */
    IOS("iOS",false),
    /**
    * The Tablet OS, by BlackBerry.
    */
    RIM_TABLET("Tablet OS",false),
    /**
    * The BlackBerry OS, mostly used on BlackBerry phones.
    */
    BBOS("BB OS",false),
    /**
    * The OS was detected but judged not worthy enough to get a place in the enum. This will be OSes such as Open VMS, Palm OS, SonyEricsson's phones's OS, etc...
    */
    OTHER("Other",false),
    /**
    * Series 40 OS, by Nokia.
    */
    SERIES40("Nokia Series 40",false),
    /**
    * One of the BSD OSes (Free BSD, Open BSD, etc)
    */
    BSD("*BSD",false),
    /**
    * OS/2 by IBM
    */
    OS2("IBM OS/2",false),
    /**
    * BeOS, by Be Inc
    */
    BEOS("BeOS",false),
    /**
    * Web OS by Palm and then HP
    */
    WEBOS("Web OS",true),
    /**
    * Bada, the OS by Samsung
    */
    BADA("Bada",false),
    /**
    * RISC OS, by Castle Technology &amp; RISC OS Open (version 5), and RISCOS Ltd (versions 4 &amp; 6)
    */
    RISC("RISC OS",false),
    /**
    * One of the many Unices such as Sun OS, Solaris, IRIX, AIX and many others
    */
    UNIX("Unix",false),
    /**
    * Chrome OS, by Google.
    */
    CHROMEOS("Chrome OS",true),
    /**
    * Symbian, the OS by Nokia.
    */
    SYMBIAN("Nokia Symbian",false),
    /**
    * The OS of the PlayStation, by Sony.
    */
    PLAYSTATION("Playstation",false),
    /**
    * No OS could be detected.
    */
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