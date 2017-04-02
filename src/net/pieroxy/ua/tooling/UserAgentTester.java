package net.pieroxy.ua.tooling;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;

import net.pieroxy.ua.detection.*;

public class UserAgentTester {

  private static UserAgentDetector detector = new UserAgentDetector();

  public static void printUsage() {
    System.out.println("Usage:");
    System.out.println("  UserAgentTester [test|perf] filename");
  }

  public static void main(String[] args) throws IOException {
    if (args.length != 2) {
      printUsage();
      return;
    }

    if (args[0].equals("test")) {
      test(args[1]);
    } else if (args[0].equals("perf")) {
      perf(args[1]);
    } else {
      printUsage();
    }
  }

  public static void test(String fileName) throws IOException {
    UserAgentDetector.test();

    File f = new File(fileName);
    InputStream is = new GZIPInputStream(new FileInputStream(f));
    Reader r = new InputStreamReader(is);
    BufferedReader br = new BufferedReader(r);
    int lineNumber = 1;

    try {
      br.readLine(); // Discard header
      String line;

      int nbTests = 0;
      int nbFailures = 0;
      while ((line = br.readLine()) != null) {
        if (!test(new UserAgentDetection(line))) {
          nbFailures++;
        }
        nbTests++;
        lineNumber++;
      }
      if (nbFailures > 0)
        System.out.println(nbFailures + "/" + nbTests + " FAILURES.");
      else
        System.out.println("100% of " + nbTests + " succeeded.");
    } catch (Exception e) {
      throw new RuntimeException("at line " + lineNumber, e);
    } finally {
      br.close();
    }
  }

  public static void perf(String fileName) throws IOException {
    File f = new File(fileName);
    InputStream is = new GZIPInputStream(new FileInputStream(f));
    Reader r = new InputStreamReader(is);
    BufferedReader br = new BufferedReader(r);
    List<String> allElements = new ArrayList<String>();

    int nbTests = 0;

    try {
      br.readLine(); // Discard header
      String line;

      while ((line = br.readLine()) != null) { // Dry run to preload the JVM and
                                               // the data
        UserAgentDetection a = new UserAgentDetection(line);
        allElements.add(a.string);
        perfOne(a.string);
        nbTests++;
      }
    } finally {
      br.close();
    }

    long begin = System.currentTimeMillis();
    for (String s : allElements)
      perfOne(s);
    long end = System.currentTimeMillis();

    System.out.println(nbTests + " tests run, avg of " + (end - begin + 0.0)
        / nbTests + " ms");
  }

  private static boolean test(UserAgentDetection uad) {
    UserAgentDetectionResult detection = detector.parseUserAgent(uad.string);
    String result = compare(uad.getDetectionResult(), detection);
    if (result != null) {
      String prefix = "";
      for (int i = 0; i < uad.id.length() + 2; i++)
        prefix += " ";
      result = result.replaceAll("\t", prefix);
      result = result.replaceFirst(prefix, uad.id + ": ");
      System.out.print(result);
    }
    return result == null;
  }

  private static void perfOne(String s) {
    detector.parseUserAgent(s);
  }

  private static String compare(UserAgentDetectionResult a,
      UserAgentDetectionResult b) {
    if (a.equals(b))
      return null;
    StringBuilder result = new StringBuilder();
    addErrorReport(result, "browser", a.getBrowser(), b.getBrowser());
    addErrorReport(result, "browser description", a.getBrowser().getDescription(),
        b.getBrowser().getDescription());
    addErrorReport(result, "browser family", a.getBrowser().getFamily(), b.getBrowser().getFamily());
    addErrorReport(result, "browser rendering engine",
        a.getBrowser().getRenderingEngine(), b.getBrowser().getRenderingEngine());
    addErrorReport(result, "browser vendor", a.getBrowser().getVendor(), b.getBrowser().getVendor());
    addErrorReport(result, "browser version", a.getBrowser().getVersion(),
        b.getBrowser().getVersion());
    addErrorReport(result, "browser fullVersion", a.getBrowser().getFullVersion(),
        b.getBrowser().getFullVersion());

    addErrorReport(result, "device", a.getDevice(), b.getDevice());
    addErrorReport(result, "device architecture", a.getDevice().getArchitecture(),
            b.getDevice().getArchitecture());
    addErrorReport(result, "device brand", a.getDevice().getBrand(), b.getDevice().getBrand());
    addErrorReport(result, "device name", a.getDevice().getDevice(), b.getDevice().getDevice());
    addErrorReport(result, "device type", a.getDevice().getDeviceType(),
            b.getDevice().getDeviceType());
    addErrorReport(result, "device manufacturer", a.getDevice().getManufacturer(),
            b.getDevice().getManufacturer());

    addErrorReport(result, "OS", a.getOperatingSystem(), b.getOperatingSystem());
    addErrorReport(result, "OS", a.getOperatingSystem().getDescription(),
            b.getOperatingSystem().getDescription());
    addErrorReport(result, "OS family", a.getOperatingSystem().getFamily(),
        b.getOperatingSystem().getFamily());
    addErrorReport(result, "OS vendor", a.getOperatingSystem().getVendor(),
            b.getOperatingSystem().getVendor());
    addErrorReport(result, "OS version", a.getOperatingSystem().getVersion(),
            b.getOperatingSystem().getVersion());

    addErrorReport(result, "bot brand", a.getBot() == null ? null : a.getBot().getVendor(),
            (b.getBot() == null) ? null : b.getBot().getVendor());
    addErrorReport(result, "bot type", a.getBot() == null ? null : a.getBot().getFamily(),
        b.getBot() == null ? null : b.getBot().getFamily());
    addErrorReport(result, "bot description", a.getBot() == null ? null
        : a.getBot().getDescription(), b.getBot() == null ? null : b.getBot().getDescription());
    addErrorReport(result, "bot version", a.getBot() == null ? null : a.getBot().getVersion(),
            (b.getBot() == null) ? null : b.getBot().getVersion());
    addErrorReport(result, "bot url", a.getBot() == null ? null : a.getBot().getUrl(),
        b.getBot() == null ? null : b.getBot().getUrl());

    {
      RenderingEngine ra = a.getBrowser().getRenderingEngine();
      RenderingEngine rb = b.getBrowser().getRenderingEngine();
      addErrorReport(result, "rendering engine vendor", ra.getVendor(), rb.getVendor());
      addErrorReport(result, "rendering engine family", ra.getFamily(), rb.getFamily());
      addErrorReport(result, "rendering engine version", ra.getVersion(), rb.getVersion());
      addErrorReport(result, "rendering engine fullVersion", ra.getFullVersion(), rb.getFullVersion());
    }

    addErrorReport(result, "ignored tokens", a.getIgnoredTokens(), b.getIgnoredTokens());
    addErrorReport(result, "unknown tokens", a.getUnknownTokens(), b.getUnknownTokens());
    addErrorReport(result, "extensions", a.getExtensionsAsString(),
        b.getExtensionsAsString());
    return result.length() == 0 ? null : result.toString();
  }

  private static void addErrorReport(StringBuilder errors, String name,
      Object expected, Object actual) {
    if (objectEquals(expected, actual))
      return;
    if (expected == null) {
      errors.append("\texpected ").append(name).append(" to be null\n");
    } else if (actual == null) {
      errors.append("\texpected ").append(name)
          .append(" to not be null but to be '").append(expected.toString())
          .append("'\n");
    } else {
      if (expected != null && actual != null) {
        if (expected instanceof String || expected instanceof Enum) {
          errors.append("\texpected ").append(name).append(" to be '")
              .append(expected.toString()).append("' but was '")
              .append(actual.toString()).append("'\n");

        }
      }
    }
  }

  private static boolean objectEquals(Object a, Object b) {
    if (a == null && b == null)
      return true;
    if (a == null || b == null)
      return false;
    return a.equals(b);
  }

  private static class UserAgentDetection {
    String id, string, browser_family, browser_description,
        os_family, os_description, os_version,
        device_type, device_brand, device_manufacturer, device, lang, country,
        comment, ignored_tokens, unknown_tokens, device_arch, browser_vendor,
        os_vendor, bot_family, bot_vendor, bot_description, bot_version,
        bot_url, browser_version, browser_fullVersion, re_brand, re_family,
        re_version, re_fullversion;


    public UserAgentDetection(String line) {
      String[] elements = line.split("\t", -1);
      id = elements[0];
      string = elements[1];
      browser_family = elements[2];
      browser_description = elements[3];
      os_family = elements[5];
      os_description = elements[6];
      os_version = elements[7];
      device_type = elements[8];
      device_brand = elements[9];
      device_manufacturer = elements[10];
      device = elements[11];
      lang = elements[13];
      country = elements[14];
      comment = elements[15];
      ignored_tokens = elements[16];
      unknown_tokens = elements[17];
      device_arch = elements[18];
      browser_vendor = elements[19];
      os_vendor = elements[20];
      bot_vendor = getStringOrNull(elements[22]);
      bot_family = getStringOrNull(elements[23]);
      bot_description = getStringOrNull(elements[24]);
      bot_version = getStringOrNull(elements[25]);
      bot_url = getStringOrNull(elements[26]);
      browser_version = getStringOrNull(elements[27]);
      browser_fullVersion = getStringOrNull(elements[28]);
      re_brand = getStringOrNull(elements[29]);
      re_family = getStringOrNull(elements[30]);
      re_version  = getStringOrNull(elements[31]);
      re_fullversion = getStringOrNull(elements[32]);
    }

    private String getStringOrNull(String s) {
      if (s == null || s.equals("NULL"))
        return null;
      return s;
    }

    public UserAgentDetectionResult getDetectionResult() {
      Bot bot = null;
      BotFamily f = (bot_family == null || bot_family.length() == 0 || bot_family
          .equals("NULL")) ? null : Enum.valueOf(BotFamily.class, bot_family);
      if (f != null) {
        bot = new Bot(Enum.valueOf(Brand.class, bot_vendor), f,
            bot_description, bot_version, bot_url);
      }

      return new UserAgentDetectionResult(
          new Device(device_arch, Enum.valueOf(DeviceType.class, device_type),
              Enum.valueOf(Brand.class, device_brand), Enum.valueOf(
                  Brand.class, device_manufacturer), device),
          new Browser(Enum.valueOf(Brand.class, browser_vendor),
                  Enum.valueOf(BrowserFamily.class, browser_family),
                  browser_description,
                  new RenderingEngine(
                          Enum.valueOf(Brand.class, re_brand),
                          Enum.valueOf(RenderingEngineFamily.class, re_family),
                          re_version, re_fullversion),
                  browser_version,
                  browser_fullVersion),
          new OS(Enum.valueOf(Brand.class, os_vendor), Enum.valueOf(
              OSFamily.class, os_family), os_description, os_version),
          new Locale(lang, country), comment, ignored_tokens, unknown_tokens,
          bot);

    }
  }
}
