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
    addErrorReport(result, "browser", a.browser, b.browser);
    addErrorReport(result, "browser description", a.browser.description,
        b.browser.description);
    addErrorReport(result, "browser family", a.browser.family, b.browser.family);
    addErrorReport(result, "browser rendering engine",
        a.browser.renderingEngine, b.browser.renderingEngine);
    addErrorReport(result, "browser vendor", a.browser.vendor, b.browser.vendor);
    addErrorReport(result, "browser version", a.browser.version,
        b.browser.version);
    addErrorReport(result, "browser fullVersion", a.browser.fullVersion,
        b.browser.fullVersion);

    addErrorReport(result, "device", a.device, b.device);
    addErrorReport(result, "device architecture", a.device.architecture,
        b.device.architecture);
    addErrorReport(result, "device brand", a.device.brand, b.device.brand);
    addErrorReport(result, "device name", a.device.device, b.device.device);
    addErrorReport(result, "device type", a.device.deviceType,
        b.device.deviceType);
    addErrorReport(result, "device manufacturer", a.device.manufacturer,
        b.device.manufacturer);

    addErrorReport(result, "OS", a.operatingSystem, b.operatingSystem);
    addErrorReport(result, "OS", a.operatingSystem.description,
        b.operatingSystem.description);
    addErrorReport(result, "OS family", a.operatingSystem.family,
        b.operatingSystem.family);
    addErrorReport(result, "OS vendor", a.operatingSystem.vendor,
        b.operatingSystem.vendor);
    addErrorReport(result, "OS version", a.operatingSystem.version,
        b.operatingSystem.version);

    addErrorReport(result, "bot brand", a.bot == null ? null : a.bot.vendor,
        b.bot == null ? null : b.bot.vendor);
    addErrorReport(result, "bot type", a.bot == null ? null : a.bot.family,
        b.bot == null ? null : b.bot.family);
    addErrorReport(result, "bot description", a.bot == null ? null
        : a.bot.description, b.bot == null ? null : b.bot.description);
    addErrorReport(result, "bot version", a.bot == null ? null : a.bot.version,
        b.bot == null ? null : b.bot.version);
    addErrorReport(result, "bot url", a.bot == null ? null : a.bot.url,
        b.bot == null ? null : b.bot.url);

    addErrorReport(result, "ignored tokens", a.ignoredTokens, b.ignoredTokens);
    addErrorReport(result, "unknown tokens", a.unknownTokens, b.unknownTokens);
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
