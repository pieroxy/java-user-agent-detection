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

import net.pieroxy.ua.detection.Brand;
import net.pieroxy.ua.detection.Browser;
import net.pieroxy.ua.detection.BrowserFamily;
import net.pieroxy.ua.detection.Device;
import net.pieroxy.ua.detection.DeviceType;
import net.pieroxy.ua.detection.Locale;
import net.pieroxy.ua.detection.OS;
import net.pieroxy.ua.detection.OSFamily;
import net.pieroxy.ua.detection.UserAgentDetectionResult;
import net.pieroxy.ua.detection.UserAgentDetector;

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
      }
      if (nbFailures > 0)
        System.out.println(nbFailures + "/" + nbTests + " FAILURES.");
      else
        System.out.println("100% of " + nbTests + " succeeded.");
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
        browser_renderingEngine, os_family, os_description, os_version,
        device_type, device_brand, device_manufacturer, device, lang, country,
        comment, ignored_tokens, unknown_tokens, device_arch, browser_vendor,
        os_vendor;

    public UserAgentDetection(String line) {
      String[] elements = line.split("\t");
      id = elements[0];
      string = elements[1];
      browser_family = elements[2];
      browser_description = elements[3];
      browser_renderingEngine = elements[4];
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
    }

    public UserAgentDetectionResult getDetectionResult() {
      return new UserAgentDetectionResult(
          new Device(device_arch, Enum.valueOf(DeviceType.class, device_type),
              Enum.valueOf(Brand.class, device_brand), Enum.valueOf(
                  Brand.class, device_manufacturer), device), new Browser(
              Enum.valueOf(Brand.class, browser_vendor), Enum.valueOf(
                  BrowserFamily.class, browser_family), browser_description,
              browser_renderingEngine), new OS(Enum.valueOf(Brand.class,
              os_vendor), Enum.valueOf(OSFamily.class, os_family),
              os_description, os_version), new Locale(lang, country), comment,
          ignored_tokens, unknown_tokens);

    }
  }
}
