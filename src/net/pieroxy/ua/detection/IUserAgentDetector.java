package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
public interface IUserAgentDetector {
    public UserAgentDetectionResult parseUserAgent(String ua);
}