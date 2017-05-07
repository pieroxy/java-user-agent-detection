package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* This represents a class that will be able to detect a user-agent features.
*/
public interface IUserAgentDetector {
    /**
     * Parse a user-agent string
     *
     * @param ua The user agent string as sent by the browser
     * @return   The result of the detection
     */
    UserAgentDetectionResult parseUserAgent(String ua);
}