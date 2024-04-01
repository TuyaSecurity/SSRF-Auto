// SSRFVulnerableServer.java

import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URLDecoder;

public class Test {
    public static boolean isSubstring(String mainString, String subString) {
        return mainString.contains(subString);
    }

    public static void main(String[] args) {
        String str = "Here are some domains: www.example.com, @google.com, test@domain.org, 192.168.1.1, @10.0.0.1.";
        // 正则表达式匹配域名或IP
        String domainPattern = "\\b((?:\\d{1,3}\\.){3}\\d{1,3}\\b)|(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\\.)+[a-zA-Z]{2,6}\\b";

        Pattern pattern = Pattern.compile(domainPattern);
        Matcher matcher = pattern.matcher(str);
        StringBuffer sb = new StringBuffer();

        while (matcher.find()) {
            if (matcher.start() > 0 && str.charAt(matcher.start() - 1) == '@') {
                matcher.appendReplacement(sb, matcher.group());
            } else {
                matcher.appendReplacement(sb, "REPLACED");
            }
        }
        matcher.appendTail(sb);
        System.out.println("Modified String: " + sb.toString());

    }
}
