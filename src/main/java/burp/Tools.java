package burp;


import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tools {
    /**
     * 做一个以.的字符串分割
     *
     * @param inputString
     * @param delimiter
     * @return
     */
    public List<String> splitStringToList(String inputString, String delimiter) {
        List<String> partsList = new ArrayList<>();
        StringTokenizer tokenizer = new StringTokenizer(inputString, delimiter);
        while (tokenizer.hasMoreTokens()) {
            partsList.add(tokenizer.nextToken());
        }
        return partsList;

    }

    /**
     * 用于url中param的替换
     *
     * @param input
     * @param replacement
     * @return
     */
    public String replaceAfterQuestionMark(String input, String replacement) {
        // 创建正则表达式匹配模式
        Pattern pattern = Pattern.compile("\\?.*$");
        // 使用 Matcher 进行匹配
        Matcher matcher = pattern.matcher(input);
        // 查找匹配
        if (matcher.find()) {
            // 获取匹配到的位置
            int startIndex = matcher.start();
            // 将匹配到的内容替换为指定的字符串
            return input.substring(0, startIndex + 1) + replacement;
        } else {
            return input;
        }
    }

    /**
     * 获取header头的list
     *
     * @param requestInfo
     * @return
     */
    public List<String> Get_header_list(IRequestInfo requestInfo) {
        List<String> headerlist = requestInfo.getHeaders();
        // 删除前两个元素，前两个元素是path和Host
        if (headerlist.size() >= 2) {
            headerlist.remove(0);
            headerlist.remove(0);
        }
        return headerlist;
    }

    public void HTTP_request(IRequestInfo requestInfo, String new_url) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            // 创建 GET 请求
            HttpGet httpGet = new HttpGet(new_url);
            // 设置请求的连接超时时间和读取超时时间（单位：毫秒）
            int timeout = 2000; // 0.5秒
            RequestConfig requestConfig = RequestConfig.custom()
                    .setConnectTimeout(timeout)
                    .setSocketTimeout(timeout)
                    .build();

            httpGet.setConfig(requestConfig);
            // 添加自定义 Header
            for (String s : Get_header_list(requestInfo)) {
                String[] parts = s.split(":", 2);
                String key = parts[0].trim();
                String value = parts[1].trim();
                httpGet.setHeader(key, value);
            }
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                // 获取响应状态码
//                int statusCode = response.getStatusLine().getStatusCode();
//
//                // 获取响应内容
//                HttpEntity entity = response.getEntity();
//                String responseBody = EntityUtils.toString(entity);
//
//                // 输出响应状态码和响应内容
//                System.out.println("Get-----Response Body: " + responseBody);
            }
        }

    }

    public void Post_request(IRequestInfo requestInfo, String new_body) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            // 创建 Post请求
            HttpPost httpPost = new HttpPost(requestInfo.getUrl().toString());


            // 设置请求的连接超时时间和读取超时时间（单位：毫秒）
            int timeout = 2000; // 0.5秒
            RequestConfig requestConfig = RequestConfig.custom()
                    .setConnectTimeout(timeout)
                    .setSocketTimeout(timeout)
                    .build();
            httpPost.setConfig(requestConfig);

            // 添加自定义 Header
            for (String s : Get_header_list(requestInfo)) {
                String[] parts = s.split(":", 2);
                String key = parts[0].trim();
                String value = parts[1].trim();
                if(!key.contains("Content-Length")) {
                    System.out.println(key);
                    httpPost.setHeader(key, value);
                }
            }
            StringEntity entity = new StringEntity(new_body);
            httpPost.setEntity(entity);
            HttpResponse response = httpClient.execute(httpPost);
//            String responseBody = EntityUtils.toString(response.getEntity());
//            System.out.println("Post----Response: " + responseBody);
        }
    }

    /**
     * 判断是否能匹配到域名
     *
     * @param input
     * @param regex
     * @return
     */
    public boolean hasMatch(String input, String regex) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(input);
        return matcher.find();
    }

    public boolean blacklist(String host) {
        List<String> list = List.of("baidu", "google", "firefox", "edge", "github", "gitee", "csdn", "sougou");
        for (String str : list) {
            if (StringUtils.indexOf(host, str) > -1) {
                return true;
            }
        }
        return false;

    }


}