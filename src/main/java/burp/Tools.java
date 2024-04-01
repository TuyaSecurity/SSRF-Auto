package burp;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tools {

    private OkHttpClient client = new OkHttpClient();

    public static final Pattern PARAM_PATTERN = Pattern.compile("\\?.*$");

    public Tools() {
        this.client = new OkHttpClient.Builder()
                .connectTimeout(3, TimeUnit.SECONDS)
                .readTimeout(3, TimeUnit.SECONDS)
                .build();
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
//        Pattern pattern = Pattern.compile("\\?.*$");
        // 使用 Matcher 进行匹配
        Matcher matcher = PARAM_PATTERN.matcher(input);
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

    public void HTTP_request(IRequestInfo requestInfo, String new_url, IBurpExtenderCallbacks callbacks, ITextEditor textEditor, List<String> logRequestList) throws IOException {
        Request.Builder requestBuilder = new Request.Builder().url(new_url);
        // 添加原来的header
        for (String s : Get_header_list(requestInfo)) {
            String[] parts = s.split(":", 2);
            if (parts.length >= 2) {
                String key = parts[0].trim();
                String value = parts[1].trim();
                requestBuilder.addHeader(key, value);
            }
        }
        Request request = requestBuilder.build();
        try {
            String logReuquest = "\n-------------Get Replace Request-------------------\n" + request.url().toString() + '\n' + request.headers().toString();
            logRequestList.add(logReuquest);
            textEditor.setText(StringUtils.join(logRequestList, '\n').getBytes());
            client.newCall(request).execute().close();
            // 获取响应的状态码
        } catch (IOException e) {
            callbacks.printError("Get Request Error" + new_url + '\n');
        }
    }

    public void otherRequest(IRequestInfo requestInfo, String newBody, IBurpExtenderCallbacks callbacks, ITextEditor textEditor, List<String> logRequestList) throws IOException {
        RequestBody requestBody = RequestBody.create(MediaType.parse("text/plain"), newBody);
        Request.Builder requestBuilder = new Request.Builder().url(requestInfo.getUrl().toString());
        // 将原来的Header加入
        for (String s : Get_header_list(requestInfo)) {
            String[] parts = s.split(":", 2);
            String key = parts[0].trim();
            String value = parts[1].trim();
            if (!key.contains("Content-Length")) {
                requestBuilder.addHeader(key, value);
            }
        }
        switch (requestInfo.getMethod().toLowerCase()) {
            case "post":
                requestBuilder.post(requestBody);
                break;
            case "put":
                requestBuilder.put(requestBody);
                break;
            case "delete":
                if (newBody.isEmpty()) {
                    requestBuilder.delete();
                } else {
                    requestBuilder.delete(requestBody);
                }
                break;
            default:
                throw new IllegalArgumentException("Invalid HTTP method: " + requestInfo.getMethod().toLowerCase());
        }
        Request request = requestBuilder.build();
        try {
            String LogRequest = "\n-------------Post Replace Request -------------------\n" + request.url().toString() + '\n' + request.headers().toString() + '\n' + newBody;
            logRequestList.add(LogRequest);
            textEditor.setText(StringUtils.join(logRequestList, '\n').getBytes());
            client.newCall(request).execute().close();
        } catch (IOException e) {
            callbacks.printError("Post Request Error" + request.url().toString() + '\n');
        }
    }


}
