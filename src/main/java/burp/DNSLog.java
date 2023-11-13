package burp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Date;

public class DNSLog {

    public List DNSLog(BurpExtender.MyTableModel tableModel, List<BurpExtender.MyData> dataList, List list,IBurpExtenderCallbacks callbacks,String webhook) throws IOException {
//        dataList.clear();
        List<String> namelist = new ArrayList<>();
        int flag = 0;
        URL url = new URL(webhook);
        // 打开连接
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        // 设置连接超时时间和读取超时时间（单位：毫秒）
        int timeout = 5000; // 3秒
        connection.setConnectTimeout(timeout);
        connection.setReadTimeout(timeout);

        // 设置请求方法为 GET
        connection.setRequestMethod("GET");
        // 获取响应状态码
        int responseCode = connection.getResponseCode();
        if (responseCode != 200) {
            callbacks.printOutput("ceye接口请求出现问题，请检查网络");
        }
        // 读取响应内容
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String line;
        StringBuilder response = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        String rs = response.toString();
        System.out.println(rs);
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(rs);
            String item = jsonNode.get("data").toString();
            jsonNode = objectMapper.readTree(item);
            for (JsonNode node : jsonNode) {
                flag = flag + 1;
                String id = node.get("id").asText();
                String name = node.get("name").asText();
                String remoteAddr = node.get("remote_addr").asText();
                String createdAt = node.get("created_at").asText();
                createdAt = time_switch(createdAt);


                String[] rowData = new String[5];
                rowData[0] = id;
                rowData[1] = name;
                rowData[2] = remoteAddr;
                rowData[3] = createdAt;

                namelist.add(name);

                if (!list.contains(id)) {
                    tableModel.addData(rowData);
                }
            }
            return namelist;
        } catch (Exception e) {
            System.out.println("DNSe: " + e.getMessage());
            return namelist;

        } catch (Throwable th) {
            System.out.println("DNSth: " + th);
            return namelist;
        }

    }

    /**
     * 这里时间需要加8小时
     *
     * @param createdAt
     * @return
     */
    public String time_switch(String createdAt) {

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        try {
            // 将字符串解析为 Date 对象
            Date date = sdf.parse(createdAt);
            // 加上 8 小时
            long timeInMillis = date.getTime();
            timeInMillis += 8 * 60 * 60 * 1000; // 8 小时的毫秒数
            date.setTime(timeInMillis);
            // 将 Date 对象转换回字符串
            String result = sdf.format(date);
            return result;
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }

}
