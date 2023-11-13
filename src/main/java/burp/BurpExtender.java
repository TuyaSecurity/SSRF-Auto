package burp;


import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import com.fasterxml.jackson.databind.annotation.JsonAppend;
import org.json.JSONObject;
import burp.DNSLog.*;
import java.net.URLDecoder;


//要使用这个文件中的代码，需要先将文件名改为BurpExtender.java
public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    //swingui用于接收参数
    private JTextField inputField;
    private List<MyData> dataList;
    private MyTableModel tableModel;
    private JTable table;
    private JTabbedPane tabs;
    private JSplitPane splitPane;
    private JTextField textField1;
    private JTextField textField2;
    private JTextField textField3;
    private JPanel panel;
    private JPanel rightPanel;
    private JButton customButton;
    private JButton clearButton;
    private List list = new ArrayList();
    private IBurpCollaboratorClientContext burpCollaboratorClientContext;
    private boolean isButtonEnabled = false;
    Tools tools = new Tools();


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object  获取helpers对象
        helpers = callbacks.getHelpers();

        // set our extension name 设置插件名称
        callbacks.setExtensionName("SSRF-Auto");

        dataList = new ArrayList<>();

        // 注册监听器
        callbacks.registerHttpListener(this);

        callbacks.addSuiteTab(this);

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        if (messageIsRequest && isButtonEnabled) {
            // 获取请求数据包
            IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
            String request = new String(messageInfo.getRequest(), StandardCharsets.UTF_8);
            String regex = textField2.getText();
            System.out.println(requestInfo.getUrl().getQuery());
            if(!tools.blacklist(requestInfo.getUrl().getHost())) {

                        if (requestInfo.getMethod().equalsIgnoreCase("GET") && URLDecoder.decode(requestInfo.getUrl().getQuery()) != null && tools.hasMatch(requestInfo.getUrl().getQuery(), regex)) {
                            //替换过param后的URL
                            String new_url = Get_replaceContent(requestInfo, messageInfo);

                        }
                        //判断是不是get请求且body不为空, 且正则匹配不为空
                        else if (requestInfo.getMethod() == "POST" && requestInfo.getBodyOffset() != -1 && tools.hasMatch(request.substring(requestInfo.getBodyOffset()), regex)) {
                            // 获取请求的 body 数据
                            String requestBody = request.substring(requestInfo.getBodyOffset());
                            String new_body = Post_replaceContent(requestBody, requestInfo, messageInfo);
                        }
            }
        }else {
            System.out.println("");
        }

    }

    /**
     * GET以外的请求做处理
     *
     * @param originalBody
     * @param requestInfo
     * @return
     */
    private String Post_replaceContent(String originalBody, IRequestInfo requestInfo, IHttpRequestResponse messageInfo) {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        URL url = requestInfo.getUrl();
        String path = url.getPath().replace('/', '.');
        String host = url.getHost();
        String method = requestInfo.getMethod().toLowerCase();
        String replacement = method+'.'+host + path +'.'+textField1.getText();
        String input = originalBody;
        String regex = textField2.getText();
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(input);
        StringBuffer sb = new StringBuffer();
        while(matcher.find()){
            if (matcher.start() > 0 && input.charAt(matcher.start() - 1) == '@') {
                matcher.appendReplacement(sb, matcher.group());
            }else {
                matcher.appendReplacement(sb, replacement);
            }
        }
        matcher.appendTail(sb);
        String result = sb.toString();
        String webhook = textField3.getText();
        //异步发送一个post请求
        Runnable task = new Runnable() {
            @Override
            public void run() {
                try {
                    tools.Post_request(requestInfo, result);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try {
                    List<String> include = new ArrayList<>();
                    include = new DNSLog().DNSLog(tableModel, dataList, list, callbacks,webhook);
                    if (include.contains(replacement)) {
                        messageInfo.setHighlight("red");
                    }

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };
        Future<?> future = executorService.submit(task);
        try {
            // 等待异步任务完成，最多等待5秒钟
            future.get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            // 处理异常
        }
        executorService.shutdown();

        return result;
    }

    /**
     * GET请求做处理
     *
     * @param requestInfo
     * @return
     */
    private String Get_replaceContent(IRequestInfo requestInfo, IHttpRequestResponse messageInfo) {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        URL url = requestInfo.getUrl();
        String method = requestInfo.getMethod().toLowerCase();
        String path = url.getPath().replace('/', '.');
        String host = url.getHost();
        String replacement = method+'.'+host + path +'.'+textField1.getText();
        // 在这里编写替换内容的逻辑
        String input = URLDecoder.decode(url.getQuery());
//        String regex = "^(?:[a-zA-Z0-9][a-zA-Z0-9-]*\\.)*(?:[a-zA-Z0-9][a-zA-Z0-9-]*\\.)?(?:com(?:\\.cn)?|xyz|top|net|org)$";
        String regex = textField2.getText();
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(input);
        StringBuffer sb = new StringBuffer();
        while(matcher.find()){
            if (matcher.start() > 0 && input.charAt(matcher.start() - 1) == '@') {
                matcher.appendReplacement(sb, matcher.group());
            }else {
                matcher.appendReplacement(sb, replacement);
            }
        }
        matcher.appendTail(sb);
        String Get_url = tools.replaceAfterQuestionMark(url.toString(), sb.toString());
        String webhook = textField3.getText();
        //异步发送一个get请求
        Runnable task = new Runnable() {
            @Override
            public void run() {
                try {
                    tools.HTTP_request(requestInfo, Get_url);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try {
                    List<String> include = new ArrayList<>();
                    include = new DNSLog().DNSLog(tableModel, dataList, list, callbacks,webhook);
                    if (include.contains(replacement)) {
                        messageInfo.setHighlight("red");
                    }

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };
        Future<?> future = executorService.submit(task);
        try {
            // 等待异步任务完成，最多等待5秒钟
            future.get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            // 处理异常
        }
        executorService.shutdown();

        return Get_url;
    }


    /**
     * UI界面
     */
    @Override
    public String getTabCaption() {
        return "SSRF-Auto";
    }

    @Override
    public JComponent getUiComponent() {
        // Create the custom Swing UI with JSplitPane
        panel = new JPanel(new BorderLayout());
        rightPanel = new JPanel(new GridBagLayout());

/**
 * 返回ceye的接口数据
 */
        tableModel = new MyTableModel();
        table = new JTable(tableModel);
        table.setRowHeight(30);

        JScrollPane scrollPane = new JScrollPane(table);
        panel.add(scrollPane, BorderLayout.CENTER);

        /**
         * 设置config配置,正则不会匹配到邮箱
         */
        textField1 = new JTextField("ceye的dnslog", 30);
        textField2 = new JTextField("\\b((?:\\d{1,3}\\.){3}\\d{1,3}\\b)|(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\\.)+[a-zA-Z]{2,6}\\b", 30);
        textField3 = new JTextField("ceye拉取dns接口", 30);
        JLabel label1 = new JLabel("ceye-DNSLog：");
        JLabel label2 = new JLabel("Regular rule：");
        JLabel label3 = new JLabel("ceye-api：");
        rightPanel.setPreferredSize(new Dimension(400, 100));
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.insets = new Insets(10, 10, 10, 10); // 设置组件之间的间距

        constraints.gridx = 0;
        constraints.gridy = 0;
        rightPanel.add(label1, constraints);

        constraints.gridx = 1;
        constraints.gridy = 0;
        rightPanel.add(textField1, constraints);

        constraints.gridx = 0;
        constraints.gridy = 1;
        rightPanel.add(label2, constraints);

        constraints.gridx = 1;
        constraints.gridy = 1;
        rightPanel.add(textField2, constraints);

        constraints.gridx = 0;
        constraints.gridy = 2;
        rightPanel.add(label3, constraints);

        constraints.gridx = 1;
        constraints.gridy = 2;
        rightPanel.add(textField3, constraints);

        constraints.gridx = 0;
        constraints.gridy = -3;

        customButton = new JButton("Refresh ceye-data");
        String webhook = textField3.getText();
        customButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 用户点击按钮时执行自定义方法
                try {
                    DNSLog dnsLog = new DNSLog();
                    dnsLog.DNSLog(tableModel, dataList, list, callbacks,webhook);
                } catch (Throwable th) {
                    System.out.println("Refresh ceye-datath: " + th);
                }
            }
        });

        rightPanel.add(customButton, constraints);

        clearButton = new JButton(" Clear ceye-data ");
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 用户点击按钮时执行自定义方法
                try {
                    dataList.clear();
                    list.clear();
                    tableModel.fireTableDataChanged();
                } catch (Throwable th) {
                    System.out.println("th: " + th);
                }
            }
        });
        constraints.gridx = 0;
        constraints.gridy = -3;
        rightPanel.add(clearButton, constraints);

        // 创建一个开关按钮
        JToggleButton toggleButton = new JToggleButton(" Disable ");
        toggleButton.setSelected(isButtonEnabled);
        toggleButton.addItemListener(e -> {
            isButtonEnabled = toggleButton.isSelected();
            toggleButton.setText(isButtonEnabled ? "Enable" : "Disable");
        });
        constraints.gridx = 0;
        constraints.gridy = -4;
        rightPanel.add(toggleButton, constraints);
        /**
         * 分割
         */
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, panel, rightPanel);
        // 设置分隔条大小
        splitPane.setDividerSize(7);
        // 设置分隔条位置
        splitPane.setDividerLocation(850);
        // 允许连续拖动
        splitPane.setContinuousLayout(true);
        // 设置分隔条可拖动
        splitPane.setOneTouchExpandable(true);

        return splitPane;

    }

    public class MyTableModel extends AbstractTableModel {

        private String[] columns = {"ID", "Name", "Remote Addr", "Create At"};


        public void addData(String[] row) throws IOException {
            dataList.add(new MyData(row[0], row[1], row[2], row[3]));
            if (!list.contains(row[0])) {
                list.add(row[0]);
                tableModel.fireTableDataChanged();
            }

        }

        @Override
        public int getRowCount() {
            return dataList.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            MyData data = dataList.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return data.getId();
                case 1:
                    return data.getName();
                case 2:
                    return data.getRemoteAddr();
                case 3:
                    return data.getCreateAt();
                default:
                    return null;
            }
        }


        @Override
        public String getColumnName(int column) {
            return columns[column];
        }
    }

    class MyData extends MyTableModel {
        private String id;
        private String name;
        private String remoteAddr;
        private String createAt;

        public MyData(String id, String name, String remoteAddr, String createAt) {
            this.id = id;
            this.name = name;
            this.remoteAddr = remoteAddr;
            this.createAt = createAt;
        }

        public String getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public String getRemoteAddr() {
            return remoteAddr;
        }

        public String getCreateAt() {
            return createAt;
        }

    }

}
