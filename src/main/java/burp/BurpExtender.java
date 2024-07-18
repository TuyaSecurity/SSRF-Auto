package burp;

import org.apache.commons.lang3.StringUtils;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.border.LineBorder;

//要使用这个文件中的代码，需要先将文件名改为BurpExtender.java
public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private IBurpExtenderCallbacks callbacks;
    private JSplitPane mainPanel;
    private IBurpCollaboratorClientContext collaboratorContext;
    private String payload;
    private List<MyData> dataList = new ArrayList<MyData>();
    private List<Integer> idList = new ArrayList<Integer>();
    private MyTableModel tableModel;
    private JTable table;
    private boolean isButtonEnabled = true;
    private List<IBurpCollaboratorInteraction> resultList = new ArrayList<IBurpCollaboratorInteraction>();
    private int id = 0;
    private ITextEditor textEditor;
    Tools tools = new Tools();
    private static final Pattern REGEX_PATTERN = Pattern.compile("\\b((?:\\d{1,3}\\.){3}\\d{1,3}\\b)|(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\\.)+[a-zA-Z]{2,6}\\b");
    private static final Pattern WORD_RE_PATTERN = Pattern.compile("[a-zA-Z0-9]+");
    public List<String> logRequestList = new ArrayList<String>();
    final static Base64.Decoder decoder = Base64.getDecoder();
    private JList IFList;
    private List<String> filterList = new ArrayList<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        // 生成一个负载
        this.payload = collaboratorContext.generatePayload(true);
        callbacks.printOutput("Generated payload: " + payload);
        // 注册监听器
        callbacks.registerHttpListener(this);
        // 设置插件的名称
        callbacks.setExtensionName("SSRF-Auto");
        textEditor = callbacks.createTextEditor();
        textEditor.setEditable(true);
        // 创建 UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // 创建左侧面板
                JPanel leftPanel = new JPanel(new BorderLayout());
                tableModel = new MyTableModel();
                table = new JTable(tableModel);
                table.setRowHeight(30);
                table.setAutoCreateRowSorter(true);//设置表格排序
                int tableWidth = table.getWidth();
                table.getColumn("ID").setPreferredWidth((int) (tableWidth * 0.1));
                table.getColumn("RemoteIP").setPreferredWidth((int) (tableWidth * 0.2));
                table.getColumn("QueryValue").setPreferredWidth((int) (tableWidth * 0.5));
                table.getColumn("TimeStamp").setPreferredWidth((int) (tableWidth * 0.2));
                JScrollPane scrollPane = new JScrollPane(table);
                leftPanel.add(scrollPane, BorderLayout.CENTER);
                // 创建右侧上半部分面板1
                JPanel rightTopPanel1 = new JPanel(new GridBagLayout());
                GridBagConstraints constraints = new GridBagConstraints();
                constraints.insets = new Insets(10, 10, 10, 10); // 设置组件之间的间距
                rightTopPanel1.setPreferredSize(new Dimension(50, 50));
                // 创建一个开关按钮
                JToggleButton toggleButton = new JToggleButton(" Enable ");
                toggleButton.setSelected(isButtonEnabled);
                toggleButton.addItemListener(e -> {
                    isButtonEnabled = toggleButton.isSelected();
                    toggleButton.setText(isButtonEnabled ? "Enable" : "Disable");
                });
                constraints.gridx = 0;
                constraints.gridy = 0;
                rightTopPanel1.add(toggleButton, constraints);

                // 创建右侧下半部分面板1
                JPanel rightBottomPanel1 = new JPanel();
                JLabel IFLType = new JLabel("Type:");
                IFLType.setBounds(10, 10, 140, 30);
                List<String> filterTypeList = List.of("Domain filter: (Example: tuya.com、go.tuya.com)", "URL filter: (Example: tuya.com/test/payload)");

                JComboBox<String> filterType = new JComboBox<>();
                filterType.setBounds(80, 10, 350, 30);
                filterTypeList.forEach(filterType::addItem);

                JLabel IFLContent = new JLabel("Content:");
                IFLContent.setBounds(10, 50, 140, 30);
                JTextArea IFText = new JTextArea("", 5, 30);
                JScrollPane scrollIFText = new JScrollPane(IFText);
                scrollIFText.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                scrollIFText.setBounds(80, 50, 300, 110);

                JLabel IFLabelList = new JLabel("Filter List:");
                IFLabelList.setBounds(10, 165, 140, 30);
                DefaultListModel IFModel = new DefaultListModel();
                IFList = new JList(IFModel);
                JScrollPane scrollIFList = new JScrollPane(IFList);
                scrollIFList.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                scrollIFList.setBounds(80, 175, 300, 110);
                scrollIFList.setBorder(new LineBorder(Color.BLACK));

                IFModel.addElement("Domain filter: google.com");
                IFModel.addElement("Domain filter: baidu.com");
                IFModel.addElement("Domain filter: csdn.com");
                IFModel.addElement("Domain filter: gov.cn");
                IFModel.addElement("Domain filter: github.com");
                IFModel.addElement("Domain filter: gitlab.com");
                for (int i = 0; i < IFList.getModel().getSize(); i++) {
                    filterList.add((String) IFList.getModel().getElementAt(i));
                }

                JButton IFAdd = new JButton("Add filter");
                IFAdd.setBounds(390, 85, 120, 30);
                IFAdd.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        addFilterHelper(filterType, IFModel, IFText);
                    }
                });
                JButton IFDel = new JButton("Remove filter");
                IFDel.setBounds(390, 210, 120, 30);
                IFDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        delFilterHelper(IFList);
                    }
                });

                rightBottomPanel1.setLayout(null);
                rightBottomPanel1.setBounds(0, 0, 1000, 1000);
                rightBottomPanel1.add(IFLType);
                rightBottomPanel1.add(filterType);
                rightBottomPanel1.add(IFLContent);
                rightBottomPanel1.add(scrollIFText);
                rightBottomPanel1.add(IFAdd);
                rightBottomPanel1.add(IFDel);
                rightBottomPanel1.add(IFLabelList);
                rightBottomPanel1.add(scrollIFList);

                // 用JSplitPane将右侧上下部分面板1分开
                JSplitPane rightSplitPane1 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, rightTopPanel1, rightBottomPanel1);

                // 使用JTabbedPane将右侧面板分成两个tab
                JTabbedPane rightTabbedPane = new JTabbedPane();
                rightTabbedPane.addTab("Configuration", rightSplitPane1);
                rightTabbedPane.addTab("ReplaceRequestLog", textEditor.getComponent());

                // 使用JSplitPane将主面板分开
                mainPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightTabbedPane);

                // 将主面板添加到 Burp 的 UI
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    // 以下两个方法是 ITab 接口的一部分，用于定义选项卡的名称和组件
    @Override
    public String getTabCaption() {
        return "SSRF-Auto";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public void processHttpMessage(int i, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest && isButtonEnabled) {
            // 获取请求数据包
            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
            URL url = requestInfo.getUrl();
            if (!whiteListJudge(url.getHost())
                    && !StringUtils.equals(requestInfo.getMethod().toLowerCase(), "options")
                    && !whiteUrlListJudge(url.toString())) {
                String path = url.getPath();
                if (StringUtils.equals(requestInfo.getMethod().toLowerCase(), "get")
                        && StringUtils.isNotEmpty(requestInfo.getUrl().getQuery())
                        && !path.endsWith(".js")
                        && !path.endsWith(".png")
                        && !path.endsWith(".gif")
                        && !path.endsWith(".jpg")) {
                    getReplaceContent(requestInfo, messageInfo);

                } else if (!StringUtils.equals(requestInfo.getMethod().toLowerCase(), "get") && requestInfo.getBodyOffset() != -1) {
                    String request = new String(messageInfo.getRequest(), StandardCharsets.UTF_8);
                    String requestBody = request.substring(requestInfo.getBodyOffset());
                    //防止多个请求包过大导致burp挂掉
                    if (requestBody.length() <= 0.5 * 1024 * 1024) {
                        otherReplaceContent(requestBody, requestInfo, messageInfo);
                    }
                }
            }
        }
    }

    public boolean whiteListJudge(String host) {
        return filterList.stream()
                .filter(filter -> !StringUtils.equals(StringUtils.substringBefore(filter, ":").strip(),"Domain filter"))
                .anyMatch(str -> StringUtils.indexOf(host, StringUtils.substringAfterLast(str,":")) > -1);
    }

    public boolean whiteUrlListJudge(String url) {
        return filterList.stream()
                .filter(filter -> !StringUtils.equals(StringUtils.substringBefore(filter, ":").strip(),"URL filter"))
                .anyMatch(str -> StringUtils.indexOf(url, StringUtils.substringAfterLast(str,":")) > -1);
    }

    public class MyTableModel extends AbstractTableModel {

        private String[] columns = {"ID", "RemoteIP", "QueryValue", "TimeStamp"};

        public void addData(int id, String[] row) throws IOException {
            if (!idList.contains(id)) {
                synchronized(dataList) {
                    dataList.add(new MyData(id, row[0], row[1], row[2]));
                }
                idList.add(id);
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
                    return data.getReomteIp();
                case 2:
                    return data.getQueryValue();
                case 3:
                    return data.getTime_stamp();
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            switch (column) {
                case 0:
                    return Integer.class; // 例如，第一列是字符串
                case 1:
                    return String.class; // 第二列是整数
                case 2:
                    return String.class; // 第二列是整数
                case 4:
                    return String.class; // 第二列是整数
                default:
                    return super.getColumnClass(column);
            }
        }
    }

    class MyData extends MyTableModel {
        private int id;
        private String reomteIp;
        private String time_stamp;
        private String queryValue;

        public MyData(int id, String reomteIp, String queryValue, String time_stamp) {
            this.id = id;
            this.reomteIp = reomteIp;
            this.time_stamp = time_stamp;
            this.queryValue = queryValue;
        }

        public int getId() {
            return id;
        }

        public String getReomteIp() {
            return reomteIp;
        }

        public String getTime_stamp() {
            return time_stamp;
        }

        public String getQueryValue() {
            return queryValue;
        }
    }

    /**
     * get类型请求做处理
     *
     * @param requestInfo
     * @param messageInfo
     * @return
     */
    public String getReplaceContent(IRequestInfo requestInfo, IHttpRequestResponse messageInfo) {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        URL url = requestInfo.getUrl();
        String input = callbacks.getHelpers().urlDecode(url.getQuery());
        String method = requestInfo.getMethod().toLowerCase();
        String path = url.getPath().replace('/', '.');
        path = StringUtils.removeEnd(path, ".");
        String host = url.getHost();
        String replacement = method + '.' + host + path + '.' + payload;
        Matcher matcher = REGEX_PATTERN.matcher(input);
        boolean isFound = false;
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            isFound = true;
            //这个地方是为了解决邮箱误报的问题
            if (matcher.start() > 0 && input.charAt(matcher.start() - 1) == '@') {
                matcher.appendReplacement(sb, matcher.group());
            } else {
                matcher.appendReplacement(sb, replacement);
            }
        }
        if (!isFound) {
            return url.toString(); // if no match found, return url.toString()
        }
        matcher.appendTail(sb);
        String getUrl = tools.replaceAfterQuestionMark(url.toString(), sb.toString());
        // 异步发送一个get请求
        Runnable task = () -> {
            try {
                tools.HTTP_request(requestInfo, getUrl, callbacks, textEditor, logRequestList);
                //去拉取burp的dns返回接口拉取结果并处理
                try {
                    resultList = collaboratorContext.fetchCollaboratorInteractionsFor(payload);
                    if (!resultList.isEmpty()) {
                        for (IBurpCollaboratorInteraction item : resultList) {
                            id++;
                            String[] rowData = new String[3];
                            rowData[0] = item.getProperty("client_ip");
                            String rawQuery = new String(decoder.decode(item.getProperty("raw_query")), StandardCharsets.UTF_8);
                            String dnsResult = wordListToString(rawQuery, requestInfo.getMethod());
                            rowData[1] = dnsResult;
                            rowData[2] = item.getProperty("time_stamp");
                            tableModel.addData(id, rowData);
                            if (StringUtils.equals(dnsResult, replacement)) {
                                messageInfo.setHighlight("red");
                            }
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } catch (IOException e) {
                callbacks.printError("Get请求失败：" + getUrl);
            }
        };
        Future<?> future = executorService.submit(task);
        try {
            // 等待异步任务完成，最多等待5秒钟
            future.get(4, TimeUnit.SECONDS);
        } catch (Exception e) {
            // 处理异常
        }
        executorService.shutdown();

        return getUrl;
    }

    /**
     * GET以外的请求做处理
     *
     * @param originalBody
     * @param requestInfo
     * @return
     */
    public String otherReplaceContent(String originalBody, IRequestInfo requestInfo, IHttpRequestResponse messageInfo) {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        URL url = requestInfo.getUrl();
        String path = url.getPath().replace('/', '.');
        path = StringUtils.removeEnd(path, ".");
        String host = url.getHost();
        String method = requestInfo.getMethod().toLowerCase();
        String replacement = method + '.' + host + path + '.' + payload;
        originalBody = callbacks.getHelpers().urlDecode(originalBody);
        Matcher matcher = REGEX_PATTERN.matcher(originalBody);
        StringBuffer sb = new StringBuffer();
        boolean isFound = false;
        while (matcher.find()) {
            isFound = true;
            //解决邮箱误报问题
            if (matcher.start() > 0 && originalBody.charAt(matcher.start() - 1) == '@') {
                matcher.appendReplacement(sb, matcher.group());
            } else {
                matcher.appendReplacement(sb, replacement);
            }
        }
        if (!isFound) {
            return url.toString();
        }
        matcher.appendTail(sb);
        String newBody = sb.toString();
        //异步发送一个post请求
        Runnable task = new Runnable() {
            @Override
            public void run() {
                try {
                    tools.otherRequest(requestInfo, newBody, callbacks, textEditor, logRequestList);
                    //去拉取burp的dns返回接口拉取结果并处理
                    try {
                        resultList = collaboratorContext.fetchCollaboratorInteractionsFor(payload);
                        if (!resultList.isEmpty()) {
                            for (IBurpCollaboratorInteraction item : resultList) {
                                id++;
                                String[] rowData = new String[3];
                                rowData[0] = item.getProperty("client_ip");
                                String rawQuery = new String(decoder.decode(item.getProperty("raw_query")), StandardCharsets.UTF_8);
                                String dnsResult = wordListToString(rawQuery, requestInfo.getMethod());
                                rowData[1] = dnsResult;
                                rowData[2] = item.getProperty("time_stamp");
                                tableModel.addData(id, rowData);
                                if (StringUtils.equals(dnsResult, replacement)) {
                                    messageInfo.setHighlight("red");
                                }
                            }
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
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
        return newBody;
    }

    public String wordListToString(String rawQuery, String method) {
        List<String> wordList = new ArrayList<>();
        Matcher wordMatcher = WORD_RE_PATTERN.matcher(rawQuery);
        while (wordMatcher.find()) {
            wordList.add(wordMatcher.group());
        }
        return stringTrim(StringUtils.join(wordList, '.'), method);
    }

    public String stringTrim(String word, String method) {
        int idxMethod = word.indexOf(method.toLowerCase());
        if (idxMethod != -1) {
            String result = word.substring(idxMethod);
            int idxCom = result.lastIndexOf("com");
            if (idxCom != -1) {
                result = result.substring(0, idxCom + 3);
                return result;
            }
        }
        return null;
    }

    /**
     * 向过滤器列表中添加一个新的过滤器帮助器项，并清空文本输入区。
     * @param filterType 选择过滤器类型的下拉框，从中获取当前选择的过滤器类型名称。
     * @param IFModel 过滤器列表模型，用于在用户界面中显示过滤器项。
     * @param IFText 输入文本区，用户在此输入过滤器的具体条件，添加后将被清空。
     */
    public void addFilterHelper(JComboBox<String> filterType, DefaultListModel<String> IFModel, JTextArea IFText) {
        // 获取当前选中的过滤器类型名称，并处理文本格式
        String typeName = filterType.getSelectedItem().toString().split(":")[0];
        // 将过滤器类型和条件文本组合后添加到模型和过滤器列表中
        IFModel.addElement(typeName + ':' + IFText.getText().strip());
        filterList.add(typeName + ':' + IFText.getText().strip());
        // 清空输入文本区，以便于输入下一个过滤器条件
        IFText.setText("");
    }

    /**
     * 从列表中删除选定的过滤器助手。
     * @param IFList 待操作的JList对象，其中包含过滤器条目。
     */
    public void delFilterHelper(JList IFList) {
        // 获取当前选中的索引
        int index = IFList.getSelectedIndex();
        if (index != -1) { // 检查是否有项被选中
            DefaultListModel<String> model = (DefaultListModel<String>) IFList.getModel();
            model.remove(index); // 从模型中删除选中项
            filterList.remove(index); // 从filterList中删除对应的项
        }
    }
}
