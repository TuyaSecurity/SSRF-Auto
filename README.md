## By: 涂鸦安全实验室-文鸯

### 使用方法
- 日志（增加了替换数据包的日志展示）

![image](https://github.com/TuyaSecurity/SSRF-Auto/assets/59638836/8c3f9a66-0ad1-4a5f-888e-5978ff1aecf2)

- 过滤（增加了Url和domain的过滤）

![image](https://github.com/TuyaSecurity/SSRF-Auto/assets/59638836/b9795460-51b4-4f9a-98c3-0a9a5ba0d2aa)

- 返回结果
![image](https://github.com/TuyaSecurity/SSRF-Auto/assets/59638836/d5ba0154-c4af-4437-ab26-1bc0c4b3bd2b)
这里是从burp的dns拉取到的数据，这里时间就不处理了大家自己➕8就好😂
**但是这里有个小问题，burp传给我的queryValue数据base64后会有乱码问题，换了其他编码也还是乱码，这个是我通过字符串加工出来的数据，有时重复的内容会有空白出现，不会有什么影响。**

> ![image](https://github.com/TuyaSecurity/SSRF-Auto/assets/59638836/09a68355-6e20-4523-856e-5533ef3fa08c)异步做的请求，对于存在ssrf问题的地方，会在http history中红色高亮显示

>![image](https://github.com/TuyaSecurity/SSRF-Auto/assets/59638836/d73d48ad-1fb8-4093-8f10-f0f4db4bda43)会在burp extensions功能出会展示每一次从burp申请的paylaod


# 免责声明
- 本工具仅面向合法授权的企业安全建设行为，如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。
- 本产品仅限于合法的安全测试和研究用途，禁止用于非法入侵和攻击，一旦发现使用者有违法行为，本产品将立即停止服务并向有关部门报告。
- 仅提供技术，不对任何该产品造成任何理论上的或实际上的损失承担责任。
- 使用本产品即表示您已经完全理解、认可并接受本免责声明中的所有条款和内容，如有任何问题请及时联系我们。
  
**在安装并使用本产品前，请您 务必审慎阅读、充分理解以上各条款内容。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本产品。 您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。**
