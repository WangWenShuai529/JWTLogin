[官方学习文档](https://jwt.io/introduction)

# 简介

## 什么是 JSON Web 令牌？

**JSON Web Token （JWT） 是一种开放标准 （RFC 7519），它定义了一种紧凑且独立的方式，用于将信息作为 JSON 对象在各方之间安全地传输。此信息可以进行验证和信任，因为它是经过数字签名的。JWT 可以使用密钥（使用 HMAC 算法）或使用 RSA 或 ECDSA 的公钥/私钥对进行签名。**
虽然 JWT 可以加密以在各方之间提供保密性，但我们将重点介绍已签名的令牌。签名令牌可以验证其中包含的声明的完整性，而加密令牌可以向其他方隐藏这些声明。当使用公钥/私钥对对令牌进行签名时，签名还证明只有持有私钥的一方是签名者。**

## 何时应使用 JSON Web 令牌？

以下是 JSON Web 令牌有用的一些方案：

- 授权：这是使用 JWT 的最常见方案。用户登录后，每个后续请求都将包含 JWT，允许用户访问该令牌允许的路由、服务和资源。单点登录是当今广泛使用 JWT 的一项功能，因为它的开销很小，并且能够跨不同域轻松使用。
- 信息交换：JSON Web令牌是在各方之间安全传输信息的好方法。由于 JWT 可以签名（例如，使用公钥/私钥对），因此您可以确定发送方就是他们所说的人。此外，由于签名是使用标头和有效负载计算的，因此您还可以验证内容是否未被篡改。

# 原理

## 什么是 JSON Web 令牌结构？

在其紧凑的形式中，JSON Web令牌由三个部分组成，由点（）分隔，它们是：.
xxxx.yyyy.zzz

- 页眉
- 有效载荷
- 签名
  因此，JWT 通常如下所示。

xxxxx.yyyyy.zzzzz

让我们分解不同的部分。

### 页眉

标头通常由两部分组成：令牌的类型（即 JWT）和正在使用的签名算法（如 HMAC SHA256 或 RSA）。

例如：

{
  "alg": "HS256",
  "typ": "JWT"
}
然后，这个 JSON 是 Base64Url 编码，以形成 JWT 的第一部分。

### 有效载荷

令牌的第二部分是有效负载，其中包含声明。声明是关于实体（通常是用户）和其他数据的语句。有三种类型的声明：注册声明、公共声明和私人声明。

注册声明：这些是一组预定义的声明，这些声明不是必需的，但建议提供一组有用的、可互操作的声明。其中一些是：iss（发行人），exp（到期时间），子（主题），aud（受众）等。

请注意，声明名称的长度只有三个字符，因为 JWT 应该是紧凑的。

公共声明：这些可以由使用JWT的人随意定义。但为避免冲突，应在 IANA JSON Web 令牌注册表中定义它们，或将其定义为包含抗冲突命名空间的 URI。

私人声明：这些是为在同意使用它们的各方之间共享信息而创建的自定义声明，既不是注册声明也不是公开声明。

示例有效负载可以是：

{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
然后对有效负载进行 Base64Url 编码，以形成 JSON Web 令牌的第二部分。

请注意，对于已签名的令牌，此信息虽然受到保护以防止篡改，但任何人都可以读取。不要将机密信息放在 JWT 的有效负载或标头元素中，除非它已加密。

### 签名

要创建签名部分，您必须获取编码的标头、编码的有效负载、机密、标头中指定的算法，并对其进行签名。

例如，如果要使用 HMAC SHA256 算法，将按以下方式创建签名：

HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
签名用于验证消息在此过程中未发生更改，并且，对于使用私钥签名的令牌，它还可以验证 JWT 的发送者是否是它所说的发件人。

将所有内容放在一起
输出是三个 Base64-URL 字符串，由点分隔，可以在 HTML 和 HTTP 环境中轻松传递，同时与基于 XML 的标准（如 SAML）相比更紧凑。

下面显示了一个 JWT，它具有编码的先前标头和有效负载，并使用密钥对其进行签名。编码的 JWT

如果要使用 JWT 并将这些概念付诸实践，可以使用 jwt.io 调试器来解码、验证和生成 JWT。

JWT.io 调试器
![在这里插入图片描述](https://img-blog.csdnimg.cn/5339f2f355924ac0949cfd98e25d4bfc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5rGq56iL5bqP54y_,size_20,color_FFFFFF,t_70,g_se,x_16)

## JSON Web 令牌如何工作？

在身份验证中，当用户使用其凭据成功登录时，将返回 JSON Web 令牌。由于令牌是凭据，因此必须非常小心地防止安全问题。**通常，保留令牌的时间不应超过所需的时间。**

由于缺乏安全性，您也不应将敏感会话数据存储在浏览器存储中。

每当用户想要访问受保护的路由或资源时，用户代理都应发送 JWT，通常在授权标头中使用持有者架构。标头的内容应如下所示：

Authorization: Bearer <token>
在某些情况下，这可能是一种无状态的授权机制。服务器的受保护路由将在标头中检查有效的 JWT，如果存在，将允许用户访问受保护的资源。如果 JWT 包含必要的数据，则可能会减少查询数据库以进行某些操作的需要，尽管情况可能并非总是如此。Authorization

请注意，如果通过 HTTP 标头发送 JWT 令牌，则应尝试防止它们变得太大。某些服务器不接受标头中超过 8 KB 的容量。如果您尝试在 JWT 令牌中嵌入太多信息（例如通过包含所有用户的权限），则可能需要替代解决方案，如 Auth0 细粒度授权。

如果令牌在标头中发送，则跨源资源共享 （CORS） 不会成为问题，因为它不使用 Cookie。Authorization

下图显示了如何获取 JWT 并用于访问 API 或资源：

## JSON 网络令牌如何工作

应用程序或客户端请求对授权服务器进行授权。这是通过不同的授权流之一执行的。例如，典型的 OpenID Connect 兼容 Web 应用程序将使用授权代码流通过终结点。/oauth/authorize
授予授权后，授权服务器将向应用程序返回访问令牌。
应用程序使用访问令牌访问受保护的资源（如 API）。
请注意，对于已签名的令牌，令牌中包含的所有信息都会向用户或其他方公开，即使他们无法更改它。这意味着您不应将机密信息放在令牌中。

## 我们为什么要使用 JSON Web 令牌？

让我们来谈谈 JSON Web 令牌 （JWT） 与简单 Web 令牌 （SWT） 和安全断言标记语言令牌 （SAML） 相比的优势。

由于JSON不如XML详细，因此当它被编码时，它的大小也更小，这使得JWT比SAML更紧凑。这使得 JWT 成为在 HTML 和 HTTP 环境中传递的不错选择。

在安全方面，SWT 只能由使用 HMAC 算法的共享密钥进行对称签名。但是，JWT 和 SAML 令牌可以使用 X.509 证书形式的公钥/私钥对进行签名。与对 JSON 进行签名的简单性相比，使用 XML 进行签名 数字签名而不引入晦涩的安全漏洞是非常困难的。

JSON解析器在大多数编程语言中都很常见，因为它们直接映射到对象。相反，XML 没有自然的文档到对象映射。这使得使用 JWT 比 SAML 断言更容易。

关于使用，智威汤逊以互联网规模使用。这突出了在多个平台（尤其是移动设备）上处理 JSON Web 令牌的客户端的易用性。

比较编码的 JWT 和编码的 SAML 的长度 编码的 JWT 和编码的 SAML 的长度比较



# 实现

## 项目结构

![](https://img-blog.csdnimg.cn/491c11fe40b045b9ab78bd64e691371a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5rGq56iL5bqP54y_,size_20,color_FFFFFF,t_70,g_se,x_16)

## 配置文件

这里我的数据库为3300端口。

```
server.port=8989
spring.application.name=jwt

spring.datasource.type=com.alibaba.druid.pool.DruidDataSource
spring.datasource.driver-class-name=com.mysql.jdbc.Driver
spring.datasource.url=jdbc:mysql://127.0.0.1:3300/test?useUnicode=true&characterEncoding=utf8&useSSL=true&serverTimezone=UTC&useSSL=false
spring.datasource.username=root
spring.datasource.password=root

mybatis.type-aliases-package=com.chilly.entity
mybatis.mapper-locations=classpath:com/chilly/mapper/*.xml

logging.level.com.chilly.dao=debug

```

## 传统放入session中

```java
package com.chilly.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by on 2020/9/9.
 */
@RestController
public class HelloController {

    @RequestMapping("/test/test")
    public String test(String username, HttpServletRequest request) {

        //认证成功，放入session
        request.getSession().setAttribute("username",username);
        return "login ok";
    }

}

```

![在这里插入图片描述](https://img-blog.csdnimg.cn/b8121732772a473a9b556dfcffa985fe.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5rGq56iL5bqP54y_,size_20,color_FFFFFF,t_70,g_se,x_16)

## JWT

![在这里插入图片描述](https://img-blog.csdnimg.cn/7d4485c78ef34580b7d3df5fb6f4ba7a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5rGq56iL5bqP54y_,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/796599b7fbef46b8a7ca5f4bed1a9882.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5rGq56iL5bqP54y_,size_20,color_FFFFFF,t_70,g_se,x_16)
核心代码

```java
package com.chilly.controller;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.chilly.entity.User;
import com.chilly.service.UserService;
import com.chilly.utils.JWTUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by 
 */
@RestController
@Slf4j
public class UserController {

    @Resource
    private UserService userService;

    @GetMapping("/user/login")
    public Map<String, Object> login(User user) {
        log.info("用户名：{}", user.getName());
        log.info("password: {}", user.getPassword());

        Map<String, Object> map = new HashMap<>();

        try {
            User userDB = userService.login(user);

            Map<String, String> payload = new HashMap<>();
            payload.put("id", userDB.getId());
            payload.put("name", userDB.getName());
            String token = JWTUtils.getToken(payload);

            map.put("state", true);
            map.put("msg", "登录成功");
            map.put("token", token);
            return map;
        } catch (Exception e) {
            e.printStackTrace();
            map.put("state", false);
            map.put("msg", e.getMessage());
            map.put("token", "");
        }
        return map;
    }

    @PostMapping("/user/test")
    public Map<String, Object> test(HttpServletRequest request) {
        String token = request.getHeader("token");
        DecodedJWT verify = JWTUtils.verify(token);
        String id = verify.getClaim("id").asString();
        String name = verify.getClaim("name").asString();
        log.info("用户id：{}", id);
        log.info("用户名: {}", name);

        //TODO 业务逻辑
        Map<String, Object> map = new HashMap<>();
        map.put("state", true);
        map.put("msg", "请求成功");
        return map;
    }

}

```

```java
package com.chilly.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Map;

/**
 * Created by
 */
public class JWTUtils {
//    这个是密钥，一定不能让别人知道
    private static String SECRET = "token!Q@W#E$R";

    /**
     * 生产token
     */
    public static String getToken(Map<String, String> map) {
        JWTCreator.Builder builder = JWT.create();

        //payload
        map.forEach((k, v) -> {
            builder.withClaim(k, v);
        });

        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.DATE, 7); //默认7天过期

        builder.withExpiresAt(instance.getTime());//指定令牌的过期时间
        String token = builder.sign(Algorithm.HMAC256(SECRET));//签名
        return token;
    }

    /**
     * 验证token
     */
    public static DecodedJWT verify(String token) {
        //如果有任何验证异常，此处都会抛出异常
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256(SECRET)).build().verify(token);
        return decodedJWT;
    }

//    /**
//     * 获取token中的 payload
//     */
//    public static DecodedJWT getToken(String token) {
//        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256(SECRET)).build().verify(token);
//        return decodedJWT;
//    }
}

```

```java
package com.chilly.config;

import com.chilly.interceptors.JWTInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Created by
 */
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new JWTInterceptor())
//                进行拦截，一般登录不拦截，企业都拦截
                .addPathPatterns("/user/**")
                .excludePathPatterns("/user/login")
        ;
    }
}

```

```java
package com.chilly.interceptors;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.chilly.utils.JWTUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by
 */
@Slf4j
public class JWTInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {

        //获取请求头中的令牌
        String token = request.getHeader("token");
        log.info("当前token为：{}", token);

        Map<String, Object> map = new HashMap<>();
        try {
            JWTUtils.verify(token);
            return true;
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            map.put("msg", "签名不一致");
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            map.put("msg", "令牌过期");
        } catch (AlgorithmMismatchException e) {
            e.printStackTrace();
            map.put("msg", "算法不匹配");
        } catch (InvalidClaimException e) {
            e.printStackTrace();
            map.put("msg", "失效的payload");
        } catch (Exception e) {
            e.printStackTrace();
            map.put("msg", "token无效");
        }

        map.put("state", false);

        //响应到前台: 将map转为json
        String json = new ObjectMapper().writeValueAsString(map);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().println(json);
        return false;
    }
}

```

# 总结

### JWT原理

服务器认证以后会生产一个json对象，服务器完全只靠这个json对象校验用户身份，
为了防止json串被篡改，服务器在生成这个json对象时会进行签名

也就是说服务器端不保存这个数据，每次客户端请求时需要带着这个json对象

#### JWT数据结构

形如 xxxx.yyy.zzz 由三部分组成，每部分用英文句号连接

JWT的三个部分：
header 头部
payload 负载
signature 签名

也就是 Header.Payload.Signature

##### 1、Header 头部

是一个JSON 对象, 描述JWT的元数据，形如：
{"alg": "HS256", "typ": "JWT"}

alg属性表示签名的算法（algorithm）,默认是 HMAC SHA256

typ属性表示这个令牌的类型（type）,JWT 令牌统一写为JWT

##### 2、payload 负载

是一个JSON 对象, 用来存放实际需要传递的数据，形如：
{"sub": "1234567890", "name": "John Doe","admin": true}

一般是在这个部分定义私有字段：
例如{"userId":"1","userName":"jack"}

其中payload官方规定了7个字段：

iss (issuer)：签发人

exp (expiration time)：过期时间

sub (subject)：主题

aud (audience)：受众

nbf (Not Before)：生效时间

iat (Issued At)：签发时间

jti (JWT ID)：编号

注意，JWT 默认是不加密的，任何人都可以读到，所以不要把机密信息放在这个部分。

##### 3、signature 签名

signature 是对前两部分的签名，防止数据篡改

1、需要指定一个密钥（secret）
2、这个密钥只有服务器才知道，不能泄露给客户端
3、使用 Header 里面指定的签名算法，按照下面的公式产生签名。
    

```
`HMACSHA256(
   base64UrlEncode(header) + "." +
   base64UrlEncode(payload),
   secret
 )`
```

也就是signature等于上面公式算出来的

把 Header、Payload、Signature 三个部分拼成一个字符串: xxxx.yyy.zzz

其中base64UrlEncode是串型化算法，处理特殊字符，=被省略、+替换成-，/替换成_

#### JWT 使用方式

客户端收到服务器返回的 JWT，可以储存在 Cookie 里面，也可以储存在 localStorage
以后客户端每次与服务器通信，都要带上这个 JWT

方式1、可以放在 Cookie 里面自动发送，但是这样不能跨域

**方式2、更好的做法是放在 HTTP 请求的头信息Authorization字段里面**

```
Authorization: Bearer <token>
```

方式3、JWT放在POST请求的数据体body里面

#### JWT 的几个特点

（1）JWT 默认是不加密，但也是可以加密的。生成原始 Token 以后，可以用密钥再加密一次。

（2）JWT 不加密的情况下，不能将秘密数据写入 JWT。

（3）JWT 不仅可以用于认证，也可以用于交换信息。有效使用 JWT，可以降低服务器查询数据库的次数。

（4）JWT 的最大缺点是，由于服务器不保存 session 状态，因此无法在使用过程中废止某个 token，或者更改 token 的权限。也就是说，一旦 JWT 签发了，在到期之前就会始终有效，除非服务器部署额外的逻辑。

（5）JWT 本身包含了认证信息，一旦泄露，任何人都可以获得该令牌的所有权限。为了减少盗用，JWT 的有效期应该设置得比较短。对于一些比较重要的权限，使用时应该再次对用户进行认证。

（6）为了减少盗用，JWT 不应该使用 HTTP 协议明码传输，要使用 HTTPS 协议传输。

# 源码地址

记得给个star！！！
[https://github.com/WangWenShuai529/JWTLogin](https://github.com/WangWenShuai529/JWTLogin)
