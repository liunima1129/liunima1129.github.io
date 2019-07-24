---
layout:     post
title:      Cloudflare Keyless SSL Protocol handshake workflow
subtitle:   Cloudflare keyless SSL协议握手流程
date:       2019-06-10
author:     Olivia Liu
header-img: img/post_img/dark-blue-high-tech-background-header.jpg
catalog: true
tags:
    - SSL
    - TLS
    - keyless
    - OpenSSL
    - handshake
    - protocol
---

## 握手流程

### RSA加密

在SSL协议的基础上，在使用私钥解密客户端发送至nGINX服务器的公钥加密后的pre-master时，服务器将该加密的pre-master发送给存储了私钥的key server，由key server进行解密后将解密完成的pre-master发回nGINX服务器，再进行后续的握手和对称加密流程。



![KeylessRSA](https://raw.githubusercontent.com/liunima1129/liunima1129.github.io/master/img/post_img/keylessRSA.png)



### Diffie-Hellman加密

在SSL协议的基础上，在收到客户端发送至nGINX服务器的ClientHello后，服务器将接收到的client random，自己生成的server random和server DH parameter的哈希值发送给key server，key server把两个随机数和公钥使用存储在本地的私钥签名后发回服务器，服务器再把这些签名后的数据以ServerExchange发送给客户端，完成这些步骤后服务器才可以给客户端发送ServerHelloDone。



![KeylessDH](https://raw.githubusercontent.com/liunima1129/liunima1129.github.io/master/img/post_img/keylessDH.png)





 
