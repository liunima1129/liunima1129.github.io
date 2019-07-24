# OpenSSL Shell文件代码介绍

---
title: OpenSSL Shell File Introduction
subtitle:OpenSSL Shell文件代码介绍
date: 2019-06-13
author: Olivia Liu
catalog: true
tags:
    - keyless
    - OpenSSL
   
---

## gen.sh 文件代码解释

##### 生成自签名证书(.pem)：

```shell
#生成RSA私钥和自签名证书，使用openssl-ca.cnf文件来配置生成的x509证书，证书私钥为4096位RSA加密，证书摘要采用SHA256哈希算法，-nodes不加密，-outform指定证书格式为.pem格式，证书名为cacert.pem
openssl req -x509 -config openssl-ca.cnf -newkey rsa:4096 -sha256 -nodes -out cacert.pem -outform PEM
#打印证书内容，-text使用文本方式详细打印出该证书的所有细节，-noout不打印出请求的编码版本信息
openssl x509 -in cacert.pem -text -noout
#-purpose打印出证书附加项里所有有关用途允许和用途禁止的内容，-inform用于定义证书格式
openssl x509 -purpose -in cacert.pem -inform PEM
```

##### 生成服务器端证书申请文件(.csr)：

```shell
#生成RSA私钥和服务器端证书，使用openssl-server.cnf文件来配置生成的证书，证书私钥为2048位RSA加密，证书摘要采用SHA256算法，-nodes不加密，证书输出格式为.pem格式 
openssl req -config openssl-server.cnf -newkey rsa:2048 -sha256 -nodes -out servercert.csr -outform PEM
#校验证书请求文件servercert.csr
openssl req -text -noout -verify -in servercert.csr
```

##### 使用CA证书签名：

```shell
#使用openssl-ca.cnf文件进行配置，-policy指定签名规则使signing_policy, -infiles指明被处理的(可为多个)证书请求文件servercert.csr, -extensions添加扩展信息字段signing_req, 如果不添加则生成v1格式的证书，生成的签名证书文件为servercert.pem
openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out servercert.pem -infiles servercert.csr
#打印服务器端证书servercert.pem内容
openssl x509 -in servercert.pem -text -noout
```

##### 生成客户端证书

```shell
#生成RSA私钥和客户端证书请求文件clientcert.csr，使用openssl-client.cnf文件进行配置，证书私钥为2048位RSA加密，证书摘要使用SHA256算法，-nodes不加密，证书输出格式为.pem格式
openssl req -config openssl-client.cnf -newkey rsa:2048 -sha256 -nodes -out clientcert.csr -outform PEM
#校验证书请求文件clientcert.csr
openssl req -text -noout -verify -in clientcert.csr
#为客户端证书签名，输出证书文件为clientcert.pem, -infiles指定证书请求文件clientcert.csr, 使用openssl-ca.cnf文件进行配置，-policy指定签名规则使signing_policy, -extensions添加扩展信息字段signing_req
openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out 
clientcert.pem -infiles clientcert.csr
#打印客户端证书clientcert.pem内容
openssl x509 -in clientcert.pem -text -noout
```

##### 生成客户端ECDSA证书：

```shell
#生成ECDSA私钥和客户端ecdsa证书请求文件，私钥使用ecparam -name指定secp384r1算法
openssl req -config openssl-client-ec.cnf -newkey ec:<(openssl ecparam -name secp384r1) -sha256 -nodes -out client_eccert.csr -outform PEM
#校验证书请求文件client_eccert.csr
openssl req -text -noout -verify -in client_eccert.csr
#为客户端证书签名
openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req client_eccert.pem -infiles client_eccert.csr
#打印客户端证书内容
openssl x509 -in client_eccert.pem -text -noout
```

##### 输出公钥文件(.pubkey)

```shell
#rsa指定密钥类型为RSA加密密钥，-in指定待处理密钥文件rsa.key, -pubout输出公钥文件rsa.pubkey
openssl rsa -in rsa.key -pubout -out rsa.pubkey
#ec指定密钥类型为ECDSA加密密钥，-in指定待处理密钥文件rsa.key, -pubout输出公钥文件rsa.pubkey
openssl ec -in ec.key -pubout -out ec.pubkey
```






















