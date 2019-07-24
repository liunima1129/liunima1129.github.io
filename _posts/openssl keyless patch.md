# OpenSSL Keyless patch

---
layout: post
title: OpenSSL Keyless patch
subtitle: OpenSSl keyless 补丁
date: 2019-07-05
author: Olivia Liu
catalog: true
tags:
    - OpenSSL 
    - keyless

---

OpenSSL的源码是将私钥的加解密计算和签名等操作直接在NGINX本地进行，因此如果使用Keyless把这些操作放在key server上进行，则需要对原本的OpenSSL代码进行修改。

## ECDSA 私钥签名

Position: /openssl-1.1.0h/crypto/ec/ec_pmeth.c

```c
static int pkey_ec_sign(EVP_PKEY_CTX *ctx, ...)  //ecdsa私钥签名证书操作从本地移至key server
{
     ...
-    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);  //在本地进行ecdsa签名
+    s = EVP_PKEY_CTX_keyless_get_s(ctx);                   //新建keyless dcdsa私钥签名会话s
+                                                           //在此会话中进行签名
		 ...
}
```

Position: /openssl-1.1.0h/crypto/evp/evp_lib.c

```c
+  void EVP_MD_CTX_keyless_set_s(EVP_MD_CTX *ctx, SSL *s)
+  {
+      ctx->s = s;
+  } //建立keyless会话环境
+
+  SSL *EVP_MD_CTX_keyless_get_s(EVP_MD_CTX *ctx)
+  {
+      return ctx->s;
+  } //返回s
```

Position: /openssl-1.1.0h/crypto/evp/evp_locl.h

```c
struct evp_md_ctx_st {
+    SSL *s; //在evp_md会话中加入keyless成员变量
     const EVP_MD *digest;
     ...
```

Position: /openssl-1.1.0h/crypto/evp/p_sign.c

```c
int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,  //EVP 签名
                  unsigned int *siglen, EVP_PKEY *pkey)
     ...
-    if (EVP_PKEY_sign(pkctx, sigret, &sltmp, m, m_len) <= 0)  //本地签名
+    EVP_PKEY_CTX_keyless_set_s(pkctx, EVP_MD_CTX_keyless_get_s(ctx)); //建立keyless会话
+    int ret = EVP_PKEY_sign(pkctx, sigret, &sltmp, m, m_len); //进行签名，返回ret表示状态
		 ...
```

## RSA私钥解密

Position: /openssl-1.1.0h/crypto/evp/pmeth_lib.c

```c
+ void EVP_PKEY_CTX_keyless_set_s(EVP_PKEY_CTX *ctx, SSL *s)
+ {
+ ctx->s = s;
+ } // 建立keyless私钥解密会话
+
+ SSL *EVP_PKEY_CTX_keyless_get_s(EVP_PKEY_CTX *ctx)
+ {
+ return ctx->s;
+ } // 返回s
```

Position: openssl-1.1.0h/crypto/include/internal/evp_int.h

```c
struct evp_pkey_ctx_st {
+ SSL *s; //添加keyless会话需要使用的成员变量
/* Method associated with this operation */
...
```

Position: /openssl-1.1.0h/crypto/rsa/rsa_pmeth.c

```c
static int pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, ...  
                         //使用rsa加密时key server私钥解密过程
+    SSL *s
     ...
-    ret = RSA_sign(EVP_MD_type(rctx->md),
-                   tbs, tbslen, sig, &sltmp, rsa);
-    if (ret <= 0)
-       return ret;
-    ret = sltmp;  // 删除直接本地私钥解密
+    s = EVP_PKEY_CTX_keyless_get_s(ctx); // 建立keyless会话
		 ...
```

## 函数声明&定义

Position: /openssl-1.1.0h/include/openssl/evp.h

```c
+  void EVP_MD_CTX_keyless_set_s(EVP_MD_CTX *ctx, SSL *s);
+  SSL *EVP_MD_CTX_keyless_get_s(EVP_MD_CTX *ctx);
...
+  void EVP_PKEY_CTX_keyless_set_s(EVP_PKEY_CTX *ctx, SSL *s);
+  SSL *EVP_PKEY_CTX_keyless_get_s(EVP_PKEY_CTX *ctx);
```

Position: /openssl/ssl.h

```c
+void SSL_CTX_set_rsa_sign_cb(SSL_CTX *ctx,
+                             int (*rsa_sign_cb) (struct ssl_st *ssl,
+                                                 int type,
+                                                 const unsigned char *m,
+                                                 unsigned int m_len,
+                                                 unsigned char *sigret,
+                                                 unsigned int *siglen,
+                                                 RSA *rsa));
+void SSL_CTX_set_rsa_private_decrypt_cb(SSL_CTX *ctx,
+                             int (*rsa_private_dectypt_cb) (struct ssl_st *ssl,
+                                                 int flen,
+                                                 const unsigned char *from,
+                                                 unsigned char *to,
+                                                 RSA *rsa,
+                                                 int padding));
+void SSL_CTX_set_ec_sign_cb(SSL_CTX *ctx,
+                             int (*ec_sign_cb) (struct ssl_st *ssl,
+                                                 int type,
+                                                 const unsigned char *dgst,
+                                                 unsigned int dlen,
+                                                 unsigned char *sig,
+                                                 unsigned int *siglen,
+                                                 EC_KEY *eckey));
...
+  # define SSL_PENDING_KEYLESS    8
...
+  # define SSL_want_keyless(s)    (SSL_want(s) == SSL_PENDING_KEYLESS)
...
typedef enum {
     TLS_ST_SW_SRVR_HELLO,
     TLS_ST_SW_CERT,
     TLS_ST_SW_KEY_EXCH,
+    TLS_ST_SW_KEY_EXCH_KEYLESS_PENDING_EVP_SIGNFINAL,
     TLS_ST_SW_CERT_REQ,
     TLS_ST_SW_SRVR_DONE,
     TLS_ST_SR_CERT,
     TLS_ST_SR_KEY_EXCH,
+    TLS_ST_SR_KEY_EXCH_KEYLESS_PENDING_RSA_PRIVATE_DECRYPT,
     TLS_ST_SR_CERT_VRFY,
     TLS_ST_SR_NEXT_PROTO,
     TLS_ST_SR_CHANGE, 
...
+  # define SSL_ERROR_PENDING_KEYLESS      12
...
+  __owur int SSL_CTX_use_PrivateKey_keyless(SSL_CTX *ctx, X509 *x509);
```

Position: /openssl-1.1.0h/ssl/ssl_lib.c

```c
+  void SSL_CTX_set_rsa_sign_cb(SSL_CTX *ctx,
+                               int (*rsa_sign_cb) (struct ssl_st *ssl,
+                                                 int type,
+                                                 const unsigned char *m,
+                                                 unsigned int m_len,
+                                                 unsigned char *sigret,
+                                                 unsigned int *siglen,
+                                                 RSA *rsa))
+  {
+      ctx->rsa_sign_cb = rsa_sign_cb;
+  }
+
+  void SSL_CTX_set_rsa_private_decrypt_cb(SSL_CTX *ctx,
+                               int (*rsa_private_decrypt_cb) (struct ssl_st *ssl,
+                                                 int flen,
+                                                 const unsigned char *from,
+                                                 unsigned char *to,
+                                                 RSA *rsa,
+                                                 int padding))
+  {
+      ctx->rsa_private_decrypt_cb = rsa_private_decrypt_cb;
+  }
+
+  void SSL_CTX_set_ec_sign_cb(SSL_CTX *ctx,
+                               int (*ec_sign_cb) (struct ssl_st *ssl,
+                                                 int type,
+                                                 const unsigned char *dgst,
+                                                 unsigned int dlen,
+                                                 unsigned char *sig,
+                                                 unsigned int *siglen,
+                                                 EC_KEY *eckey))
+  {
+      ctx->ec_sign_cb = ec_sign_cb;
+  }
...
int SSL_get_error(const SSL *s, int i)
     if (SSL_want_sess_lookup(s)) {
         return SSL_ERROR_WANT_SESSION_LOOKUP;
     }
+    if (SSL_want_keyless(s)) {  // 加入keyless错误处理
+        return SSL_ERROR_PENDING_KEYLESS;
+    }
```

Position: /openssl-1.1.0h/ssl/ssl_locl.h

```c
+    int (*rsa_sign_cb) (struct ssl_st *ssl, int type, const unsigned char *m,
+                        unsigned int m_len, unsigned char *sigret,
+                        unsigned int *siglen, RSA *rsa);
+    int (*rsa_private_decrypt_cb) (struct ssl_st *ssl, int flen,
+                        const unsigned char *from, unsigned char *to,
+                        RSA *rsa, int padding);
+    int (*ec_sign_cb) (struct ssl_st *ssl, int type, const unsigned char *dgst,
+                        unsigned int dlen, unsigned char *sig,
+                        unsigned int *siglen, EC_KEY *eckey);
...
+//keyless_ctx 会话环境structure
+    struct keyless_ctx_s {
+        /* used in pkey_rsa_sign() */
+        int                  sltmp;
+
+        /* used in tls_construct_server_key_exchange() */
+        int                  i;
+        int                  n;
+        unsigned char       *p;
+        EVP_MD_CTX          *md_ctx;
+        EVP_PKEY            *pkey;
+
+        /* rsa_private_decrypt, used in tls_process_cke_rsa() */
+        unsigned char       *rsa_decrypt;
+    } keyless_ctx;
```

Position: /openssl-1.1.0h/ssl/ssl_rsa.c

```c
+  int SSL_CTX_use_PrivateKey_keyless(SSL_CTX *ctx, X509 *x509)  // key server使用私钥解密公钥
+  {
+      EVP_PKEY *pubkey;
+
+      pubkey = X509_get0_pubkey(x509);
+
+      return (ssl_set_pkey(ctx->cert, pubkey));
+  }
```

Position: /openssl-1.1.0h/ssl/statem/statem.c

```c
static SUB_STATE_RETURN read_state_machine(SSL *s)  // 加入keyless状态返回
             }
             ret = process_message(s, &pkt);

+            if (ret == -SSL_ERROR_PENDING_KEYLESS) {
+                /*st->read_state = READ_STATE_PROCESS;*/
+                s->rwstate = SSL_PENDING_KEYLESS;
+                return SUB_STATE_ERROR;
+            }
...
static SUB_STATE_RETURN write_state_machine(SSL *s)  // 加入keyless状态返回
             case WORK_FINISHED_STOP:
                 return SUB_STATE_END_HANDSHAKE;
             }
-            if (construct_message(s) == 0) //使用keyless构建消息
+            ret = construct_message(s);
+            if (ret == -SSL_ERROR_PENDING_KEYLESS) {
+                st->write_state = WRITE_STATE_PRE_WORK;
+                s->rwstate = SSL_PENDING_KEYLESS;
+                return SUB_STATE_ERROR;
+            }
+            if (ret == 0)
                 return SUB_STATE_ERROR;
```

Position: /openssl-1.1.0h/ssl/statem/statrem_srvr.c

```c
int ossl_statem_server_construct_message(SSL *s)
         return tls_construct_server_certificate(s);     
		 ...
+    case TLS_ST_SW_KEY_EXCH_KEYLESS_PENDING_EVP_SIGNFINAL:
         return tls_construct_server_key_exchange(s);
     ...
+    case TLS_ST_SR_KEY_EXCH_KEYLESS_PENDING_RSA_PRIVATE_DECRYPT:
         return tls_process_client_key_exchange(s, pkt);
		 ...
       
int tls_construct_server_key_exchange(SSL *s) // 服务器密钥交换
     ...
-    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new(); //不直接生成读写锁
+    z *md_ctx;  
+    OSSL_STATEM *st = &s->statem;
+  // 若keyless状态为pending evp signal则生成keyless读写锁
+    if (st->hand_state == TLS_ST_SW_KEY_EXCH_KEYLESS_PENDING_EVP_SIGNFINAL) {
+        md_ctx = s->keyless_ctx.md_ctx;
+        goto resume_EVP_SignFinal;
+    } else {
+        md_ctx = EVP_MD_CTX_new();
+        s->keyless_ctx.md_ctx = md_ctx;
+    }

int tls_construct_server_key_exchange(SSL *s)		 
		 ...
+    EVP_MD_CTX_keyless_set_s(md_ctx, s);
     type = s->s3->tmp.new_cipher->algorithm_mkey;

     buf = s->init_buf;
 int tls_construct_server_key_exchange(SSL *s)  // 服务器端密钥交换
                                   SSL3_RANDOM_SIZE) <= 0
                 || EVP_SignUpdate(md_ctx, &(s->s3->server_random[0]),
                                   SSL3_RANDOM_SIZE) <= 0
-                || EVP_SignUpdate(md_ctx, d, n) <= 0
-                || EVP_SignFinal(md_ctx, &(p[2]),
-                                 (unsigned int *)&i, pkey) <= 0) {
+                || EVP_SignUpdate(md_ctx, d, n) <= 0) {  //参数删除EVP_SignFinal
		 ...
+
+resume_EVP_SignFinal: //使用keyless通过key server完成服务器端密钥交换解密/证书签名
+            if (s->ctx->rsa_sign_cb || s->ctx->ec_sign_cb) { // rsa/ecdsa签名
+		 ...
+            int ret = EVP_SignFinal(md_ctx, &(p[2]), // 新的EVP_SignFinal
+                             (unsigned int *)&s->keyless_ctx.i, pkey);
+    ...
+                /* done */
+                i = s->keyless_ctx.i;
+                st->hand_state = TLS_ST_SW_KEY_EXCH;
		 ...
+
+  pending_EVP_SignFinal: // 释放内存
+
+  #ifndef OPENSSL_NO_DH
+    EVP_PKEY_free(pkdh);
+  #endif
+  #ifndef OPENSSL_NO_EC
+    OPENSSL_free(encodedPoint);
+  #endif
+    st->hand_state = TLS_ST_SW_KEY_EXCH_KEYLESS_PENDING_EVP_SIGNFINAL;
+    return -SSL_ERROR_PENDING_KEYLESS;
 }
...
static int tls_process_cke_rsa(SSL *s, PACKET *pkt, int *al) // rsa私钥解密
     ...
+    OSSL_STATEM *st = &s->statem; //进行keyless rsa私钥解密操作
		 ...
+
+resume_rsa_private_decrypt:  //私钥解密错误：返回错误值
     if (RAND_bytes(rand_premaster_secret, sizeof(rand_premaster_secret)) <= 0)
         goto err;
 		 ... 
 
-    decrypt_len = RSA_private_decrypt(PACKET_remaining(&enc_premaster), // 删除本地解密
+    if (s->ctx->rsa_private_decrypt_cb) { //key server使用rsa私钥解密
+        s->keyless_ctx.rsa_decrypt = rsa_decrypt;
+        decrypt_len = s->ctx->rsa_private_decrypt_cb(s,
+                                      PACKET_remaining(&enc_premaster),
                                       PACKET_data(&enc_premaster),
                                       rsa_decrypt, rsa, RSA_NO_PADDING);
		 ...                                       
MSG_PROCESS_RETURN tls_process_client_key_exchange(SSL *s, PACKET *pkt)	// 客户端密钥交换
+    int ret;
		 ...
else if (alg_k & (SSL_kRSA | SSL_kRSAPSK)) { //修改错误处理
-        if (!tls_process_cke_rsa(s, pkt, &al))
+        ret = tls_process_cke_rsa(s, pkt, &al);
+        if (ret == - SSL_ERROR_PENDING_KEYLESS)
+            return ret;
+        if (!ret)
             goto err;
```


