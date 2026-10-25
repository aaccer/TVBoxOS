package com.github.tvbox.osc.util.js;

import android.os.Environment;
import android.util.Base64;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;

import com.github.tvbox.osc.server.ControlManager;
import com.github.tvbox.osc.util.FileUtils;
import com.github.tvbox.osc.util.LOG;
import com.github.tvbox.osc.util.rsa.RSAEncrypt;
import com.github.tvbox.osc.util.StringUtils;
import com.whl.quickjs.wrapper.ContextSetter;
import com.whl.quickjs.wrapper.Function;
import com.whl.quickjs.wrapper.JSArray;
import com.whl.quickjs.wrapper.JSFunction;
import com.whl.quickjs.wrapper.JSObject;
import com.whl.quickjs.wrapper.JSUtils;
import com.whl.quickjs.wrapper.QuickJSContext;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URLEncoder;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class Global {
    private QuickJSContext runtime;
    public ExecutorService executor;
    private final Timer timer;

    public Global(ExecutorService executor) {
        this.executor = executor;
        this.timer = new Timer();
    }

    @Keep
    @Function
    public String getProxy(boolean local) {
        return ControlManager.get().getAddress(local) + "proxy?do=js";
    }

    @Keep
    @Function
    public String js2Proxy(Boolean dynamic, Integer siteType, String siteKey, String url, JSObject headers) {
        return getProxy(true) + "&from=catvod" + "&siteType=" + siteType + "&siteKey=" + siteKey + "&header=" + URLEncoder.encode(headers.toJsonString()) + "&url=" + URLEncoder.encode(url);
    }

    @Keep
    @Function
    public String joinUrl(String parent, String child) {
        return HtmlParser.joinUrl(parent, child);
    }

    @Keep
    @Function
    public String pd(String html, String rule, String add_url) {
        return HtmlParser.parseDomForUrl(html, rule, add_url);
    }

    @Keep
    @Function
    public String pdfh(String html, String rule) {
        return HtmlParser.parseDomForUrl(html, rule, "");
    }

    @Keep
    @Function
    public JSArray pdfa(String html, String rule) {

        return new JSUtils<String>().toArray(runtime, HtmlParser.parseDomForArray(html, rule));
    }

    @Keep
    @Function
    public JSArray pdfla(String html, String p1, String list_text, String list_url, String add_url) {
        return new JSUtils<String>().toArray(runtime, HtmlParser.parseDomForList(html, p1, list_text, list_url, add_url));
    }

    @Keep
    @Function
    public String s2t(String text) {
        try {
            return Trans.s2t(false, text);
        } catch (Exception e) {
            return "";
        }
    }

    @Keep
    @Function
    public String t2s(String text) {
        try {
            return Trans.t2s(false, text);
        } catch (Exception e) {
            return "";
        }
    }

    @Keep
    @Function
    public String aesX(String mode, boolean encrypt, String input, boolean inBase64, String key, String iv, boolean outBase64) {
        String result = Crypto.aes(mode, encrypt, input, inBase64, key, iv, outBase64);
        //LOG.e("aesX",String.format("mode:%s\nencrypt:%s\ninBase64:%s\noutBase64:%s\nkey:%s\niv:%s\ninput:\n%s\nresult:\n%s", mode, encrypt, inBase64, outBase64, key, iv, input, result));
        return result;
    }

    @Keep
    @Function
    public String rsaX(String mode, boolean pub, boolean encrypt, String input, boolean inBase64, String key, boolean outBase64) {
        String result = Crypto.rsa(pub, encrypt, input, inBase64, key, outBase64);
        //LOG.e("aesX",String.format("mode:%s\npub:%s\nencrypt:%s\ninBase64:%s\noutBase64:%s\nkey:\n%s\ninput:\n%s\nresult:\n%s", mode, pub, encrypt, inBase64, outBase64, key, input, result));
        return result;
    }

    /**
     * RSA 加密
     *
     * @param data    要加密的数据
     * @param key     密钥，type 为 1 则公钥，type 为 2 则私钥
     * @param options 加密的选项，包含加密配置和类型：{ config: "RSA/ECB/PKCS1Padding", type: 1, long: 1 }
     *                config 加密的配置，默认 RSA/ECB/PKCS1Padding （可选）
     *                type 加密类型，1 公钥加密 私钥解密，2 私钥加密 公钥解密（可选，默认 1）
     *                long 加密方式，1 普通，2 分段（可选，默认 1）
     *                block 分段长度，false 固定117，true 自动（可选，默认 true ）
     * @return 返回加密结果
     */

    @Keep
    @Function
    public String rsaEncrypt(String data, String key, JSObject options) {
        int mLong = 1;
        int mType = 1;
        boolean mBlock = true;
        String mConfig = null;
        if (options != null) {
            JSONObject op = options.toJsonObject();
            if (op.has("config")) {
                try {
                    mConfig = (String) op.get("config");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (op.has("type")) {
                try {
                    mType = ((Double) op.get("type")).intValue();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (op.has("long")) {
                try {
                    mLong = ((Double) op.get("long")).intValue();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (op.has("block")) {
                try {
                    mBlock = (Boolean) op.get("block");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        try {
            switch (mType) {
                case 1:
                    if (mConfig != null) {
                        return RSAEncrypt.encryptByPublicKey(data, key, mConfig, mLong, mBlock);
                    } else {
                        return RSAEncrypt.encryptByPublicKey(data, key, mLong, mBlock);
                    }
                case 2:
                    if (mConfig != null) {
                        return RSAEncrypt.encryptByPrivateKey(data, key, mConfig, mLong, mBlock);
                    } else {
                        return RSAEncrypt.encryptByPrivateKey(data, key, mLong, mBlock);
                    }
                default:
                    return "";
            }
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * RSA 解密
     *
     * @param encryptBase64Data 加密后的 Base64 字符串
     * @param key               密钥，type 为 1 则私钥，type 为 2 则公钥
     * @param options           解密的选项，包含解密配置和类型：{ config: "RSA/ECB/PKCS1Padding", type: 1, long: 1 }
     *                          config 解密的配置，默认 RSA/ECB/PKCS1Padding （可选）
     *                          type 解密类型，1 公钥加密 私钥解密，2 私钥加密 公钥解密（可选，默认 1）
     *                          long 解密方式，1 普通，2 分段（可选，默认 1）
     *                          block 分段长度，false 固定128，true 自动（可选，默认 true ）
     * @return 返回解密结果
     */
    @Keep
    @Function
    public String rsaDecrypt(String encryptBase64Data, String key, JSObject options) {
        int mLong = 1;
        int mType = 1;
        boolean mBlock = true;
        String mConfig = null;
        if (options != null) {
            JSONObject op = options.toJsonObject();
            if (op.has("config")) {
                try {
                    mConfig = (String) op.get("config");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (op.has("type")) {
                try {
                    mType = ((Double) op.get("type")).intValue();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (op.has("long")) {
                try {
                    mLong = ((Double) op.get("long")).intValue();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (op.has("block")) {
                try {
                    mBlock = (Boolean) op.get("block");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        try {
            switch (mType) {
                case 1:
                    if (mConfig != null) {
                        return RSAEncrypt.decryptByPrivateKey(encryptBase64Data, key, mConfig, mLong, mBlock);
                    } else {
                        return RSAEncrypt.decryptByPrivateKey(encryptBase64Data, key, mLong, mBlock);
                    }
                case 2:
                    if (mConfig != null) {
                        return RSAEncrypt.decryptByPublicKey(encryptBase64Data, key, mConfig, mLong, mBlock);
                    } else {
                        return RSAEncrypt.decryptByPublicKey(encryptBase64Data, key, mLong, mBlock);
                    }
                default:
                    return "";
            }
        } catch (Exception e) {
            return "";
        }
    }

    private JSObject req(String url, JSObject options) {
        try {
            Req req = Req.objectFrom(options.toJsonObject().toString());
            Response res = Connect.to(url, req).execute();
            return Connect.success(runtime, req, res);
        } catch (Exception e) {
            return Connect.error(runtime);
        }
    }

    @Keep
    @Function
    public JSObject _http(String url, JSObject options) {
        JSFunction complete = options.getJSFunction("complete");
        if (complete == null) return req(url, options);
        Req req = Req.objectFrom(options.toJsonObject().toString());
        Connect.to(url, req).enqueue(getCallback(complete, req));
        return null;
    }

    @Keep
    @Function
    public void setTimeout(JSFunction func, Integer delay) {
        func.hold();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                if (!executor.isShutdown()) executor.submit(() -> {func.call();});
            }
        }, delay);
    }

    @Keep
    @Function
    public JSArray aesGcmEncrypt(Object key, Object iv, Object plain, Object aad) {
        try {
            byte[] keyBytes   = toByteArray(key);
            byte[] ivBytes    = toByteArray(iv);
            byte[] plainBytes = toByteArray(plain);
            byte[] aadBytes   = (aad == null) ? null : toByteArray(aad);
            if (keyBytes == null || ivBytes == null || plainBytes == null) return runtime.createJSArray();
    
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            if (aadBytes != null) c.updateAAD(aadBytes);
            byte[] out = c.doFinal(plainBytes);
    
            // 转 0~255，避免 JSUtils 推负数
            JSArray arr = runtime.createJSArray();
            for (byte b : out) {
                arr.push(b & 0xff);
            }
            return arr;
        } catch (Exception e) {
            e.printStackTrace();
            return runtime.createJSArray();
        }
    }

    // AES-GCM 解密（返回 UTF-8 字符串）    
    @Keep
    @Function
    public String aesGcmDecryptAad(Object key, Object iv, Object cipher, Object tag, Object aad) {
        try {
            // 3参数兼容：tag 为 null 时把 cipher 末尾 16 字节拆出来
            if (tag == null) {
                byte[] combined = toByteArray(cipher);
                if (combined == null || combined.length < 16) return null;
                byte[] c = new byte[combined.length - 16];
                byte[] t = new byte[16];
                System.arraycopy(combined, 0, c, 0, c.length);
                System.arraycopy(combined, c.length, t, 0, 16);
                cipher = c;
                tag = t;
            }
    
            byte[] keyBytes    = toByteArray(key);
            byte[] ivBytes     = toByteArray(iv);
            byte[] cipherBytes = toByteArray(cipher);
            byte[] tagBytes    = toByteArray(tag);
            byte[] aadBytes    = (aad == null) ? null : toByteArray(aad);
    
            if (keyBytes == null || ivBytes == null || cipherBytes == null || tagBytes == null) return null;
    
            int tagLenBits = tagBytes.length * 8;
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLenBits, ivBytes);
            Cipher cipherObj = Cipher.getInstance("AES/GCM/NoPadding");
            cipherObj.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
    
            // AAD 参与认证
            if (aadBytes != null) {
                cipherObj.updateAAD(aadBytes);
            }
    
            byte[] combined = new byte[cipherBytes.length + tagBytes.length];
            System.arraycopy(cipherBytes, 0, combined, 0, cipherBytes.length);
            System.arraycopy(tagBytes, 0, combined, cipherBytes.length, tagBytes.length);
    
            byte[] plain = cipherObj.doFinal(combined);
            return new String(plain, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Keep
    @Function
    public String aesGcmDecrypt(Object key, Object iv, Object cipher, Object tag) {
        return aesGcmDecryptAad(key, iv, cipher, tag, null);
    }

    // digest（SHA-256 / SHA-1 / SHA-384 / SHA-512 / MD5）
    @Keep
    @Function
    public String digest(String algoStr, Object dataObj) {
        try {
            String algo = algoStr.toUpperCase().replace("-", "");
            byte[] data = toByteArray(dataObj);
            
            if (data == null) return null;
    
            String javaAlgo;
            switch (algo) {
                case "SHA256": javaAlgo = "SHA-256"; break;
                case "SHA1":   javaAlgo = "SHA-1";   break;
                case "SHA384": javaAlgo = "SHA-384"; break;
                case "SHA512": javaAlgo = "SHA-512"; break;
                case "MD5":    javaAlgo = "MD5";     break;
                default: return null;
            }
            MessageDigest md = MessageDigest.getInstance(javaAlgo);
            byte[] hash = md.digest(data);
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Keep
    @Function
    public String hmac(Object algoObj, Object keyObj, Object dataObj) {
        try {
            String algo = (algoObj == null ? "HmacSHA256" : algoObj.toString().trim());
            // 兼容传入 "SHA256" / "HmacSHA256" / "HMACSHA256"
            String normalized = algo.toUpperCase().replace("-", "").replace("HMAC", "");
            String javaAlgo;
            switch (normalized) {
                case "SHA256": javaAlgo = "HmacSHA256"; break;
                case "SHA1":   javaAlgo = "HmacSHA1";   break;
                case "SHA384": javaAlgo = "HmacSHA384"; break;
                case "SHA512": javaAlgo = "HmacSHA512"; break;
                case "MD5":    javaAlgo = "HmacMD5";    break;
                default: return null;
            }
    
            byte[] key  = toByteArray(keyObj);
            byte[] data = toByteArray(dataObj);
            if (key == null || data == null) return null;
    
            Mac mac = Mac.getInstance(javaAlgo);
            mac.init(new SecretKeySpec(key, javaAlgo));
            byte[] out = mac.doFinal(data);
    
            // 返回 hex 文本
            StringBuilder hex = new StringBuilder(out.length * 2);
            for (byte b : out) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // powNonce：SHA-256 Proof-of-Work 求 Nonce
    // 返回：nonce（long），失败返回 -1
    @Keep
    @Function
    public long powNonce(Object dataStr, String diffStr, String mode, Number maxIter, String nonceSuffix) {
        try {
            byte[] data = toBytesForHash(dataStr);
            int diffLen = diffStr.length();
            if (diffLen == 0 || diffLen > 8) return -1L;

            long diffInt = Long.parseLong(diffStr, 16);

            if (mode == null) mode = "eq";
            long max = (maxIter != null) ? maxIter.longValue() : 10000000L;
            
            if (nonceSuffix == null) nonceSuffix = "dec";

            int bits = diffLen * 4;
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            for (long nonce = 0; nonce < max; nonce++) {
                byte[] nonceBytes;
                if ("hex".equals(nonceSuffix)) {
                    nonceBytes = Long.toHexString(nonce).getBytes(StandardCharsets.UTF_8);
                } else {
                    nonceBytes = Long.toString(nonce).getBytes(StandardCharsets.UTF_8);
                }

                md.reset();
                md.update(data);
                md.update(nonceBytes);
                byte[] hash = md.digest();

                long head = extractHead(hash, bits);

                boolean matched;
                switch (mode) {
                    case "eq": matched = head == diffInt; break;
                    case "le": matched = head <= diffInt; break;
                    case "lt":
                    default:   matched = head <  diffInt; break;
                }

                if (matched) return nonce;
            }

            //powNonce:未在max内找到
            return -1L;
        } catch (Exception e) {
            e.printStackTrace();
            return -1L;
        }
    }

    /** 从 hash 前 bits 位提取整数（bits 必须 <= 64）*/
    private static long extractHead(byte[] hash, int bits) {
        int bytesNeeded = (bits + 7) / 8;
        long value = 0;
        for (int i = 0; i < bytesNeeded; i++) {
            value = (value << 8) | (hash[i] & 0xFF);
        }
        int shift = bytesNeeded * 8 - bits;
        return value >>> shift;
    }


    private static final SecureRandom RNG = new SecureRandom();

    /** 指定长度随机字节，返回 hex 字符串（不 Base64） */
    @Keep
    @Function
    public String randomHex(int len) {
        if (len <= 0) return "";
        byte[] buf = new byte[len];
        RNG.nextBytes(buf);
        StringBuilder sb = new StringBuilder(len * 2);
        for (byte b : buf) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** 指定长度随机字节，返回 JS 数组（每个元素 0~255），不 Base64 */
    @Keep
    @Function
    public JSArray randomBytes(int len) {
        JSArray arr = runtime.createJSArray();
        if (len <= 0) return arr;
        byte[] buf = new byte[len];
        RNG.nextBytes(buf);
        for (byte b : buf) {
            arr.push(b & 0xff);
        }
        return arr;
    }
    /** 生成 UUID v4 */
    @Keep
    @Function
    public String uuidv4() {
        return UUID.randomUUID().toString();
    }

    /** 生成 32 字节随机，返回43位Base64 URL_SAFE | NO_WRAP | NO_PADDING */
    @Keep
    @Function
    public String randomCredential() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return Base64.encodeToString(buf, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    /** 指定长度随机字节，返回Base64 URL_SAFE 编码 */
    @Keep
    @Function
    public String secureRandom(int len) {
        if (len <= 0) return "";
        byte[] buf = new byte[len];
        RNG.nextBytes(buf);
        return Base64.encodeToString(buf, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    @Keep
    @Function
    public String detectType(Object obj) {
        if (obj == null) return "null";
    
        StringBuilder sb = new StringBuilder();
        Class<?> clazz = obj.getClass();
        sb.append("类名: ").append(clazz.getName());
    
        if (obj instanceof JSArray) {
            JSArray arr = (JSArray) obj;
            int len = arr.length();
            sb.append("\n类型: JSArray");
            sb.append("\n长度: ").append(len);
            if (len > 0) {
                Object first = arr.get(0);
                sb.append("\n第一个元素类型: ")
                  .append(first == null ? "null" : first.getClass().getName());
            }
        }else if (obj instanceof JSObject) {
            sb.append("\n类型: JSObject");
            try {
                String json = ((JSObject) obj).toJsonString();
                sb.append("\n预览: ").append(json, 0, Math.min(100, json.length()));
            } catch (Exception e) {
                sb.append("\n预览失败: ").append(e.getMessage());
            }
        }else if (clazz.isArray()) {
            sb.append("\n类型: 数组");
            int len = Array.getLength(obj);
            sb.append("\n长度: ").append(len);
            if (len > 0) {
                Object first = Array.get(obj, 0);
                sb.append("\n第一个元素类型: ")
                  .append(first == null ? "null" : first.getClass().getName());
            }
        } else if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            sb.append("\n类型: List");
            sb.append("\n长度: ").append(list.size());
            if (!list.isEmpty()) {
                Object first = list.get(0);
                sb.append("\n第一个元素类型: ")
                  .append(first == null ? "null" : first.getClass().getName());
            }
        } else if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;
            sb.append("\n类型: Map");
            sb.append("\n大小: ").append(map.size());
        } else if (obj instanceof String) {
            String s = (String) obj;
            sb.append("\n类型: String");
            sb.append("\n长度: ").append(s.length());
            sb.append("\n内容预览: ").append(s, 0, Math.min(50, s.length()));
        } else if (obj instanceof Number) {
            sb.append("\n类型: Number");
            sb.append("\n数值: ").append(obj);
            sb.append("\n精确类型: ").append(clazz.getName());
        } else if (obj instanceof Boolean) {
            sb.append("\n类型: Boolean");
            sb.append("\n值: ").append(obj);
        } else {
            String name = clazz.getName();
            if (name.contains("Uint8Array")) sb.append("\n类型: Uint8Array");
            else if (name.contains("TypedArray")) sb.append("\n类型: TypedArray");
            else if (name.contains("ArrayBuffer")) sb.append("\n类型: ArrayBuffer");
            else if (name.contains("JSObject")) sb.append("\n类型: JSObject");
            else if (name.contains("JSFunction")) sb.append("\n类型: JSFunction");
            else sb.append("\n类型: 其他");

            sb.append("\n实现的接口:");
            for (Class<?> iface : clazz.getInterfaces()) {
                sb.append(" ").append(iface.getName());
            }
        }

        return sb.toString();
    }

    /**
     *  将任意输入转换为 byte[]
     * String文本默认十六进制字符串 
     */
    public static byte[] toByteArray(Object obj) {
        if (obj == null) return null;
        if (obj instanceof byte[]) return (byte[]) obj;
 
        if (obj instanceof ByteBuffer) {
            ByteBuffer buf = (ByteBuffer) obj;
            byte[] arr = new byte[buf.remaining()];
            buf.get(arr);
            return arr;
        }
        
        // 十六进制字符串    
        if (obj instanceof String) {
            String s = ((String) obj).trim();
            if (s.length() % 2 != 0) s = "0" + s;
            byte[] data = new byte[s.length() / 2];
            for (int i = 0; i < s.length(); i += 2) {
                int hi = Character.digit(s.charAt(i), 16);
                int lo = Character.digit(s.charAt(i + 1), 16);
                if (hi == -1 || lo == -1) throw new IllegalArgumentException("非法十六进制");
                data[i / 2] = (byte) ((hi << 4) | lo);
            }
            return data;
        }
    
        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            byte[] arr = new byte[list.size()];
            for (int i = 0; i < list.size(); i++) {
                Object v = list.get(i);
                arr[i] = (v instanceof Number) ? ((Number) v).byteValue() : 0;
            }
            return arr;
        }
    
        // JSArray 必须先于 JSObject 判断
        if (obj instanceof JSArray) {
            JSArray arr = (JSArray) obj;
            int len = arr.length();
            byte[] result = new byte[len];
            for (int i = 0; i < len; i++) {
                Object item = arr.get(i);
                result[i] = (item instanceof Number) ? ((Number) item).byteValue() : 0;
            }
            return result;
        }
    
        // Uint8Array 走这里（被桥接为 JSObject）
        if (obj instanceof JSObject) {
            JSObject jsObj = (JSObject) obj;
            try {
                Object lenObj = jsObj.get("length");
                if (lenObj instanceof Number) {
                    int len = ((Number) lenObj).intValue();
                    if (len >= 0 && len < 100 * 1024 * 1024) {
                        byte[] result = new byte[len];
                        for (int i = 0; i < len; i++) {
                            Object item = jsObj.get(String.valueOf(i));
                            result[i] = (item instanceof Number) ? ((Number) item).byteValue() : 0;
                        }
                        return result;
                    }
                }
            } catch (Exception ignored) {}
        }
    
        if (obj.getClass().isArray()) {
            int len = Array.getLength(obj);
            byte[] arr = new byte[len];
            for (int i = 0; i < len; i++) {
                Object elem = Array.get(obj, i);
                if (elem instanceof Number) arr[i] = ((Number) elem).byteValue();
                else return null;
            }
            return arr;
        }
    
        return null;
    }

    /**
     * 哈希类函数专用：String 按 UTF-8 处理，其他类型走 toByteArray
     * 与 CryptoJS.SHA256(str) 行为一致
     */
    public static byte[] toBytesForHash(Object obj) {
        if (obj == null) return null;
        if (obj instanceof String) {
            return ((String) obj).getBytes(StandardCharsets.UTF_8);
        }
        return toByteArray(obj);
    }

    // ================= 路径信息 =================
    
    /** 内部存储根目录 /storage/emulated/0 */
    @Keep
    @Function
    public String rootPath() {
        return FileUtils.getRootPath();
    }
    
    /** 应用缓存目录 */
    @Keep
    @Function
    public String cachePath() {
        return FileUtils.getCachePath();
    }
    
    /** 应用私有 files 目录 */
    @Keep
    @Function
    public String filesPath() {
        return FileUtils.getFilePath();
    }
    
    /** 外部缓存目录（可能为 null） */
    @Keep
    @Function
    public String externalCachePath() {
        try {
            return FileUtils.getExternalCachePath();
        } catch (Exception e) {
            return "";
        }
    }
    
    // ================= 存在性判断 =================
    
    /** 路径是否存在 */
    @Keep
    @Function
    public boolean exists(String path) {
        if (StringUtils.isEmpty(path)) return false;
        return new File(normalizePath(path)).exists();
    }
    
    /** 是否是文件 */
    @Keep
    @Function
    public boolean isFile(String path) {
        if (StringUtils.isEmpty(path)) return false;
        return new File(normalizePath(path)).isFile();
    }
    
    /** 是否是目录 */
    @Keep
    @Function
    public boolean isDir(String path) {
        if (StringUtils.isEmpty(path)) return false;
        return new File(normalizePath(path)).isDirectory();
    }
    
    // ================= 目录读取 =================
    
    /**
     * 列出目录内容
     * @return 每项 {name, path, isDir, size, lastModified}
     *         目录不存在或为空时返回空 List
     */
    @Keep
    @Function
    public JSArray listDir(String path) {
        JSArray out = runtime.createJSArray();
        if (StringUtils.isEmpty(path)) return out;
    
        File dir = new File(normalizePath(path));
        if (!dir.exists() || !dir.isDirectory()) return out;
    
        File[] files = dir.listFiles();
        if (files == null) return out;
    
        for (File f : files) {
            JSObject item = runtime.createJSObject();
            item.set("name", f.getName());
            item.set("path", f.getAbsolutePath());
            item.set("isDir", f.isDirectory());
            item.set("size", f.length());
            item.set("lastModified", f.lastModified());
            out.push(item);
        }
        return out;
    }


    
    /** 只返回文件名数组，按名字排序 */
    @Keep
    @Function
    public JSArray listNames(String path) {
        JSArray out = runtime.createJSArray();
        if (StringUtils.isEmpty(path)) return out;
    
        File dir = new File(normalizePath(path));
        if (!dir.exists() || !dir.isDirectory()) return out;
    
        String[] names = dir.list();
        if (names == null) return out;
    
        java.util.Arrays.sort(names);
        for (String n : names) out.push(n);
        return out;
    }
    
    // ================= 文件读取 =================
    
    /** 读文本文件，指定编码，失败返回空串 */
    @Keep
    @Function
    public String readText(String path, String charset) {
        if(charset == null) charset ="UTF-8";
        if (StringUtils.isEmpty(path)) return "";
        try {
            return FileUtils.readFileToString(normalizePath(path), charset);
        } catch (Exception e) {
            return "";
        }
    }
    
    /** 读文本，直接返回 FileUtils 的解码结果（走 FileUtils.readFileToString） */
    @Keep
    @Function
    public String readUtf8Text(String path) {
        return readText(path, "UTF-8");
    }
    
    /** 读二进制文件，返回 0~255 的数组；失败返回空数组 */
    @Keep
    @Function
    public JSArray readBytes(String path) {
        JSArray arr = runtime.createJSArray();
        if (StringUtils.isEmpty(path)) return arr;
    
        File file = new File(normalizePath(path));
        if (!file.exists() || !file.isFile()) return arr;
    
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buf = new byte[(int) file.length()];
            int read = 0, total = 0;
            while ((read = fis.read(buf, total, buf.length - total)) > 0) {
                total += read;
                if (total >= buf.length) break;
            }
            for (int i = 0; i < total; i++) arr.push(buf[i] & 0xff);
        } catch (IOException e) {
            // ignore
        }
        return arr;
    }
    
    // ================= 文件写入 =================
    //覆盖
    @Keep
    @Function
    public boolean writeText(String path, Object content, String charset) {
        if (StringUtils.isEmpty(path) || content == null) return false;
        try {
            String cs = (charset == null || charset.isEmpty()) ? "UTF-8" : charset;
            String text = String.valueOf(content);
            File file = new File(normalizePath(path));
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            return FileUtils.writeSimple(text.getBytes(cs), file);
        } catch (Exception e) {
            return false;
        }
    }
    //追加
    @Keep
    @Function
    public boolean appendText(String path, Object content, String charset) {
        if (StringUtils.isEmpty(path) || content == null) return false;
        try {
            String cs = (charset == null || charset.isEmpty()) ? "UTF-8" : charset;
            String text = String.valueOf(content);   // 布尔/数字/字符串都转
            File file = new File(normalizePath(path));
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            try (FileOutputStream fos = new FileOutputStream(file, true)) {
                fos.write(text.getBytes(cs));
                fos.flush();
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 规范化路径：
     * - 支持 file:// / file:/ 前缀
     * - 支持 /sdcard/ 别名 → /storage/emulated/0/
     * - 其他原样返回
     */
    private String normalizePath(String path) {
        if (StringUtils.isEmpty(path)) return "";
        String p = path.trim();
    
        if (p.startsWith("file://")) {
            p = p.substring(7);
        } else if (p.startsWith("file:/")) {
            p = p.substring(6);
        }
    
        if (p.startsWith("/sdcard/")) {
            p = p.replaceFirst("^/sdcard/", "/storage/emulated/0/");
        } else if (p.equals("/sdcard")) {
            p = "/storage/emulated/0";
        }
    
        return p;
    }
    

    private Callback getCallback(JSFunction complete, Req req) {
        return new Callback() {
            @Override
            public void onResponse(@NonNull Call call, @NonNull Response res) {
                executor.submit(() -> {
                    complete.call(Connect.success(runtime, req, res));
                });
            }

            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                executor.submit(() -> {
                    complete.call(Connect.error(runtime));
                });
            }
        };
    }
    // 声明用于依赖注入的 QuickJSContext
    @Keep
    @ContextSetter
    public void setJSContext(QuickJSContext runtime) {
        this.runtime = runtime;
    }

}
