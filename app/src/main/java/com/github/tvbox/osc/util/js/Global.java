package com.github.tvbox.osc.util.js;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;

import com.github.tvbox.osc.server.ControlManager;
import com.github.tvbox.osc.util.LOG;
import com.github.tvbox.osc.util.rsa.RSAEncrypt;
import com.whl.quickjs.wrapper.ContextSetter;
import com.whl.quickjs.wrapper.Function;
import com.whl.quickjs.wrapper.JSArray;
import com.whl.quickjs.wrapper.JSFunction;
import com.whl.quickjs.wrapper.JSObject;
import com.whl.quickjs.wrapper.JSUtils;
import com.whl.quickjs.wrapper.QuickJSContext;

import org.json.JSONObject;

import java.io.IOException;
import java.net.URLEncoder;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;

import javax.crypto.Cipher;
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

    @Keep
    @Function
    public String rsaEncrypt(String data, String key) {
        return  rsaEncrypt(data, key, null);
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

    @Keep
    @Function
    public String rsaDecrypt(String encryptBase64Data, String key) {
        return  rsaDecrypt(encryptBase64Data, key, null);
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

    // AES-GCM 解密（返回 UTF-8 字符串）    
    @Keep
    @Function
    public String aesGcmDecrypt(Object key, Object iv, Object cipher, Object tag) {
        try {
            // 3 参数时把 cipher 和 tag 合并
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
            byte[] keyBytes = toByteArray(key);
            byte[] ivBytes = toByteArray(iv);
            byte[] cipherBytes = toByteArray(cipher);
            byte[] tagBytes = toByteArray(tag);
            if (keyBytes == null || ivBytes == null || cipherBytes == null || tagBytes == null) return null;
    
            int tagLenBits = tagBytes.length * 8;
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLenBits, ivBytes);
            Cipher cipherObj = Cipher.getInstance("AES/GCM/NoPadding");
            cipherObj.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
    
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

    // digest（SHA-256 / SHA-1 / SHA-384 / SHA-512 / MD5）
    @Keep
    @Function
    public String digest(String algoStr, Object dataObj) {
        try {
            String algo = algoStr.toUpperCase().replace("-", "");
            byte[] data = toBytesForHash(dataObj);
            
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

    // powNonce：SHA-256 Proof-of-Work 求 Nonce
    // 参数：(data, diff, mode, maxIter, nonceSuffix)
    // 返回：nonce（long），失败返回 -1
    @Keep
    @Function
    public long powNonce(Object dataStr, String diffStr, String mode, Integer maxIter, String nonceSuffix) {
        try {
            byte[] data = toBytesForHash(dataStr);
            int diffLen = diffStr.length();
            if (diffLen == 0 || diffLen > 8) return -1L;

            long diffInt = Long.parseLong(diffStr, 16);

            if (mode == null) mode = "eq";
            if (maxIter == null) maxIter = 10000000L;
            if (nonceSuffix == null) nonceSuffix = "dec";

            int bits = diffLen * 4;
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            for (long nonce = 0; nonce < maxIter; nonce++) {
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

            //System.err.println("powNonce: 未在 " + maxIter + " 次内找到");
            return -1L;
        } catch (Exception e) {
            e.printStackTrace();
            return -1L;
        }
    }


    /**
     * 从 hash 前 bits 位提取整数（bits 必须 <= 64）
     */
    private static long extractHead(byte[] hash, int bits) {
        int bytesNeeded = (bits + 7) / 8;
        long value = 0;
        for (int i = 0; i < bytesNeeded; i++) {
            value = (value << 8) | (hash[i] & 0xFF);
        }
        int shift = bytesNeeded * 8 - bits;
        return value >>> shift;
    }


    @Keep
    @Function
    public String detectType(Object obj) {
        if (obj == null) return "null";

        StringBuilder sb = new StringBuilder();
        Class<?> clazz = obj.getClass();
        sb.append("类名: ").append(clazz.getName());

        if (clazz.isArray()) {
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

        // 尝试转换为 byte[]
        try {
            byte[] bytes = toByteArray(obj);
            if (bytes != null) {
                sb.append("\n可转为 byte[]，长度: ").append(bytes.length);
            } else {
                sb.append("\n无法转为 byte[]");
            }
        } catch (Exception e) {
            sb.append("\n转换 byte[] 时异常: ").append(e.getMessage());
        }

        return sb.toString();
    }

    // 将任意输入转换为 byte[]
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
            // 优先用 JSON 序列化（大数据快），失败再退到索引访问
            try {
                String json = arr.toJsonString();
                byte[] result = new byte[len];
                int idx = 0, num = 0;
                boolean inNum = false;
                for (int i = 1; i < json.length() && idx < len; i++) {
                    char c = json.charAt(i);
                    if (c >= '0' && c <= '9') {
                        num = num * 10 + (c - '0');
                        inNum = true;
                    } else if (inNum) {
                        result[idx++] = (byte) num;
                        num = 0;
                        inNum = false;
                    }
                }
                if (idx == len) return result;
            } catch (Exception ignored) {}
    
            // 兜底：逐索引
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
    @Keep
    // 声明用于依赖注入的 QuickJSContext
    @ContextSetter
    public void setJSContext(QuickJSContext runtime) {
        this.runtime = runtime;
    }

}
