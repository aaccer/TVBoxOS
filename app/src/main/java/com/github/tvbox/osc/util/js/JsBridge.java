package com.github.tvbox.osc.util.js;

import com.whl.quickjs.wrapper.JSCallFunction;
import com.whl.quickjs.wrapper.QuickJSContext;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JsBridge {

    // 注册所有桥接函数到 QuickJS 全局对象
    public static void register(QuickJSContext ctx) {
        ctx.getGlobalObject().set("aesGcmDecrypt", AES_GCM_DECRYPT);
        ctx.getGlobalObject().set("digest", DIGEST);
        ctx.getGlobalObject().set("detectType", DETECT_TYPE);
        ctx.getGlobalObject().set("powNonce", POW_NONCE);
    }

    // AES-GCM 解密（返回 UTF-8 字符串）
    private static final JSCallFunction AES_GCM_DECRYPT = new JSCallFunction() {
        @Override
        public Object call(Object... args) {
            try {
                if (args.length < 3) {
                    return null;
                }
    
                byte[] key = toByteArray(args[0]);
                byte[] iv = toByteArray(args[1]);
                if (key == null || iv == null) {
                    return null;
                }
    
                byte[] cipher;
                byte[] tag;
    
                if (args.length == 3) {
                    // 3 个参数：cipher 与 tag 拼接在 args[2] 中，tag 取末尾 16 字节
                    byte[] combined = toByteArray(args[2]);
                    if (combined == null || combined.length < 16) {
                        return null;
                    }
                    int tagLen = 16;
                    cipher = new byte[combined.length - tagLen];
                    tag = new byte[tagLen];
                    System.arraycopy(combined, 0, cipher, 0, cipher.length);
                    System.arraycopy(combined, cipher.length, tag, 0, tagLen);
                } else {
                    // 4 个参数：cipher 与 tag 分开传入
                    cipher = toByteArray(args[2]);
                    tag = toByteArray(args[3]);
                    if (cipher == null || tag == null) {
                        return null;
                    }
                }
    
                int tagLenBits = tag.length * 8;
                SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLenBits, iv);
                Cipher cipherObj = Cipher.getInstance("AES/GCM/NoPadding");
                cipherObj.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
    
                byte[] combined = new byte[cipher.length + tag.length];
                System.arraycopy(cipher, 0, combined, 0, cipher.length);
                System.arraycopy(tag, 0, combined, cipher.length, tag.length);
    
                byte[] plain = cipherObj.doFinal(combined);
                return new String(plain, StandardCharsets.UTF_8);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }
    };


    // digest（SHA-256 / SHA-1 / SHA-384 / SHA-512 / MD5）
    // 返回 byte[]（桥接层会转为 ArrayBuffer）
    private static final JSCallFunction DIGEST = new JSCallFunction() {
        @Override
        public Object call(Object... args) {
            try {
                if (args.length < 1) {
                    return null;
                }
    
                String algo;
                byte[] data;
    
                if (args.length == 1) {
                    // 只传 1 个参数：默认 SHA-256，参数为数据
                    algo = "SHA256";
                    data = toByteArray(args[0]);
                } else {
                    // 2 个及以上参数：第一个是算法名，第二个是数据
                    algo = args[0].toString().toUpperCase().replace("-", "");
                    data = toByteArray(args[1]);
                }
    
                if (data == null) {
                    return null;
                }
    
                String javaAlgo;
                switch (algo) {
                    case "SHA256": javaAlgo = "SHA-256"; break;
                    case "SHA1":   javaAlgo = "SHA-1";   break;
                    case "SHA384": javaAlgo = "SHA-384"; break;
                    case "SHA512": javaAlgo = "SHA-512"; break;
                    case "MD5":    javaAlgo = "MD5";     break;
                    default:
                        return null;
                }
    
                MessageDigest md = MessageDigest.getInstance(javaAlgo);
                return md.digest(data);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }
    };

// ============================================================
// powNonce：SHA-256 Proof-of-Work 求 Nonce
// 参数：(data, diff[, mode[, maxIter[, nonceSuffix]]])
// 返回：nonce（long），失败返回 -1
// ============================================================
private static final JSCallFunction POW_NONCE = new JSCallFunction() {
    @Override
    public Object call(Object... args) {
        try {
            if (args.length < 2) {
                //System.err.println("powNonce: 至少需要2个参数 (data, diff)");
                return -1L;
            }

            byte[] data = toByteArray(args[0]);
            if (data == null) {
                //System.err.println("powNonce: 数据转换失败");
                return -1L;
            }

            String diffStr = args[1].toString().trim();
            int diffLen = diffStr.length();
            if (diffLen == 0 || diffLen > 8) {
                //System.err.println("powNonce: diff 长度必须在 1~8 之间，实际: " + diffLen);
                return -1L;
            }
            long diffInt = Long.parseLong(diffStr, 16);

            String mode = args.length >= 3 ? args[2].toString() : "lt";
            long maxIter = args.length >= 4
                    ? ((Number) args[3]).longValue()
                    : 10000000L;
            String nonceSuffix = args.length >= 5 ? args[4].toString() : "dec";

            int bits = diffLen * 4;   // diff 对应的位数
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            for (long nonce = 0; nonce < maxIter; nonce++) {
                // 拼接 nonce
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

                if (matched) {
                    return nonce;
                }
            }

            //System.err.println("powNonce: 未在 " + maxIter + " 次内找到符合条件的 nonce");
            return -1L;
        } catch (Exception e) {
            e.printStackTrace();
            return -1L;
        }
    }
};

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


    // 返回参数类型的详细描述
    private static final JSCallFunction DETECT_TYPE = new JSCallFunction() {
        @Override
        public Object call(Object... args) {
            if (args.length == 0) return "没有参数";
            return detectType(args[0]);
        }
    };

    public static String detectType(Object obj) {
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

        // 1. 直接 byte[]
        if (obj instanceof byte[]) return (byte[]) obj;

        // 2. ByteBuffer
        if (obj instanceof ByteBuffer) {
            ByteBuffer buf = (ByteBuffer) obj;
            byte[] arr = new byte[buf.remaining()];
            buf.get(arr);
            return arr;
        }

        // 3. 十六进制字符串
        if (obj instanceof String) {
            String s = ((String) obj).trim();
            if (s.length() % 2 != 0) s = "0" + s;
            byte[] data = new byte[s.length() / 2];
            for (int i = 0; i < s.length(); i += 2) {
                int high = Character.digit(s.charAt(i), 16);
                int low = Character.digit(s.charAt(i + 1), 16);
                if (high == -1 || low == -1) {
                    throw new IllegalArgumentException("非法十六进制字符串: " + s);
                }
                data[i / 2] = (byte) ((high << 4) | low);
            }
            return data;
        }

        // 4. List（如 JS 数组）
        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            byte[] arr = new byte[list.size()];
            for (int i = 0; i < list.size(); i++) {
                Object val = list.get(i);
                if (val instanceof Number) {
                    arr[i] = ((Number) val).byteValue();
                } else {
                    arr[i] = 0;
                }
            }
            return arr;
        }

        // 5. QuickJS 的 Uint8Array / TypedArray / ArrayBuffer（反射获取）
        String className = obj.getClass().getName();
        if (className.contains("Uint8Array")
                || className.contains("TypedArray")
                || className.contains("ArrayBuffer")) {
            try {
                Method m = obj.getClass().getMethod("toByteArray");
                return (byte[]) m.invoke(obj);
            } catch (Exception ignored) {}

            try {
                Method getBuffer = obj.getClass().getMethod("getBuffer");
                Object buffer = getBuffer.invoke(obj);
                Method getData = buffer.getClass().getMethod("getData");
                return (byte[]) getData.invoke(buffer);
            } catch (Exception ignored) {}
        }

        // 6. 其他原生数组（int[]、long[] 等）
        if (obj.getClass().isArray()) {
            int len = Array.getLength(obj);
            byte[] arr = new byte[len];
            for (int i = 0; i < len; i++) {
                Object elem = Array.get(obj, i);
                if (elem instanceof Number) {
                    arr[i] = ((Number) elem).byteValue();
                } else {
                    return null;
                }
            }
            return arr;
        }

        return null;
    }
}
