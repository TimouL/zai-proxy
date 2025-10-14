import time
import hmac
import hashlib
import base64


def generate_signature(e: str, t: str) -> dict:
    """
    根据输入参数 e 和 t 生成签名和时间戳。

    Args:
        e: 第一个输入参数。e = "requestId,{request_id},timestamp,{timestamp},user_id,{user_id}"
        t: 第二个输入参数(content,将被Base64编码)。

    Returns:
        一个包含 'signature' 和 'timestamp' 的字典。
    """
    # 1. 获取当前时间的毫秒级时间戳
    timestamp_ms = int(time.time() * 1000)
    # timestamp_ms = 1759746422192

    # 2. 对 content 进行 Base64 编码
    content_base64 = base64.b64encode(t.encode('utf-8')).decode('ascii')

    # 3. 拼接字符串
    message_string = f"{e}|{content_base64}|{timestamp_ms}"

    # 4. 计算 n
    n = timestamp_ms // (5 * 60 * 1000)

    # 5. 计算中间密钥 o (HMAC-SHA256)
    key1 = "junjie".encode("utf-8")
    msg1 = str(n).encode("utf-8")
    intermediate_key = hmac.new(key1, msg1, hashlib.sha256).hexdigest()

    # 6. 计算最终签名 (HMAC-SHA256)
    key2 = intermediate_key.encode("utf-8")
    msg2 = message_string.encode("utf-8")
    final_signature = hmac.new(key2, msg2, hashlib.sha256).hexdigest()

    # 7. 返回结果
    return {"signature": final_signature, "timestamp": timestamp_ms}


if __name__ == "__main__":
    # 示例用法
    e_value = "requestId,7c30e6d9-e1fc-4970-9fc6-e27363415dda,timestamp,1759746406495,user_id,21ea9ec3-e492-4dbb-b522-fc0eaf64f0f6"
    t_value = "写一个hello world"
    result = generate_signature(e_value, t_value)
    print(f"生成的签名: {result['signature']}")
    print(f"时间戳: {result['timestamp']}")
