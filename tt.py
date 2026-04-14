import requests

# ======================
# Python版 难度解压缩函数
# 【1:1 对齐你的Rust最终版函数，结果完全一致】
# ======================
def compact_to_target(compact: int) -> bytes:
    exponent = (compact >> 24) & 0xFF
    mantissa = compact & 0x00FFFFFF

    # 比特币官方校验
    if exponent == 0 or mantissa == 0 or (mantissa & 0x800000) != 0:
        raise ValueError("无效的nBits")
    if exponent > 32:
        raise ValueError("指数超过256位上限")

    target = bytearray(32)  # 32字节大端目标值

    if exponent <= 3:
        # 小指数：右移填充到低位
        shift = 8 * (3 - exponent)
        mantissa >>= shift
        bytes_val = mantissa.to_bytes(4, byteorder="big")
        target[31] = bytes_val[3]
        if exponent >= 2:
            target[30] = bytes_val[2]
        if exponent == 3:
            target[29] = bytes_val[1]
    else:
        # 大指数：填充到高位
        start = 32 - exponent
        target[start] = (mantissa >> 16) & 0xFF
        target[start + 1] = (mantissa >> 8) & 0xFF
        target[start + 2] = mantissa & 0xFF

    return bytes(target)

# ======================
# 通过API获取比特币指定高度区块的难度数据
# ======================
def get_bitcoin_difficulty(block_height: int):
    base_url = "https://blockstream.info/api"

    try:
        # 1. 根据区块高度获取区块哈希
        hash_resp = requests.get(f"{base_url}/block-height/{block_height}", timeout=10)
        block_hash = hash_resp.text.strip()

        # 2. 获取区块详情（拿到nBits）
        block_resp = requests.get(f"{base_url}/block/{block_hash}", timeout=10)
        block_data = block_resp.json()

        # 提取核心数据
        bits_hex = block_data["bits"]          # 十六进制nBits
        bits_int = int(bits_hex, 16)           # 十进制nBits
        target_bytes = compact_to_target(bits_int)  # 解压缩后的32字节目标值
        target_hex = target_bytes.hex()         # 十六进制格式（方便对比）

        # 打印结果
        print("=" * 60)
        print(f"比特币区块高度: {block_height}")
        print(f"区块哈希: {block_hash}")
        print(f"原始nBits(十六进制): {bits_hex}")
        print(f"原始nBits(十进制): {bits_int}")
        print(f"解压缩后256位目标值(十六进制): {target_hex}")
        print("=" * 60)

        return {
            "height": block_height,
            "bits_hex": bits_hex,
            "bits_int": bits_int,
            "target_hex": target_hex
        }

    except Exception as e:
        print(f"获取失败: {e}")
        return None

# ======================
# 【使用方法】输入你想查询的区块高度即可
# ======================
if __name__ == "__main__":
    # 示例：查询最新区块/历史区块
    # 可以改成任意高度：如 840000（牛市高点）、0（创世区块）、700000 等
    TARGET_HEIGHT = 840000
    get_bitcoin_difficulty(TARGET_HEIGHT)