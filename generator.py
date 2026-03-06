import os
import json
import requests
import shutil
import math
import re
from datetime import datetime

# --- CẤU HÌNH ---
CONFIG_FILE = 'config/sources.json'
OUTPUT_DIR = 'output'
MAX_LINES_PER_FILE = 400_000
REPO_BASE_URL = "https://raw.githubusercontent.com/hoafd/adguard_filters/main/output/"

# 1. Dọn dẹp và tạo mới thư mục OUTPUT
if os.path.exists(OUTPUT_DIR): 
    shutil.rmtree(OUTPUT_DIR)
os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_clean_domain(rule):
    """
    SIÊU CHUẨN HÓA: Đưa mọi định dạng về domain thuần túy để so sánh.
    Lột sạch @@, ||, ^, $options, !, # và xử lý file Hosts.
    """
    r = rule.lower().strip()
    r = r.replace('@@', '').replace('||', '')
    
    # Xử lý định dạng file Hosts (0.0.0.0 domain.com)
    parts = r.split()
    if len(parts) > 1 and (re.match(r'^\d', parts[0]) or parts[0] == 'localhost'):
        r = parts[1]
    else:
        r = parts[0]

    # Loại bỏ phần đuôi và ký tự điều hướng
    r = r.split('$')[0].split('!')[0].split('#')[0].replace('^', '').strip()
    return r

def process_content(content, data_dict, is_whitelist):
    """
    Xử lý nội dung văn bản và đưa vào từ điển theo key là domain đã chuẩn hóa.
    """
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('!', '#')): continue
        if not is_whitelist and line.startswith('@@'): continue

        domain_key = get_clean_domain(line)
        if not domain_key: continue

        has_important = '$important' in line.lower()

        if domain_key not in data_dict:
            data_dict[domain_key] = line
        else:
            # Xử lý ưu tiên trong cùng danh sách
            current_line = data_dict[domain_key]
            current_important = '$important' in current_line.lower()
            
            if is_whitelist:
                if has_important and not current_important:
                    data_dict[domain_key] = line
            else:
                if not has_important and current_important:
                    data_dict[domain_key] = line

def fetch_data(session, url_list, category):
    """
    Tải dữ liệu trực tiếp từ URL, không lưu backup.
    """
    data_dict = {}
    is_wl = (category == 'whitelist')
    for url in url_list:
        print(f"[*] [{category.upper()}] Đang tải: {url[:60]}...")
        try:
            # Chống cache của GitHub
            f_url = f"{url}?t={int(datetime.now().timestamp())}" if "github" in url else url
            r = session.get(f_url, timeout=25)
            if r.status_code == 200:
                process_content(r.text, data_dict, is_wl)
            else:
                print(f"   [!] Lỗi HTTP {r.status_code}: Bỏ qua nguồn này.")
        except Exception as e:
            print(f"   [!] Lỗi kết nối: {e}. Bỏ qua nguồn này.")
    return data_dict

def generate_header(title, count, total, config, links_str):
    time_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    h = [f"! Title: {title}", f"! Updated: {time_now}", f"! Rules: {count}"]
    if total: h.append(f"! Total Block Rules: {total}")
    h.extend(["!", "! --- LINKS ---", links_str, "!", "! --- SOURCES ---"])
    for c in ['whitelist', 'blocklist']:
        h.append(f"! [{c.upper()}]")
        for s in config.get(c, []): h.append(f"! - {s}")
    return "\n".join(h)

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"[!] Không tìm thấy file cấu hình: {CONFIG_FILE}")
        return
        
    with open(CONFIG_FILE) as f: 
        config = json.load(f)
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'AdGuardGen/6.0'})

    # BƯỚC 1: Tải và xử lý trực tiếp
    print("\n--- BÀI TOÁN TẢI DỮ LIỆU ---")
    allow_dict = fetch_data(session, config.get('whitelist', []), 'whitelist')
    block_dict = fetch_data(session, config.get('blocklist', []), 'blocklist')

    # BƯỚC 2: Loại bỏ xung đột (Whitelist đè Blocklist)
    print("\n--- XỬ LÝ XUNG ĐỘT ---")
    allow_keys = set(allow_dict.keys())
    initial_block_count = len(block_dict)
    
    # Chỉ giữ lại những block rule nào có domain KHÔNG nằm trong whitelist
    final_block_dict = {k: v for k, v in block_dict.items() if k not in allow_keys}
    removed_count = initial_block_count - len(final_block_dict)

    final_allow = sorted(list(allow_dict.values()))
    final_block = sorted(list(final_block_dict.values()))

    print(f"-> Tổng Whitelist: {len(final_allow)} rule.")
    print(f"-> Đã loại bỏ {removed_count} rule block bị trùng/xung đột.")
    print(f"-> Blocklist sạch còn lại: {len(final_block)} rule.")

    # BƯỚC 3: Xuất file
    print("\n--- XUẤT FILE ---")
    total_parts = math.ceil(len(final_block) / MAX_LINES_PER_FILE) or 1
    links = [f"! > Whitelist: {REPO_BASE_URL}whitelist.txt"]
    for i in range(1, total_parts + 1):
        links.append(f"! > Blocklist Part {i}: {REPO_BASE_URL}filter_{i:03d}.txt")
    links_str = "\n".join(links)

    # Ghi file Whitelist
    with open(os.path.join(OUTPUT_DIR, 'whitelist.txt'), 'w', encoding='utf-8') as f:
        f.write(generate_header("Final Whitelist", len(final_allow), None, config, links_str))
        f.write("\n! " + "="*50 + "\n" + '\n'.join(final_allow))

    # Ghi các file Blocklist
    for i in range(0, len(final_block), MAX_LINES_PER_FILE):
        p_idx = (i // MAX_LINES_PER_FILE) + 1
        chunk = final_block[i : i + MAX_LINES_PER_FILE]
        fname = f"filter_{p_idx:03d}.txt"
        with open(os.path.join(OUTPUT_DIR, fname), 'w', encoding='utf-8') as f:
            f.write(generate_header(f"Blocklist Part {p_idx}", len(chunk), len(final_block), config, links_str))
            f.write("\n! " + "="*50 + "\n" + '\n'.join(chunk))
            
    print(f"\n[ THÀNH CÔNG ] Kết quả tại thư mục /{OUTPUT_DIR}")

if __name__ == "__main__":
    main()
    
