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
BACKUP_DIR = 'backup'
MAX_LINES_PER_FILE = 500_000
REPO_BASE_URL = "https://raw.githubusercontent.com/hoafd/adguard_filters/main/output/"

# 1. Dọn dẹp thư mục OUTPUT
if os.path.exists(OUTPUT_DIR): shutil.rmtree(OUTPUT_DIR)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 2. Tạo cấu trúc BACKUP (Chỉ còn whitelist và blocklist)
for category in ['whitelist', 'blocklist']:
    os.makedirs(os.path.join(BACKUP_DIR, category), exist_ok=True)

def url_to_filename(url):
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url)
    return safe_name + ".txt"

def get_base_rule(rule):
    """
    Tạo ra 'Key ảo' (Rule gốc) để đối chiếu bằng cách ẩn đi tham số 'important'.
    Hàm này KHÔNG làm thay đổi rule thật, chỉ dùng để lấy Key.
    """
    if 'important' not in rule:
        return rule
        
    parts = rule.split('$', 1)
    if len(parts) == 1:
        return rule
    
    domain, options = parts[0], parts[1]
    opt_list = [o.strip() for o in options.split(',')]
    
    # Lọc bỏ 'important' để lấy key
    opt_list = [o for o in opt_list if o != 'important']
    
    if not opt_list:
        return domain
    return f"{domain}${','.join(opt_list)}"

def process_content(content, data_dict, is_whitelist):
    """
    Nạp dữ liệu vào từ điển chung (data_dict).
    Giữ nguyên 100% text của tác giả, chỉ thay đổi khi có xung đột theo đúng rule ưu tiên.
    """
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('!', '#')): continue
        if not is_whitelist and line.startswith('@@'): continue

        base_rule = get_base_rule(line)
        
        # Nhận biết dòng này gốc của tác giả có important hay không
        # Bằng cách xem nó có bị biến đổi khi lấy base_rule không
        has_important = (line != base_rule)

        if base_rule not in data_dict:
            # Chưa từng có -> Lưu thẳng bản gốc của tác giả vào
            data_dict[base_rule] = line
        else:
            # Đã tồn tại -> Xử lý tranh chấp
            current_line = data_dict[base_rule]
            current_has_important = (current_line != base_rule)

            if is_whitelist:
                # Ở Whitelist: Ưu tiên lấy cái CÓ $important
                # Nếu dòng mới CÓ, mà dòng đang giữ KHÔNG CÓ -> Đổi sang dòng mới
                if has_important and not current_has_important:
                    data_dict[base_rule] = line
            else:
                # Ở Blocklist: Ưu tiên lấy cái KHÔNG CÓ $important
                # Nếu dòng mới KHÔNG CÓ, mà dòng đang giữ lại CÓ -> Đổi sang dòng mới
                if not has_important and current_has_important:
                    data_dict[base_rule] = line

def fetch_data(url_list, category):
    data_dict = {}
    is_wl = (category == 'whitelist')
    
    for url in url_list:
        filename = url_to_filename(url)
        backup_path = os.path.join(BACKUP_DIR, category, filename)
        
        print(f"[*] [{category.upper()}] Xử lý: {url[:50]}...")
        content = ""
        
        try:
            fetch_url = url
            if "raw.githubusercontent.com" in url:
                fetch_url = f"{url}?t={int(datetime.now().timestamp())}"
                
            r = requests.get(fetch_url, headers={'User-Agent': 'AdGuardGen/3.0', 'Cache-Control': 'no-cache'}, timeout=20)
            if r.status_code == 200:
                content = r.text
                with open(backup_path, 'w', encoding='utf-8') as f: 
                    f.write(content)
            else:
                raise Exception(f"HTTP {r.status_code}")
        except Exception as e:
            print(f"   -> [!] Lỗi tải, dùng backup: {e}")
            if os.path.exists(backup_path):
                with open(backup_path, 'r', encoding='utf-8') as f: 
                    content = f.read()
        
        if content:
            # Gửi thẳng data_dict vào hàm để cập nhật liên tục qua từng file
            process_content(content, data_dict, is_whitelist=is_wl)
                    
    return data_dict

def generate_header(title, updated_time, count, total_count, config, generated_links_text):
    lines = [
        f"! Title: {title}",
        f"! Updated: {updated_time}",
        f"! Rules in this file: {count}"
    ]
    if total_count: lines.append(f"! Total Block Rules (All parts): {total_count}")
    lines.extend([
        "!",
        "! --- YOUR FILTER LINKS ---",
        generated_links_text,
        "!",
        "! --- SOURCES USED ---"
    ])
    lines.append("! [WHITELIST SOURCES]")
    for url in config.get('whitelist', []): lines.append(f"! - {url}")
    lines.append("! [BLOCKLIST SOURCES]")
    for url in config.get('blocklist', []): lines.append(f"! - {url}")
    return "\n".join(lines)

def main():
    if not os.path.exists(CONFIG_FILE): 
        print(f"[!] Không tìm thấy file {CONFIG_FILE}.")
        return
        
    with open(CONFIG_FILE) as f: config = json.load(f)

    print("\n--- BƯỚC 1: TẢI & SAO LƯU DỮ LIỆU ---")
    
    allow_dict = fetch_data(config.get('whitelist', []), 'whitelist')
    block_dict = fetch_data(config.get('blocklist', []), 'blocklist')

    print("\n--- BƯỚC 2: XỬ LÝ LOGIC ---")
    
    # Lọc 100%: Dùng Key ảo (base_rule) để kiểm tra. Nếu Key nằm trong cả Whitelist và Blocklist -> Xóa khỏi Blocklist
    domains_to_remove = []
    for base_rule in block_dict.keys():
        if base_rule in allow_dict:
            domains_to_remove.append(base_rule)

    for br in domains_to_remove:
        del block_dict[br]

    # Xuất ra mảng từ values() -> Đảm bảo 100% nguyên trạng text tác giả
    final_allow = list(allow_dict.values())
    final_block = list(block_dict.values())

    print(f"   -> Đã tổng hợp {len(final_allow)} rule Whitelist.")
    print(f"   -> Đã gỡ bỏ {len(domains_to_remove)} rule khỏi Blocklist vì xung đột 100% với Whitelist.")
    print(f"   -> Tổng hợp được {len(final_block)} rule Blocklist sẵn sàng xuất xưởng.")
    
    print("\n--- BƯỚC 3: XUẤT FILE ---")
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    final_block.sort() 
    final_allow.sort()
    
    total_parts = math.ceil(len(final_block) / MAX_LINES_PER_FILE)
    if total_parts == 0: total_parts = 1
    
    links_text = [f"! > Whitelist: {REPO_BASE_URL}whitelist.txt"]
    for i in range(1, total_parts + 1):
        links_text.append(f"! > Blocklist Part {i}: {REPO_BASE_URL}filter_{i:03d}.txt")
    generated_links_str = "\n".join(links_text)

    # Xuất Whitelist
    with open(os.path.join(OUTPUT_DIR, 'whitelist.txt'), 'w', encoding='utf-8') as f:
        header = generate_header("My Final Whitelist", timestamp, len(final_allow), None, config, generated_links_str)
        f.write(header + "\n! ---------------------------------------------------\n")
        f.write('\n'.join(final_allow))

    # Xuất Blocklist Parts
    for i in range(0, len(final_block), MAX_LINES_PER_FILE):
        part_num = (i // MAX_LINES_PER_FILE) + 1
        chunk = final_block[i : i + MAX_LINES_PER_FILE]
        filename = f"filter_{part_num:03d}.txt"
        with open(os.path.join(OUTPUT_DIR, filename), 'w', encoding='utf-8') as f:
            header = generate_header(f"My Blocklist Part {part_num}", timestamp, len(chunk), len(final_block), config, generated_links_str)
            f.write(header + "\n! ---------------------------------------------------\n")
            f.write('\n'.join(chunk))
            
    print(f"   -> Hoàn thành xuất 1 file Whitelist và {total_parts} file Blocklist.")

if __name__ == "__main__":
    main()

