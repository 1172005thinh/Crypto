from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import time
import os
import sys

class DESFileEncryption:
    def __init__(self, key):
        if len(key) != 8:
            raise ValueError("DES key phải có độ dài 8 bytes")
        self.key = key.encode() if isinstance(key, str) else key
    
    def encrypt_file(self, input_file, output_file, mode='ECB', padding='PKCS5'):
        start_time = time.time()
        
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        if mode == 'ECB':
            cipher = DES.new(self.key, DES.MODE_ECB)
            iv = None
        elif mode == 'CBC':
            cipher = DES.new(self.key, DES.MODE_CBC)
            iv = cipher.iv
        else:
            raise ValueError("Mode phải là ECB hoặc CBC")
       
        if padding == 'PKCS5':
            plaintext = pad(plaintext, DES.block_size)
        elif padding == 'NoPadding':
            
            if len(plaintext) % DES.block_size != 0:
                raise ValueError("Với NoPadding, dữ liệu phải là bội số của 8 bytes")
        else:
            raise ValueError("Padding phải là PKCS5 hoặc NoPadding")
        
       
        ciphertext = cipher.encrypt(plaintext)
        
        with open(output_file, 'wb') as f:
            if mode == 'CBC':
                f.write(iv)
            f.write(ciphertext)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        file_size = os.path.getsize(input_file)
        print(f"Mã hóa thành công!")
        print(f"Mode: DES/{mode}/{padding}")
        print(f"Kích thước file: {file_size / (1024*1024):.2f} MB")
        print(f"Thời gian mã hóa: {elapsed:.4f} giây")
        print(f"Tốc độ: {(file_size / (1024*1024)) / elapsed:.2f} MB/s")
        
        return elapsed
    
    def decrypt_file(self, input_file, output_file, mode='ECB', padding='PKCS5'):
        start_time = time.time()
        
        with open(input_file, 'rb') as f:
            data = f.read()
        
        if mode == 'ECB':
            cipher = DES.new(self.key, DES.MODE_ECB)
            ciphertext = data
        elif mode == 'CBC':
            iv = data[:8]
            ciphertext = data[8:]
            cipher = DES.new(self.key, DES.MODE_CBC, iv=iv)
        else:
            raise ValueError("Mode phải là ECB hoặc CBC")
        
        plaintext = cipher.decrypt(ciphertext)
        
        if padding == 'PKCS5':
            plaintext = unpad(plaintext, DES.block_size)
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        file_size = os.path.getsize(output_file)
        print(f"Giải mã thành công!")
        print(f"Mode: DES/{mode}/{padding}")
        print(f"Kích thước file: {file_size / (1024*1024):.2f} MB")
        print(f"Thời gian giải mã: {elapsed:.4f} giây")
        print(f"Tốc độ: {(file_size / (1024*1024)) / elapsed:.2f} MB/s")
        
        return elapsed


def main():
    print("=" * 60)
    print("CHƯƠNG TRÌNH MÃ HÓA/GIẢI MÃ TẬP TIN VỚI DES")
    print("=" * 60)
    
    action = input("\nChọn hành động (1-Mã hóa, 2-Giải mã): ").strip()
    
    if action not in ['1', '2']:
        print("Lựa chọn không hợp lệ!")
        return
    
    input_file = input("Nhập tên file đầu vào: ").strip()
    
    if not os.path.exists(input_file):
        print(f"File {input_file} không tồn tại!")
        return
    
    key_file = input("Nhập tên file chứa khóa (hoặc Enter để nhập khóa trực tiếp): ").strip()
    
    if key_file and os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()[:8]
    else:
        key_input = input("Nhập khóa (8 ký tự): ").strip()
        if len(key_input) != 8:
            print("Khóa phải có độ dài 8 ký tự!")
            return
        key = key_input
    
    print("\nChế độ mã hóa:")
    print("1. DES/ECB/PKCS5Padding")
    print("2. DES/ECB/NoPadding")
    print("3. DES/CBC/PKCS5Padding")
    print("4. DES/CBC/NoPadding")
    mode_choice = input("Chọn chế độ (1-4): ").strip()
    
    mode_map = {
        '1': ('ECB', 'PKCS5'),
        '2': ('ECB', 'NoPadding'),
        '3': ('CBC', 'PKCS5'),
        '4': ('CBC', 'NoPadding')
    }
    
    if mode_choice not in mode_map:
        print("Lựa chọn không hợp lệ!")
        return
    
    mode, padding = mode_map[mode_choice]
    
    des = DESFileEncryption(key)
    
    try:
        if action == '1':
            # Encode
            output_file = "output.enc"
            des.encrypt_file(input_file, output_file, mode, padding)
            print(f"\nFile đã được mã hóa và lưu vào: {output_file}")
        else:
            # Decode
            output_file = "output.dec"
            des.decrypt_file(input_file, output_file, mode, padding)
            print(f"\nFile đã được giải mã và lưu vào: {output_file}")
    
    except Exception as e:
        print(f"\nLỗi: {str(e)}")
        import traceback
        traceback.print_exc()


def test_performance():
    print("\n" + "=" * 60)
    print("TEST HIỆU NĂNG VỚI CÁC FILE KHÁC NHAU")
    print("=" * 60)
    
    key = "abcdEFGH"
    des = DESFileEncryption(key)
    
    test_files = {
        "10MB": "test_10mb.bin",
        "100MB": "test_100mb.bin",
        "1GB": "test_1gb.bin"
    }
    
    modes = [
        ('ECB', 'PKCS5'),
        ('ECB', 'NoPadding'),
        ('CBC', 'PKCS5'),
        ('CBC', 'NoPadding')
    ]
    
    for size_name, filename in test_files.items():
        if not os.path.exists(filename):
            print(f"\nTạo file test {size_name}...")
            size_bytes = {'10MB': 10*1024*1024, '100MB': 100*1024*1024, '1GB': 1024*1024*1024}
            with open(filename, 'wb') as f:
                chunk_size = 1024 * 1024  # 1MB
                for _ in range(size_bytes[size_name] // chunk_size):
                    f.write(os.urandom(chunk_size))
    
    results = []
    for size_name, filename in test_files.items():
        if not os.path.exists(filename):
            print(f"\nBỏ qua {size_name}: File không tồn tại")
            continue
        
        print(f"\n{'=' * 60}")
        print(f"Test với file {size_name}")
        print(f"{'=' * 60}")
        
        for mode, padding in modes:
            print(f"\n--- Mode: DES/{mode}/{padding} ---")
            try:
                enc_time = des.encrypt_file(filename, "temp.enc", mode, padding)
                dec_time = des.decrypt_file("temp.enc", "temp.dec", mode, padding)
                
                results.append({
                    'size': size_name,
                    'mode': f"{mode}/{padding}",
                    'enc_time': enc_time,
                    'dec_time': dec_time
                })
                
                os.remove("temp.enc")
                os.remove("temp.dec")
            except Exception as e:
                print(f"Lỗi: {str(e)}")
    
    print("\n" + "=" * 60)
    print("TỔNG KẾT KẾT QUẢ")
    print("=" * 60)
    for r in results:
        print(f"\n{r['size']} - {r['mode']}:")
        print(f"  Mã hóa: {r['enc_time']:.4f}s")
        print(f"  Giải mã: {r['dec_time']:.4f}s")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        test_performance()
    else:
        main()
