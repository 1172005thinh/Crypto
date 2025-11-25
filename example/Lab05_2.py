"""
Lab05_2.py - Mã hóa/Giải mã tập tin với RSA
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time
import os
import sys

class RSAFileEncryption:
    def __init__(self):
        self.key_pair = None
        self.public_key = None
        self.private_key = None
    
    def generate_keys(self, key_size=2048):
        print(f"Đang tạo cặp khóa RSA {key_size} bits...")
        start = time.time()
        self.key_pair = RSA.generate(key_size)
        print(f"Tạo khóa hoàn tất trong {time.time() - start:.2f} giây")
        
        self.private_key = self.key_pair
        self.public_key = self.key_pair.publickey()
    
    def save_keys(self, base_filename):
        with open(f"{base_filename}.key", 'wb') as f:
            f.write(self.private_key.export_key('DER'))
        

        with open(f"{base_filename}.pub", 'wb') as f:
            f.write(self.public_key.export_key('DER'))
        
        print(f"Đã lưu khóa:")
        print(f"  Private key: {base_filename}.key")
        print(f"  Public key: {base_filename}.pub")
    
    def load_public_key(self, filename):
        """
        Tải public key từ file
        """
        with open(filename, 'rb') as f:
            key_data = f.read()
        self.public_key = RSA.import_key(key_data)
        print(f"Đã tải public key từ {filename}")
    
    def load_private_key(self, filename):
        """
        Tải private key từ file
        """
        with open(filename, 'rb') as f:
            key_data = f.read()
        self.private_key = RSA.import_key(key_data)
        print(f"Đã tải private key từ {filename}")
    
    def encrypt_file(self, input_file, output_file):
        """
        Mã hóa tập tin với RSA
        RSA chỉ có thể mã hóa dữ liệu nhỏ, nên sẽ chia file thành các block
        
        Args:
            input_file: File đầu vào
            output_file: File đầu ra (đã mã hóa)
        """
        if self.public_key is None:
            raise ValueError("Chưa có public key. Hãy tạo hoặc tải khóa trước.")
        
        start_time = time.time()
        cipher = PKCS1_OAEP.new(self.public_key)
        key_size_bytes = self.public_key.size_in_bytes()
        max_block_size = key_size_bytes - 2*20 - 2 
        
        print(f"Kích thước block mã hóa: {max_block_size} bytes")
        
        with open(input_file, 'rb') as f_in:
            with open(output_file, 'wb') as f_out:
                block_count = 0
                while True:
                    block = f_in.read(max_block_size)
                    if not block:
                        break
                    encrypted_block = cipher.encrypt(block)
                    
                    block_size = len(encrypted_block)
                    f_out.write(block_size.to_bytes(2, byteorder='big'))
                    f_out.write(encrypted_block)
                    
                    block_count += 1
                    if block_count % 100 == 0:
                        print(f"Đã mã hóa {block_count} blocks...")
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        file_size = os.path.getsize(input_file)
        print(f"\nMã hóa thành công!")
        print(f"Số blocks: {block_count}")
        print(f"Kích thước file gốc: {file_size / (1024*1024):.2f} MB")
        print(f"Kích thước file mã hóa: {os.path.getsize(output_file) / (1024*1024):.2f} MB")
        print(f"Thời gian mã hóa: {elapsed:.4f} giây")
        
        if file_size > 0:
            print(f"Tốc độ: {(file_size / (1024*1024)) / elapsed:.2f} MB/s")
        
        return elapsed
    
    def decrypt_file(self, input_file, output_file):
        """
        Giải mã tập tin với RSA
        
        Args:
            input_file: File đầu vào (đã mã hóa)
            output_file: File đầu ra (giải mã)
        """
        if self.private_key is None:
            raise ValueError("Chưa có private key. Hãy tạo hoặc tải khóa trước.")
        
        start_time = time.time()
        cipher = PKCS1_OAEP.new(self.private_key)
        
        with open(input_file, 'rb') as f_in:
            with open(output_file, 'wb') as f_out:
                block_count = 0
                while True:
                    
                    size_bytes = f_in.read(2)
                    if not size_bytes:
                        break
                    
                    block_size = int.from_bytes(size_bytes, byteorder='big')
                    encrypted_block = f_in.read(block_size)
                    if not encrypted_block:
                        break
                    
                    decrypted_block = cipher.decrypt(encrypted_block)
                    f_out.write(decrypted_block)
                    
                    block_count += 1
                    if block_count % 100 == 0:
                        print(f"Đã giải mã {block_count} blocks...")
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        file_size = os.path.getsize(output_file)
        print(f"\nGiải mã thành công!")
        print(f"Số blocks: {block_count}")
        print(f"Kích thước file: {file_size / (1024*1024):.2f} MB")
        print(f"Thời gian giải mã: {elapsed:.4f} giây")
        
        if file_size > 0:
            print(f"Tốc độ: {(file_size / (1024*1024)) / elapsed:.2f} MB/s")
        
        return elapsed


def main():
    print("=" * 60)
    print("CHƯƠNG TRÌNH MÃ HÓA/GIẢI MÃ TẬP TIN VỚI RSA")
    print("=" * 60)
    
    rsa = RSAFileEncryption()
    
    print("\nChọn chức năng:")
    print("1. Tạo cặp khóa mới")
    print("2. Mã hóa file")
    print("3. Giải mã file")
    print("4. Test hiệu năng (so sánh RSA vs DES)")
    
    choice = input("\nLựa chọn (1-4): ").strip()
    
    if choice == '1':
        # Tạo khóa
        key_size = input("Nhập kích thước khóa (mặc định 2048): ").strip()
        key_size = int(key_size) if key_size else 2048
        
        rsa.generate_keys(key_size)
        
        base_name = input("Nhập tên cơ sở cho file khóa (vd: mykey): ").strip()
        if not base_name:
            base_name = "rsa_key"
        
        rsa.save_keys(base_name)
    
    elif choice == '2':
        # Mã hóa
        pub_key_file = input("Nhập tên file public key: ").strip()
        if not os.path.exists(pub_key_file):
            print(f"File {pub_key_file} không tồn tại!")
            return
        
        rsa.load_public_key(pub_key_file)
        
        input_file = input("Nhập tên file cần mã hóa: ").strip()
        if not os.path.exists(input_file):
            print(f"File {input_file} không tồn tại!")
            return
        
        output_file = input("Nhập tên file đầu ra (mặc định: output.enc): ").strip()
        if not output_file:
            output_file = "output.enc"
        
        try:
            rsa.encrypt_file(input_file, output_file)
            print(f"\nĐã lưu file mã hóa vào: {output_file}")
        except Exception as e:
            print(f"Lỗi: {str(e)}")
            import traceback
            traceback.print_exc()
    
    elif choice == '3':
        # Giải mã
        priv_key_file = input("Nhập tên file private key: ").strip()
        if not os.path.exists(priv_key_file):
            print(f"File {priv_key_file} không tồn tại!")
            return
        
        rsa.load_private_key(priv_key_file)
        
        input_file = input("Nhập tên file cần giải mã: ").strip()
        if not os.path.exists(input_file):
            print(f"File {input_file} không tồn tại!")
            return
        
        output_file = input("Nhập tên file đầu ra (mặc định: output.dec): ").strip()
        if not output_file:
            output_file = "output.dec"
        
        try:
            rsa.decrypt_file(input_file, output_file)
            print(f"\nĐã lưu file giải mã vào: {output_file}")
        except Exception as e:
            print(f"Lỗi: {str(e)}")
            import traceback
            traceback.print_exc()
    
    elif choice == '4':
        test_comparison()
    
    else:
        print("Lựa chọn không hợp lệ!")


def test_comparison():
    """
    So sánh hiệu năng RSA vs DES với file 10MB
    """
    print("\n" + "=" * 60)
    print("SO SÁNH HIỆU NĂNG RSA vs DES")
    print("=" * 60)
    
    # Tạo file test 10MB nếu chưa có
    test_file = "test_10mb.bin"
    if not os.path.exists(test_file):
        print(f"\nTạo file test 10MB...")
        with open(test_file, 'wb') as f:
            f.write(os.urandom(10 * 1024 * 1024))
    
    # Test RSA
    print("\n--- TEST RSA ---")
    rsa = RSAFileEncryption()
    rsa.generate_keys(2048)
    
    try:
        rsa_enc_time = rsa.encrypt_file(test_file, "temp_rsa.enc")
        rsa_dec_time = rsa.decrypt_file("temp_rsa.enc", "temp_rsa.dec")
        
        os.remove("temp_rsa.enc")
        os.remove("temp_rsa.dec")
    except Exception as e:
        print(f"Lỗi RSA: {str(e)}")
        rsa_enc_time = rsa_dec_time = 0
    
    # Test DES
    print("\n--- TEST DES ---")
    try:
        from Crypto.Cipher import DES
        from Crypto.Util.Padding import pad, unpad
        
        key = b"abcdEFGH"
        
        # Mã hóa DES
        start = time.time()
        with open(test_file, 'rb') as f:
            plaintext = f.read()
        
        cipher = DES.new(key, DES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
        
        with open("temp_des.enc", 'wb') as f:
            f.write(cipher.iv)
            f.write(ciphertext)
        
        des_enc_time = time.time() - start
        print(f"DES mã hóa: {des_enc_time:.4f} giây")
        
        # Giải mã DES
        start = time.time()
        with open("temp_des.enc", 'rb') as f:
            iv = f.read(8)
            ciphertext = f.read()
        
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        
        with open("temp_des.dec", 'wb') as f:
            f.write(plaintext)
        
        des_dec_time = time.time() - start
        print(f"DES giải mã: {des_dec_time:.4f} giây")
        
        os.remove("temp_des.enc")
        os.remove("temp_des.dec")
    except Exception as e:
        print(f"Lỗi DES: {str(e)}")
        des_enc_time = des_dec_time = 0
    
    # So sánh
    print("\n" + "=" * 60)
    print("KẾT QUẢ SO SÁNH")
    print("=" * 60)
    print(f"\nFile test: 10MB")
    print(f"\nRSA (2048 bits):")
    print(f"  Mã hóa: {rsa_enc_time:.4f}s")
    print(f"  Giải mã: {rsa_dec_time:.4f}s")
    print(f"  Tổng: {rsa_enc_time + rsa_dec_time:.4f}s")
    
    print(f"\nDES (CBC/PKCS5):")
    print(f"  Mã hóa: {des_enc_time:.4f}s")
    print(f"  Giải mã: {des_dec_time:.4f}s")
    print(f"  Tổng: {des_enc_time + des_dec_time:.4f}s")
    
    if rsa_enc_time > 0 and des_enc_time > 0:
        print(f"\nRSA chậm hơn DES:")
        print(f"  Mã hóa: {rsa_enc_time / des_enc_time:.1f}x")
        print(f"  Giải mã: {rsa_dec_time / des_dec_time:.1f}x")


if __name__ == "__main__":
    main()
