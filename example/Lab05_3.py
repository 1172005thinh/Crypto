from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import json
import base64


class DigitalSignature:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.des_key = None
    
    def generate_rsa_keys(self, key_size=2048):
        """Tạo cặp khóa RSA"""
        print(f"Tạo cặp khóa RSA {key_size} bits...")
        key_pair = RSA.generate(key_size)
        self.private_key = key_pair
        self.public_key = key_pair.publickey()
        print("Tạo khóa thành công!")
    
    def save_rsa_keys(self, base_filename):
        """Lưu khóa RSA vào file"""
        with open(f"{base_filename}.key", 'wb') as f:
            f.write(self.private_key.export_key('PEM'))
        with open(f"{base_filename}.pub", 'wb') as f:
            f.write(self.public_key.export_key('PEM'))
        print(f"Đã lưu khóa RSA:")
        print(f"  Private: {base_filename}.key")
        print(f"  Public: {base_filename}.pub")
    
    def load_private_key(self, filename):
        """Tải private key từ file"""
        with open(filename, 'rb') as f:
            self.private_key = RSA.import_key(f.read())
        print(f"Đã tải private key từ {filename}")
    
    def load_public_key(self, filename):
        """Tải public key từ file"""
        with open(filename, 'rb') as f:
            self.public_key = RSA.import_key(f.read())
        print(f"Đã tải public key từ {filename}")
    
    def set_des_key(self, key):
        """
        Thiết lập khóa DES (8 bytes)
        Giả sử khóa này đã được chia sẻ giữa bên gửi và bên nhận
        """
        if isinstance(key, str):
            key = key.encode()
        if len(key) != 8:
            raise ValueError("DES key phải có độ dài 8 bytes")
        self.des_key = key
    
    def sign(self, data):
        """
        Ký trên một thông điệp bằng SHA1withRSA
        
        Args:
            data: Dữ liệu cần ký (string hoặc bytes)
        
        Returns:
            signature: Chữ ký số (bytes)
        """
        if self.private_key is None:
            raise ValueError("Chưa có private key!")
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        hash_obj = SHA1.new(data)
        
        signature = pkcs1_15.new(self.private_key).sign(hash_obj)
        
        print(f"Đã ký thông điệp (độ dài: {len(data)} bytes)")
        print(f"Chữ ký (độ dài: {len(signature)} bytes)")
        
        return signature
    
    def verify_signature(self, data, signature):
        if self.public_key is None:
            raise ValueError("Chưa có public key!")
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        hash_obj = SHA1.new(data)
        
        try:
            pkcs1_15.new(self.public_key).verify(hash_obj, signature)
            print("✓ Chữ ký hợp lệ!")
            return True
        except (ValueError, TypeError):
            print("✗ Chữ ký không hợp lệ!")
            return False
    
    def sign_and_encrypt(self, data, output_file):
        if self.private_key is None:
            raise ValueError("Chưa có private key!")
        if self.des_key is None:
            raise ValueError("Chưa thiết lập DES key!")
        
        print("\n=== SIGN AND ENCRYPT ===")
        
        # Chuyển data thành bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Bước 1: Ký dữ liệu
        print("Bước 1: Ký dữ liệu...")
        signature = self.sign(data)
        
        # Bước 2: Tạo gói dữ liệu (data + signature)
        print("Bước 2: Tạo gói dữ liệu...")
        package = {
            'data_length': len(data),
            'signature_length': len(signature),
            'data': base64.b64encode(data).decode('utf-8'),
            'signature': base64.b64encode(signature).decode('utf-8')
        }
        package_json = json.dumps(package)
        package_bytes = package_json.encode('utf-8')
        
        # Bước 3: Mã hóa toàn bộ bằng DES
        print("Bước 3: Mã hóa toàn bộ bằng DES...")
        cipher = DES.new(self.des_key, DES.MODE_CBC)
        iv = cipher.iv
        
        # Padding và mã hóa
        padded_data = pad(package_bytes, DES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        # Lưu vào file (IV + ciphertext)
        with open(output_file, 'wb') as f:
            f.write(iv)
            f.write(ciphertext)
        
        print(f"✓ Đã ký và mã hóa, lưu vào {output_file}")
        print(f"  - Dữ liệu gốc: {len(data)} bytes")
        print(f"  - Chữ ký: {len(signature)} bytes")
        print(f"  - File mã hóa: {len(iv) + len(ciphertext)} bytes")
        
        return {
            'data_length': len(data),
            'signature_length': len(signature),
            'encrypted_length': len(iv) + len(ciphertext)
        }
    
    def decrypt_and_verify(self, input_file):
        if self.public_key is None:
            raise ValueError("Chưa có public key!")
        if self.des_key is None:
            raise ValueError("Chưa thiết lập DES key!")
        
        print("\n=== DECRYPT AND VERIFY ===")
        
        # Bước 1: Đọc file và giải mã bằng DES
        print("Bước 1: Giải mã bằng DES...")
        with open(input_file, 'rb') as f:
            iv = f.read(8)
            ciphertext = f.read()
        
        cipher = DES.new(self.des_key, DES.MODE_CBC, iv=iv)
        padded_data = cipher.decrypt(ciphertext)
        package_bytes = unpad(padded_data, DES.block_size)
        
        # Bước 2: Parse JSON để lấy data và signature
        print("Bước 2: Trích xuất dữ liệu và chữ ký...")
        package_json = package_bytes.decode('utf-8')
        package = json.loads(package_json)
        
        data = base64.b64decode(package['data'])
        signature = base64.b64decode(package['signature'])
        
        print(f"  - Dữ liệu: {len(data)} bytes")
        print(f"  - Chữ ký: {len(signature)} bytes")
        
        # Bước 3: Xác minh chữ ký
        print("Bước 3: Xác minh chữ ký...")
        is_valid = self.verify_signature(data, signature)
        
        return data, is_valid


def demo_basic_sign_verify():
    """Demo cơ bản về ký và xác minh"""
    print("\n" + "=" * 60)
    print("DEMO: KÝ VÀ XÁC MINH CHỮ KÝ SỐ")
    print("=" * 60)
    
    ds = DigitalSignature()
    
    # Tạo khóa
    ds.generate_rsa_keys(2048)
    
    # Thông điệp cần ký
    message = "Đây là thông điệp cần được ký và xác minh!"
    print(f"\nThông điệp: {message}")
    
    # Ký thông điệp
    print("\n--- Ký thông điệp ---")
    signature = ds.sign(message)
    
    # Xác minh chữ ký (đúng)
    print("\n--- Xác minh chữ ký (thông điệp gốc) ---")
    ds.verify_signature(message, signature)
    
    # Xác minh chữ ký (sai - thông điệp bị sửa)
    print("\n--- Xác minh chữ ký (thông điệp bị sửa) ---")
    tampered_message = "Đây là thông điệp ĐÃ BỊ SỬA ĐỔI!"
    ds.verify_signature(tampered_message, signature)


def demo_sign_and_encrypt():
    """Demo ký và mã hóa toàn bộ"""
    print("\n" + "=" * 60)
    print("DEMO: KÝ VÀ MÃ HÓA TOÀN BỘ")
    print("=" * 60)
    
    # Bên gửi
    print("\n--- BÊN GỬI ---")
    sender = DigitalSignature()
    sender.generate_rsa_keys(2048)
    sender.set_des_key("sharedKY")  # Khóa DES đã chia sẻ
    
    message = "Thông điệp bí mật cần được bảo mật và xác thực!"
    print(f"Thông điệp: {message}")
    
    # Ký và mã hóa
    sender.sign_and_encrypt(message, "encrypted_message.bin")
    
    # Bên nhận
    print("\n--- BÊN NHẬN ---")
    receiver = DigitalSignature()
    receiver.public_key = sender.public_key  # Nhận public key từ bên gửi
    receiver.set_des_key("sharedKY")  # Khóa DES đã chia sẻ
    
    # Giải mã và xác minh
    data, is_valid = receiver.decrypt_and_verify("encrypted_message.bin")
    
    print(f"\n--- KẾT QUẢ ---")
    print(f"Dữ liệu nhận được: {data.decode('utf-8')}")
    print(f"Chữ ký hợp lệ: {is_valid}")
    
    # Dọn dẹp
    os.remove("encrypted_message.bin")


def main():
    print("=" * 60)
    print("CHƯƠNG TRÌNH KÝ VÀ XÁC MINH CHỮ KÝ SỐ")
    print("=" * 60)
    
    print("\nChọn chức năng:")
    print("1. Tạo cặp khóa RSA")
    print("2. Ký thông điệp")
    print("3. Xác minh chữ ký")
    print("4. Ký và mã hóa toàn bộ (signAndEncrypt)")
    print("5. Giải mã và xác minh (decryptAndVerify)")
    print("6. Demo cơ bản")
    print("7. Demo ký và mã hóa")
    
    choice = input("\nLựa chọn (1-7): ").strip()
    
    ds = DigitalSignature()
    
    if choice == '1':
        # Tạo khóa
        key_size = input("Nhập kích thước khóa (mặc định 2048): ").strip()
        key_size = int(key_size) if key_size else 2048
        
        ds.generate_rsa_keys(key_size)
        
        base_name = input("Nhập tên cơ sở cho file khóa: ").strip()
        if not base_name:
            base_name = "signature_key"
        
        ds.save_rsa_keys(base_name)
    
    elif choice == '2':
        # Ký thông điệp
        priv_key = input("Nhập tên file private key: ").strip()
        if not os.path.exists(priv_key):
            print(f"File {priv_key} không tồn tại!")
            return
        
        ds.load_private_key(priv_key)
        
        message = input("Nhập thông điệp cần ký: ").strip()
        signature = ds.sign(message)
        
        # Lưu chữ ký
        sig_file = input("Nhập tên file lưu chữ ký (mặc định: signature.bin): ").strip()
        if not sig_file:
            sig_file = "signature.bin"
        
        with open(sig_file, 'wb') as f:
            f.write(signature)
        print(f"Đã lưu chữ ký vào {sig_file}")
    
    elif choice == '3':
        # Xác minh chữ ký
        pub_key = input("Nhập tên file public key: ").strip()
        if not os.path.exists(pub_key):
            print(f"File {pub_key} không tồn tại!")
            return
        
        ds.load_public_key(pub_key)
        
        message = input("Nhập thông điệp gốc: ").strip()
        
        sig_file = input("Nhập tên file chứa chữ ký: ").strip()
        if not os.path.exists(sig_file):
            print(f"File {sig_file} không tồn tại!")
            return
        
        with open(sig_file, 'rb') as f:
            signature = f.read()
        
        ds.verify_signature(message, signature)
    
    elif choice == '4':
        # Ký và mã hóa
        priv_key = input("Nhập tên file private key: ").strip()
        if not os.path.exists(priv_key):
            print(f"File {priv_key} không tồn tại!")
            return
        
        ds.load_private_key(priv_key)
        
        des_key = input("Nhập khóa DES (8 ký tự): ").strip()
        if len(des_key) != 8:
            print("Khóa DES phải có độ dài 8 ký tự!")
            return
        
        ds.set_des_key(des_key)
        
        message = input("Nhập thông điệp: ").strip()
        output = input("Nhập tên file đầu ra (mặc định: encrypted.bin): ").strip()
        if not output:
            output = "encrypted.bin"
        
        ds.sign_and_encrypt(message, output)
    
    elif choice == '5':
        # Giải mã và xác minh
        pub_key = input("Nhập tên file public key: ").strip()
        if not os.path.exists(pub_key):
            print(f"File {pub_key} không tồn tại!")
            return
        
        ds.load_public_key(pub_key)
        
        des_key = input("Nhập khóa DES (8 ký tự): ").strip()
        if len(des_key) != 8:
            print("Khóa DES phải có độ dài 8 ký tự!")
            return
        
        ds.set_des_key(des_key)
        
        input_file = input("Nhập tên file cần giải mã: ").strip()
        if not os.path.exists(input_file):
            print(f"File {input_file} không tồn tại!")
            return
        
        data, is_valid = ds.decrypt_and_verify(input_file)
        
        print(f"\n--- KẾT QUẢ ---")
        print(f"Dữ liệu: {data.decode('utf-8')}")
        print(f"Chữ ký hợp lệ: {is_valid}")
    
    elif choice == '6':
        demo_basic_sign_verify()
    
    elif choice == '7':
        demo_sign_and_encrypt()
    
    else:
        print("Lựa chọn không hợp lệ!")


if __name__ == "__main__":
    main()
