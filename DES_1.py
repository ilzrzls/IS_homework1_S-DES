import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import itertools


class SDES:
    """
    S-DES加密算法实现类
    """

    # 定义所有置换盒和S盒
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    P4 = [2, 4, 3, 1]

    S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]

    S1 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]

    @staticmethod
    def permute(bits, permutation):
        """执行置换操作"""
        return [bits[i - 1] for i in permutation]

    @staticmethod
    def left_shift(bits, n):
        """循环左移n位"""
        return bits[n:] + bits[:n]

    @staticmethod
    def generate_keys(key):
        """生成子密钥k1和k2"""
        # P10置换
        p10_key = SDES.permute(key, SDES.P10)

        # 分割并左移1位
        left = SDES.left_shift(p10_key[:5], 1)
        right = SDES.left_shift(p10_key[5:], 1)

        # 生成k1
        k1 = SDES.permute(left + right, SDES.P8)

        # 左移2位
        left = SDES.left_shift(left, 2)
        right = SDES.left_shift(right, 2)

        # 生成k2
        k2 = SDES.permute(left + right, SDES.P8)

        return k1, k2

    @staticmethod
    def xor(bits1, bits2):
        """异或操作"""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    @staticmethod
    def s_box_lookup(bits, s_box):
        """S盒查找"""
        row = bits[0] * 2 + bits[3]
        col = bits[1] * 2 + bits[2]
        value = s_box[row][col]
        return [value >> 1 & 1, value & 1]

    @staticmethod
    def f_function(bits, subkey):
        """轮函数F"""
        # 扩展置换
        expanded = SDES.permute(bits, SDES.EP)

        # 与子密钥异或
        xor_result = SDES.xor(expanded, subkey)

        # S盒替换
        s0_result = SDES.s_box_lookup(xor_result[:4], SDES.S0)
        s1_result = SDES.s_box_lookup(xor_result[4:], SDES.S1)

        # P4置换
        p4_result = SDES.permute(s0_result + s1_result, SDES.P4)

        return p4_result

    @staticmethod
    def encrypt_block(plaintext, key):
        """加密一个8位分组"""
        # 生成子密钥
        k1, k2 = SDES.generate_keys(key)

        # 初始置换
        ip_result = SDES.permute(plaintext, SDES.IP)

        # 第一轮F函数
        left, right = ip_result[:4], ip_result[4:]
        f_result = SDES.f_function(right, k1)
        new_right = SDES.xor(left, f_result)

        # 交换
        left, right = right, new_right

        # 第二轮F函数
        f_result = SDES.f_function(right, k2)
        new_left = SDES.xor(left, f_result)

        # 最终置换
        ciphertext = SDES.permute(new_left + right, SDES.IP_inv)

        return ciphertext

    @staticmethod
    def decrypt_block(ciphertext, key):
        """解密一个8位分组"""
        # 生成子密钥
        k1, k2 = SDES.generate_keys(key)

        # 初始置换
        ip_result = SDES.permute(ciphertext, SDES.IP)

        # 第一轮F函数
        left, right = ip_result[:4], ip_result[4:]
        f_result = SDES.f_function(right, k2)
        new_right = SDES.xor(left, f_result)

        # 交换
        left, right = right, new_right

        # 第二轮F函数
        f_result = SDES.f_function(right, k1)
        new_left = SDES.xor(left, f_result)

        # 最终置换
        plaintext = SDES.permute(new_left + right, SDES.IP_inv)

        return plaintext

    @staticmethod
    def string_to_bits(text):
        """将字符串转换为二进制位列表"""
        bits = []
        for char in text:
            byte = ord(char)
            bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        return bits

    @staticmethod
    def bits_to_string(bits):
        """将二进制位列表转换为字符串"""
        text = ""
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            char_code = sum(bit << (7 - j) for j, bit in enumerate(byte))
            text += chr(char_code)
        return text

    @staticmethod
    def encrypt_string(text, key):
        """加密字符串"""
        # 将密钥转换为10位二进制列表
        if len(key) != 10 or not all(bit in [0, 1] for bit in key):
            raise ValueError("密钥必须是10位二进制列表")

        # 将文本转换为二进制
        text_bits = SDES.string_to_bits(text)

        # 分组加密
        cipher_bits = []
        for i in range(0, len(text_bits), 8):
            block = text_bits[i:i + 8]
            if len(block) < 8:
                # 填充到8位
                block.extend([0] * (8 - len(block)))
            encrypted_block = SDES.encrypt_block(block, key)
            cipher_bits.extend(encrypted_block)

        # 转换为字符串（可能是乱码）
        cipher_text = SDES.bits_to_string(cipher_bits)
        return cipher_text

    @staticmethod
    def decrypt_string(cipher_text, key):
        """解密密文字符串"""
        # 将密钥转换为10位二进制列表
        if len(key) != 10 or not all(bit in [0, 1] for bit in key):
            raise ValueError("密钥必须是10位二进制列表")

        # 将密文转换为二进制
        cipher_bits = SDES.string_to_bits(cipher_text)

        # 分组解密
        plain_bits = []
        for i in range(0, len(cipher_bits), 8):
            block = cipher_bits[i:i + 8]
            decrypted_block = SDES.decrypt_block(block, key)
            plain_bits.extend(decrypted_block)

        # 转换为字符串
        plain_text = SDES.bits_to_string(plain_bits)
        return plain_text.rstrip('\x00')  # 移除填充的null字符


class SDESGUI:
    """
    S-DES算法GUI界面 - 按用途区分功能
    """

    def __init__(self, root):
        self.root = root
        self.root.title("S-DES加密算法工具")
        self.root.geometry("900x700")

        # 创建主框架
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill='both', expand=True)

        # 创建标签页
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True)

        # 创建各个功能标签页
        self.create_binary_operations_tab()
        self.create_text_operations_tab()
        self.create_key_analysis_tab()

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief='sunken')
        status_bar.pack(fill='x', pady=(5, 0))

        self.brute_force_running = False

    def create_binary_operations_tab(self):
        """创建二进制操作标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="二进制加解密")

        # 输入框架
        input_frame = ttk.LabelFrame(tab, text="输入参数", padding="10")
        input_frame.pack(fill='x', padx=5, pady=5)

        # 明文输入
        ttk.Label(input_frame, text="8位二进制数据:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.binary_data_entry = ttk.Entry(input_frame, width=20, font=('Courier', 10))
        self.binary_data_entry.grid(row=0, column=1, padx=5, pady=5)

        # 密钥输入
        ttk.Label(input_frame, text="10位二进制密钥:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.binary_key_entry = ttk.Entry(input_frame, width=20, font=('Courier', 10))
        self.binary_key_entry.grid(row=1, column=1, padx=5, pady=5)

        # 按钮框架
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill='x', padx=5, pady=10)

        ttk.Button(button_frame, text="加密", command=self.encrypt_binary).pack(side='left', padx=5)
        ttk.Button(button_frame, text="解密", command=self.decrypt_binary).pack(side='left', padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_binary).pack(side='left', padx=5)
        ttk.Button(button_frame, text="示例数据", command=self.load_example_binary).pack(side='left', padx=5)

        # 结果显示框架
        result_frame = ttk.LabelFrame(tab, text="加解密结果", padding="10")
        result_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.binary_result_text = scrolledtext.ScrolledText(result_frame, width=80, height=15, font=('Courier', 9))
        self.binary_result_text.pack(fill='both', expand=True)

    def create_text_operations_tab(self):
        """创建文本操作标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="文本加解密")

        # 输入框架
        input_frame = ttk.LabelFrame(tab, text="文本输入", padding="10")
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text="文本内容:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.text_input = scrolledtext.ScrolledText(input_frame, width=60, height=4)
        self.text_input.grid(row=0, column=1, padx=5, pady=5, rowspan=2)

        ttk.Label(input_frame, text="10位二进制密钥:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.text_key_entry = ttk.Entry(input_frame, width=20, font=('Courier', 10))
        self.text_key_entry.grid(row=2, column=1, sticky='w', padx=5, pady=5)

        # 按钮框架
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill='x', padx=5, pady=10)

        ttk.Button(button_frame, text="加密文本", command=self.encrypt_text).pack(side='left', padx=5)
        ttk.Button(button_frame, text="解密文本", command=self.decrypt_text).pack(side='left', padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_text).pack(side='left', padx=5)
        ttk.Button(button_frame, text="示例文本", command=self.load_example_text).pack(side='left', padx=5)

        # 结果显示框架
        result_frame = ttk.LabelFrame(tab, text="加解密结果", padding="10")
        result_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.text_result_text = scrolledtext.ScrolledText(result_frame, width=80, height=12, font=('Courier', 9))
        self.text_result_text.pack(fill='both', expand=True)

    def create_key_analysis_tab(self):
        """创建密钥分析标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="密钥分析")

        # 暴力破解框架
        brute_frame = ttk.LabelFrame(tab, text="暴力破解", padding="10")
        brute_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(brute_frame, text="已知明文:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.known_plaintext = ttk.Entry(brute_frame, width=20, font=('Courier', 10))
        self.known_plaintext.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(brute_frame, text="已知密文:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.known_ciphertext = ttk.Entry(brute_frame, width=20, font=('Courier', 10))
        self.known_ciphertext.grid(row=1, column=1, padx=5, pady=5)

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(brute_frame, variable=self.progress_var, maximum=1024)
        self.progress_bar.grid(row=2, column=0, columnspan=2, sticky='ew', padx=5, pady=5)

        # 暴力破解按钮
        brute_button_frame = ttk.Frame(brute_frame)
        brute_button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(brute_button_frame, text="开始暴力破解", command=self.start_brute_force).pack(side='left', padx=5)
        ttk.Button(brute_button_frame, text="停止破解", command=self.stop_brute_force).pack(side='left', padx=5)
        ttk.Button(brute_button_frame, text="示例数据", command=self.load_example_brute).pack(side='left', padx=5)

        # 密钥冲突分析框架
        analysis_frame = ttk.LabelFrame(tab, text="密钥冲突分析", padding="10")
        analysis_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(analysis_frame, text="分析密钥冲突", command=self.analyze_key_conflicts).pack(pady=5)

        # 结果显示
        result_frame = ttk.LabelFrame(tab, text="分析结果", padding="10")
        result_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.analysis_result_text = scrolledtext.ScrolledText(result_frame, width=80, height=15, font=('Courier', 9))
        self.analysis_result_text.pack(fill='both', expand=True)

    def parse_binary_input(self, input_str, expected_length):
        """解析二进制输入字符串"""
        try:
            if len(input_str) != expected_length:
                raise ValueError(f"长度必须为{expected_length}位")

            bits = []
            for char in input_str:
                if char not in ['0', '1']:
                    raise ValueError("只能包含0和1")
                bits.append(int(char))

            return bits
        except Exception as e:
            messagebox.showerror("输入错误", str(e))
            return None

    def encrypt_binary(self):
        """二进制加密"""
        data = self.binary_data_entry.get()
        key = self.binary_key_entry.get()

        data_bits = self.parse_binary_input(data, 8)
        key_bits = self.parse_binary_input(key, 10)

        if data_bits and key_bits:
            cipher_bits = SDES.encrypt_block(data_bits, key_bits)
            cipher_text = ''.join(str(bit) for bit in cipher_bits)

            result = f"加密操作:\n"
            result += f"明文: {data}\n"
            result += f"密钥: {key}\n"
            result += f"密文: {cipher_text}\n"

            self.binary_result_text.delete(1.0, tk.END)
            self.binary_result_text.insert(tk.END, result)
            self.status_var.set("加密完成")

    def decrypt_binary(self):
        """二进制解密"""
        data = self.binary_data_entry.get()
        key = self.binary_key_entry.get()

        data_bits = self.parse_binary_input(data, 8)
        key_bits = self.parse_binary_input(key, 10)

        if data_bits and key_bits:
            plain_bits = SDES.decrypt_block(data_bits, key_bits)
            plain_text = ''.join(str(bit) for bit in plain_bits)

            result = f"解密操作:\n"
            result += f"密文: {data}\n"
            result += f"密钥: {key}\n"
            result += f"明文: {plain_text}\n"

            self.binary_result_text.delete(1.0, tk.END)
            self.binary_result_text.insert(tk.END, result)
            self.status_var.set("解密完成")

    def clear_binary(self):
        """清空二进制操作区域"""
        self.binary_data_entry.delete(0, tk.END)
        self.binary_key_entry.delete(0, tk.END)
        self.binary_result_text.delete(1.0, tk.END)
        self.status_var.set("已清空")

    def load_example_binary(self):
        """加载二进制示例数据"""
        self.binary_data_entry.delete(0, tk.END)
        self.binary_data_entry.insert(0, "10101010")
        self.binary_key_entry.delete(0, tk.END)
        self.binary_key_entry.insert(0, "1010000010")
        self.status_var.set("示例数据已加载")

    def encrypt_text(self):
        """加密文本"""
        text = self.text_input.get(1.0, tk.END).strip()
        key_str = self.text_key_entry.get()

        if not text:
            messagebox.showerror("错误", "请输入要加密的文本")
            return

        key_bits = self.parse_binary_input(key_str, 10)
        if not key_bits:
            return

        try:
            cipher_text = SDES.encrypt_string(text, key_bits)

            result = f"文本加密结果:\n"
            result += f"原始文本: {text}\n"
            result += f"密钥: {key_str}\n"
            result += f"加密结果: {cipher_text}\n"
            result += f"十六进制: {cipher_text.encode('latin-1').hex()}\n"

            self.text_result_text.delete(1.0, tk.END)
            self.text_result_text.insert(tk.END, result)
            self.status_var.set("文本加密完成")

        except Exception as e:
            messagebox.showerror("加密错误", str(e))

    def decrypt_text(self):
        """解密文本"""
        text = self.text_input.get(1.0, tk.END).strip()
        key_str = self.text_key_entry.get()

        if not text:
            messagebox.showerror("错误", "请输入要解密的文本")
            return

        key_bits = self.parse_binary_input(key_str, 10)
        if not key_bits:
            return

        try:
            plain_text = SDES.decrypt_string(text, key_bits)

            result = f"文本解密结果:\n"
            result += f"密文: {text}\n"
            result += f"密钥: {key_str}\n"
            result += f"解密结果: {plain_text}\n"

            self.text_result_text.delete(1.0, tk.END)
            self.text_result_text.insert(tk.END, result)
            self.status_var.set("文本解密完成")

        except Exception as e:
            messagebox.showerror("解密错误", str(e))

    def clear_text(self):
        """清空文本操作区域"""
        self.text_input.delete(1.0, tk.END)
        self.text_key_entry.delete(0, tk.END)
        self.text_result_text.delete(1.0, tk.END)
        self.status_var.set("已清空")

    def load_example_text(self):
        """加载文本示例数据"""
        self.text_input.delete(1.0, tk.END)
        self.text_input.insert(1.0, "Hello S-DES!")
        self.text_key_entry.delete(0, tk.END)
        self.text_key_entry.insert(0, "1010000010")
        self.status_var.set("示例文本已加载")

    def start_brute_force(self):
        """开始暴力破解"""
        plaintext = self.known_plaintext.get()
        ciphertext = self.known_ciphertext.get()

        plain_bits = self.parse_binary_input(plaintext, 8)
        cipher_bits = self.parse_binary_input(ciphertext, 8)

        if not plain_bits or not cipher_bits:
            return

        self.brute_force_running = True
        self.analysis_result_text.delete(1.0, tk.END)
        self.analysis_result_text.insert(tk.END, "开始暴力破解...\n")
        threading.Thread(target=self.brute_force_worker, args=(plain_bits, cipher_bits)).start()

    def stop_brute_force(self):
        """停止暴力破解"""
        self.brute_force_running = False
        self.status_var.set("暴力破解已停止")

    def load_example_brute(self):
        """加载暴力破解示例数据"""
        self.known_plaintext.delete(0, tk.END)
        self.known_plaintext.insert(0, "10101010")
        self.known_ciphertext.delete(0, tk.END)
        self.known_ciphertext.insert(0, "11000010")
        self.status_var.set("暴力破解示例已加载")

    def brute_force_worker(self, plain_bits, cipher_bits):
        """暴力破解工作线程"""
        start_time = time.time()
        found_keys = []
        total_keys = 1024  # 2^10

        for key_int in range(total_keys):
            if not self.brute_force_running:
                break

            # 生成10位密钥
            key = [(key_int >> i) & 1 for i in range(9, -1, -1)]

            # 尝试加密
            try:
                encrypted = SDES.encrypt_block(plain_bits, key)
                if encrypted == cipher_bits:
                    found_keys.append(''.join(str(bit) for bit in key))
            except:
                pass

            # 更新进度
            self.progress_var.set(key_int + 1)

            # 每处理64个密钥更新一次界面
            if key_int % 64 == 0:
                elapsed = time.time() - start_time
                self.update_brute_force_progress(key_int, total_keys, elapsed, found_keys)

        # 最终更新
        elapsed = time.time() - start_time
        self.finalize_brute_force(total_keys, elapsed, found_keys)

    def update_brute_force_progress(self, current, total, elapsed, found_keys):
        """更新暴力破解进度"""
        if not self.brute_force_running:
            return

        self.root.after(0, lambda: self._update_brute_force_ui(current, total, elapsed, found_keys))

    def _update_brute_force_ui(self, current, total, elapsed, found_keys):
        """更新暴力破解UI"""
        progress_percent = (current / total) * 100

        result_text = f"暴力破解进度: {current}/{total} ({progress_percent:.1f}%)\n"
        result_text += f"用时: {elapsed:.2f}秒\n"
        result_text += f"已找到密钥: {len(found_keys)}个\n"

        if found_keys:
            result_text += f"找到的密钥: {', '.join(found_keys)}\n"

        self.analysis_result_text.delete(1.0, tk.END)
        self.analysis_result_text.insert(tk.END, result_text)
        self.status_var.set(f"暴力破解进度: {progress_percent:.1f}%")

    def finalize_brute_force(self, total, elapsed, found_keys):
        """完成暴力破解"""
        self.root.after(0, lambda: self._finalize_brute_force_ui(total, elapsed, found_keys))

    def _finalize_brute_force_ui(self, total, elapsed, found_keys):
        """完成暴力破解UI更新"""
        result_text = f"暴力破解完成!\n"
        result_text += f"总密钥数: {total}\n"
        result_text += f"总用时: {elapsed:.2f}秒\n"
        result_text += f"找到的密钥数量: {len(found_keys)}\n"

        if found_keys:
            result_text += f"可能的密钥:\n"
            for key in found_keys:
                result_text += f"  {key}\n"
        else:
            result_text += "未找到匹配的密钥\n"

        self.analysis_result_text.delete(1.0, tk.END)
        self.analysis_result_text.insert(tk.END, result_text)
        self.progress_var.set(0)
        self.brute_force_running = False
        self.status_var.set("暴力破解完成")

    def analyze_key_conflicts(self):
        """分析密钥冲突"""
        self.analysis_result_text.delete(1.0, tk.END)
        self.analysis_result_text.insert(tk.END, "开始分析密钥冲突...\n")
        self.status_var.set("正在分析密钥冲突")

        # 测试多个明密文对
        test_cases = [
            ("10101010", "1010000010"),
            ("11001100", "1110001110"),
            ("00110011", "1100110011"),
            ("11110000", "1010101010")
        ]

        conflicts_found = 0

        for plaintext_str, key_str in test_cases:
            plain_bits = self.parse_binary_input(plaintext_str, 8)
            key_bits = self.parse_binary_input(key_str, 10)

            if not plain_bits or not key_bits:
                continue

            # 加密得到密文
            cipher_bits = SDES.encrypt_block(plain_bits, key_bits)
            cipher_str = ''.join(str(bit) for bit in cipher_bits)

            # 寻找其他能产生相同密文的密钥
            alternative_keys = []
            for test_key_int in range(1024):
                test_key = [(test_key_int >> i) & 1 for i in range(9, -1, -1)]
                if test_key == key_bits:
                    continue

                try:
                    test_cipher = SDES.encrypt_block(plain_bits, test_key)
                    if test_cipher == cipher_bits:
                        key_str_alt = ''.join(str(bit) for bit in test_key)
                        alternative_keys.append(key_str_alt)
                except:
                    pass

            self.analysis_result_text.insert(tk.END, f"\n测试用例 {conflicts_found + 1}:\n")
            self.analysis_result_text.insert(tk.END, f"明文: {plaintext_str}, 原密钥: {key_str}\n")
            self.analysis_result_text.insert(tk.END, f"密文: {cipher_str}\n")
            self.analysis_result_text.insert(tk.END, f"替代密钥数量: {len(alternative_keys)}\n")

            if alternative_keys:
                conflicts_found += 1
                self.analysis_result_text.insert(tk.END, f"前5个替代密钥: {alternative_keys[:5]}\n")

        summary = f"\n总结: 在{len(test_cases)}个测试用例中，{conflicts_found}个存在密钥冲突\n"
        self.analysis_result_text.insert(tk.END, summary)
        self.status_var.set("密钥冲突分析完成")


def main():
    """主函数"""
    root = tk.Tk()
    app = SDESGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()