import os
import json
import hashlib
import zlib
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from datetime import datetime
import sys

# Константы
BLOCK_SIZE = 65536
DEFAULT_ALGORITHMS = ['crc32', 'md5', 'sha256']

# ОСНОВНАЯ ЛОГИКА
def compute_hash(filepath, algorithms):
    hashes = {}
    if 'md5' in algorithms:
        md5 = hashlib.md5()
    if 'sha256' in algorithms:
        sha256 = hashlib.sha256()
    crc32 = 0 if 'crc32' in algorithms else None
    try:
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(BLOCK_SIZE)
                if not data:
                    break
                if 'md5' in algorithms:
                    md5.update(data)
                if 'sha256' in algorithms:
                    sha256.update(data)
                if 'crc32' in algorithms:
                    crc32 = zlib.crc32(data, crc32)
    except (IOError, OSError):
        return None
    if 'md5' in algorithms:
        hashes['md5'] = md5.hexdigest()
    if 'sha256' in algorithms:
        hashes['sha256'] = sha256.hexdigest()
    if 'crc32' in algorithms:
        hashes['crc32'] = format(crc32 & 0xFFFFFFFF, '08x')
    return hashes

def scan_directory(directory, algorithms, relative_to=None):
    if relative_to is None:
        relative_to = directory
    manifest_data = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, relative_to).replace(os.sep, '/')
            hashes = compute_hash(full_path, algorithms)
            if hashes is not None:
                manifest_data[rel_path] = hashes
    return manifest_data

def save_manifest(manifest_data, manifest_path, algorithms, directory):
    manifest = {
        'version': '1.0',
        'created': datetime.now().isoformat(),
        'algorithms': algorithms,
        'directory': os.path.abspath(directory),
        'files': manifest_data
    }
    os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

def load_manifest(manifest_path):
    with open(manifest_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def verify_integrity(directory, manifest, algorithms):
    current_data = scan_directory(directory, algorithms, relative_to=directory)
    manifest_data = manifest.get('files', {})
    changes = {'new': [], 'modified': [], 'deleted': []}
    for rel_path, manifest_hashes in manifest_data.items():
        if rel_path not in current_data:
            changes['deleted'].append(rel_path)
        else:
            current_hashes = current_data[rel_path]
            for algo in algorithms:
                if algo in manifest_hashes and algo in current_hashes:
                    if manifest_hashes[algo] != current_hashes[algo]:
                        changes['modified'].append({
                            'path': rel_path,
                            'algorithm': algo,
                            'expected': manifest_hashes[algo],
                            'actual': current_hashes[algo]
                        })
                        break
    for rel_path in current_data:
        if rel_path not in manifest_data:
            changes['new'].append(rel_path)
    return changes

# ГРАФИЧЕСКИЙ ИНТЕРФЕЙС
class IntegrityCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Контроль целостности файлов")
        self.root.geometry("750x650")
        self.root.minsize(650, 500)

        # Попытка установить иконку (если есть файл icon.ico)
        try:
            self.root.iconbitmap('icon.ico')
        except:
            pass

        # Стиль
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=('Segoe UI', 10))
        style.configure('TLabel', font=('Segoe UI', 10))
        style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'))

        # Верхняя панель
        header_frame = ttk.Frame(root)
        header_frame.pack(fill=tk.X, padx=15, pady=(15, 5))

        ttk.Label(header_frame, text="Контроль целостности файлов", style='Header.TLabel').pack(side=tk.LEFT)

        # Выбор папки
        dir_frame = ttk.LabelFrame(root, text="Выбор директории", padding=10)
        dir_frame.pack(fill=tk.X, padx=15, pady=10)

        self.dir_path = tk.StringVar()
        ttk.Entry(dir_frame, textvariable=self.dir_path, font=('Segoe UI', 10)).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Button(dir_frame, text="Обзор...", command=self.select_directory, width=12).pack(side=tk.RIGHT)

        # Кнопки действий
        btn_frame = ttk.Frame(root)
        btn_frame.pack(fill=tk.X, padx=15, pady=5)

        ttk.Button(btn_frame, text="📄 Создать манифест", command=self.create_manifest).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="🔍 Проверить целостность", command=self.verify_manifest).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="🗑️ Очистить лог", command=self.clear_log).pack(side=tk.RIGHT)

        # Лог-вывод
        log_frame = ttk.LabelFrame(root, text="Результаты", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#f0f4f8',
            fg='#1a1a2e',
            insertbackground='#1a1a2e',
            relief=tk.FLAT,
            height=25
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Статусная строка
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=(10, 2))
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=15, pady=(5, 10))

    def select_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_path.set(directory)
            self.status_var.set(f"Выбрана папка: {directory}")

    def log(self, message, level='info'):
        colors = {
            'info': '#1a1a2e',
            'success': '#2e7d32',
            'error': '#c62828',
            'warning': '#e65100'
        }
        self.log_text.insert(tk.END, message + "\n", (level,))
        self.log_text.see(tk.END)
        for tag, color in colors.items():
            self.log_text.tag_config(tag, foreground=color)

    def clear_log(self):
        self.log_text.delete('1.0', tk.END)
        self.status_var.set("Лог очищен")

    def create_manifest(self):
        directory = self.dir_path.get().strip()
        if not directory:
            messagebox.showerror("Ошибка", "Сначала выберите папку!")
            return

        self.status_var.set("Создание манифеста...")
        self.log("--- СОЗДАНИЕ МАНИФЕСТА ---", 'info')
        self.log(f"Сканируемая папка: {directory}")

        try:
            algorithms = DEFAULT_ALGORITHMS
            manifest_data = scan_directory(directory, algorithms)

            base_dir = os.path.dirname(os.path.abspath(__file__))
            manifest_dir = os.path.join(base_dir, 'manifests')
            os.makedirs(manifest_dir, exist_ok=True)
            manifest_path = os.path.join(manifest_dir, f"manifest_{os.path.basename(directory)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

            save_manifest(manifest_data, manifest_path, algorithms, directory)
            self.log(f"✅ Манифест сохранён: {manifest_path}", 'success')
            self.log(f"📊 Обработано файлов: {len(manifest_data)}", 'info')
            self.status_var.set(f"Манифест создан: {os.path.basename(manifest_path)}")
        except Exception as e:
            self.log(f"❌ Ошибка: {e}", 'error')
            self.status_var.set("Ошибка при создании манифеста")

    def verify_manifest(self):
        directory = self.dir_path.get().strip()
        if not directory:
            messagebox.showerror("Ошибка", "Сначала выберите папку!")
            return

        base_dir = os.path.dirname(os.path.abspath(__file__))
        manifest_dir = os.path.join(base_dir, 'manifests')
        if not os.path.isdir(manifest_dir):
            messagebox.showerror("Ошибка", "Папка с манифестами не найдена. Сначала создайте манифест.")
            return

        folder_name = os.path.basename(directory)
        all_manifests = [f for f in os.listdir(manifest_dir) if f.endswith('.json')]
        matching_manifests = [f for f in all_manifests if folder_name in f]

        if not matching_manifests:
            messagebox.showerror(
                "Ошибка",
                f"Нет манифеста для папки '{folder_name}'.\nСначала создайте манифест для этой директории."
            )
            return

        matching_manifests.sort(reverse=True)
        manifest_path = os.path.join(manifest_dir, matching_manifests[0])

        self.status_var.set("Проверка целостности...")
        self.log("--- ПРОВЕРКА ЦЕЛОСТНОСТИ ---", 'info')
        self.log(f"Манифест: {os.path.basename(manifest_path)}")
        self.log(f"Проверяемая папка: {directory}")

        try:
            manifest = load_manifest(manifest_path)
            algorithms = manifest.get('algorithms', DEFAULT_ALGORITHMS)
            changes = verify_integrity(directory, manifest, algorithms)

            if not any(changes.values()):
                self.log("✅ Все файлы целостны. Изменений не обнаружено.", 'success')
            else:
                if changes['new']:
                    self.log(f"🆕 Новые файлы ({len(changes['new'])}):", 'warning')
                    for path in changes['new']:
                        self.log(f"   + {path}")
                if changes['deleted']:
                    self.log(f"🗑️ Удалённые файлы ({len(changes['deleted'])}):", 'warning')
                    for path in changes['deleted']:
                        self.log(f"   - {path}")
                if changes['modified']:
                    self.log(f"⚠️ Изменённые файлы ({len(changes['modified'])}):", 'error')
                    for item in changes['modified']:
                        self.log(f"   * {item['path']} ({item['algorithm']})")
                        self.log(f"     было: {item['expected']}")
                        self.log(f"     стало: {item['actual']}")
            self.status_var.set("Проверка завершена")
        except Exception as e:
            self.log(f"❌ Ошибка: {e}", 'error')
            self.status_var.set("Ошибка при проверке")

if __name__ == "__main__":
    root = tk.Tk()
    app = IntegrityCheckerApp(root)
    root.mainloop()