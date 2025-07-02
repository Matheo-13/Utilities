import os
import shutil
import hashlib
import threading
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import hashlib
from datetime import datetime
import stat


def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def compute_md5(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.digest()


def count_files_recursive(folder_path):
    total_files = 0
    for root, dirs, files in os.walk(folder_path):
        total_files += len(files)
    return total_files

def is_deletable(filepath):
    if not os.path.isfile(filepath):
        print("Not a file or doesn't exist.")
        return False
    os.chmod(filepath, stat.S_IWRITE)
    # Check write permission to the directory (deletion happens at directory level)
    parent = os.path.dirname(filepath)
    if not os.access(parent, os.W_OK):
        print("No write permission to folder.")
        return False

    # Check if file is read-only
    if not os.access(filepath, os.W_OK):
        print("File is read-only.")
        return False

    # Check if read-only bit is set (redundant but deeper check)
    mode = os.stat(filepath).st_mode
    if not (mode & stat.S_IWRITE):
        print("Read-only flag is set.")
        return False

    return True

def remove_empty_folders(folder):
    # Walk through the folder tree bottom-up
    for root, dirs, files in os.walk(folder, topdown=False):
        for d in dirs:
            dir_path = os.path.join(root, d)
            try:
                # Try to remove directory if empty
                os.rmdir(dir_path)
                print(f"Removed empty folder: {dir_path}")
            except OSError:
                # Directory not empty or error, skip
                pass


class FileManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Manager")
        self.root.geometry("400x250")

        frame = ttk.Frame(root, padding=20)
        frame.pack(expand=True)

        ttk.Label(frame, text="Select an Option", font=("Segoe UI", 16)).pack(pady=10)

        ttk.Button(frame, text="Delete Duplicate Files", bootstyle="primary, outline", width=25, command=self.open_duplicates_window).pack(pady=10)
        ttk.Button(frame, text="Copy Files", bootstyle="primary, outline", width=25, command=self.open_copy_window).pack(pady=10)
        ttk.Button(frame, text="Rename Files", bootstyle="primary, outline", width=25, command=self.open_rename_window).pack(pady=10)

    def open_duplicates_window(self):
        DuplicateWindow(self.root)

    def open_copy_window(self):
        CopyWindow(self.root)

    def open_rename_window(self):
        RenameWindow(self.root)

class DuplicateWindow:
    def __init__(self, window):
        for widget in window.winfo_children():
            widget.destroy()
        self.window = window
        self.window.title("Remove Duplicate Files")
        self.window.geometry("450x300")

        self.folder = None

        self.frame = ttk.Frame(self.window, padding=20)
        self.frame.pack(expand=True)

        ttk.Button(self.frame, text="Select Folder", bootstyle="primary", command=self.choose_folder).pack(pady=10)
        self.folder_label = ttk.Label(self.frame, text="No folder selected", wraplength=400)
        self.folder_label.pack()

        self.duplicate_progress = ttk.Progressbar(self.frame, length=350, bootstyle="info-striped")
        self.duplicate_progress.pack(pady=10)

        ttk.Button(self.frame, text="Start Removing Duplicates", bootstyle="success", command=self.start_remove_duplicates).pack(pady=15)

        self.duplicate_label = ttk.Label(self.frame, text="")
        self.duplicate_label.pack(pady=5)

    def choose_folder(self):
        self.folder = filedialog.askdirectory()
        if self.folder:
            self.folder_label.config(text=self.folder)

    def start_remove_duplicates(self):
        if not self.folder:
            messagebox.showerror("Error", "Please select a folder.")
            return
        thread = threading.Thread(target=self.remove_duplicates, args=(self.folder,))
        thread.start()

    def remove_duplicates(self, folder, file_hash : callable = compute_sha256):
        self.duplicate_progress['value'] = 0
        self.duplicate_progress.config(bootstyle="info-striped")
        total = count_files_recursive(folder)
        all_files = dict()
        duplicates = dict()
        current_step = 0
        nb_errors = 0        
        for root, _, files in os.walk(folder):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    file_hash_value = file_hash(full_path)
                    if file_hash_value not in all_files:
                        all_files[file_hash_value] = full_path
                    else:
                        if file_hash_value not in duplicates:
                            duplicates[file_hash_value] = []
                            duplicates[file_hash_value].append(full_path)
                        else:
                            duplicates[file_hash_value].append(full_path)
                except Exception as e:
                    print(f"\nError hashing {full_path}: {e}")
                    nb_errors += 1

                current_step += 1
                self.duplicate_progress['value'] = current_step / total * 100
                self.window.update_idletasks()    
        
        for hash_value, path in duplicates.items():
            path_og = all_files[hash_value]  # wherever your duplicate is stored
            print(f"\nDuplicates found:\n - {path_og}\n - {path}")
            print(f"Keeping {path_og}")
            assert path_og not in path, "Original and duplicate paths should not be the same"
            for p in path:
                if is_deletable(p):
                    try : 
                        os.remove(p)
                    except Exception as e: 
                        print(f"Error removing {p}: {e}")
                else:
                    print(f"{p} is not deletable.")

        self.duplicate_progress['value'] = 100
        self.duplicate_progress.config(bootstyle="success")
        self.duplicate_label.config(text=f"Removed {len(duplicates)} duplicate files !")



class CopyWindow:
    def __init__(self, window):
        for widget in window.winfo_children():
            widget.destroy()
        self.window = window
        self.window.title("Copy Files with Hashing")
        self.window.geometry("500x400")

        self.src_folder = None
        self.dst_folder = None
        self._src_is_done = False
        self._dst_is_done = False

        self.hash_alg = compute_sha256 

        self.frame = ttk.Frame(self.window, padding=20)
        self.frame.pack(expand=True, fill=BOTH)

        ttk.Button(self.frame, text="Select Origin Folder", bootstyle="primary", command=self.choose_src).pack(pady=5)
        self.src_label = ttk.Label(self.frame, text="No folder selected", wraplength=450)
        self.src_label.pack()

        self.src_progress = ttk.Progressbar(self.frame, length=400, bootstyle="info-striped")
        self.src_progress.pack(pady=10)

        ttk.Button(self.frame, text="Select Destination Folder", bootstyle="primary", command=self.choose_dst).pack(pady=5)
        self.dst_label = ttk.Label(self.frame, text="No folder selected", wraplength=450)
        self.dst_label.pack()

        self.dst_progress = ttk.Progressbar(self.frame, length=400, bootstyle="info-striped")
        self.dst_progress.pack(pady=10)

        self.copy_progress_label = ttk.Label(self.frame, text="")
        self.copy_progress_label.pack(pady=5)

        ttk.Button(self.frame, text="Start Copy", bootstyle="success", command=self.start_copy).pack(pady=10)

        self.copy_progress = ttk.Progressbar(self.frame, length=200, bootstyle="info-striped")
        self.copy_progress.pack(pady=10)

    def choose_src(self):
        self.src_folder = filedialog.askdirectory()
        if self.src_folder:
            self.src_label.config(text=self.src_folder)
            threading.Thread(target=self.start_hashing, args=(self.src_folder, self.src_progress, True, self.hash_alg)).start()

    def choose_dst(self):
        self.dst_folder = filedialog.askdirectory()
        if self.dst_folder:
            self.dst_label.config(text=self.dst_folder)
            threading.Thread(target=self.start_hashing, args=(self.dst_folder, self.dst_progress, False, self.hash_alg)).start()


    def start_copy(self):
        if not self._src_is_done or not self._dst_is_done:
            messagebox.showerror("Error", "Both folders need to be hashed.")
            return

        thread = threading.Thread(target=self.copy_files_with_progress)
        thread.start()

    def start_hashing(self, folder, progress_bar, is_src=True, file_hash : callable = compute_sha256):
        if is_src:
            self.src_progress.config(bootstyle="info-striped")
            self._src_is_done = False
            self.all_src_files = dict()
            self.src_duplicates = dict()
            self.src_progress['value'] = 0
        else:
            self.dst_progress.config(bootstyle="info-striped")
            self._dst_is_done = False
            self.all_dst_files = dict()
            self.dst_duplicates = dict()
            self.dst_progress['value'] = 0

        self.copy_progress['value'] = 0
        self.copy_progress.config(bootstyle="info-striped")
        total = count_files_recursive(folder)
        all_files = dict()
        duplicates = dict()
        current_step = 0
        nb_errors = 0
        if total == 0:
            if is_src: 
                self.all_src_files = all_files
                self.src_duplicates = duplicates
                self._src_is_done = True
                self.src_progress['value'] = 100
                self.src_progress.config(bootstyle="success")
            else:
                self.all_dst_files = all_files
                self.dst_duplicates = duplicates
                self._dst_is_done = True
                self.dst_progress['value'] = 100
                self.dst_progress.config(bootstyle="success")
            return
        
        for root, _, files in os.walk(folder):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    file_hash_value = file_hash(full_path)
                    if file_hash_value not in all_files:
                        all_files[file_hash_value] = full_path
                    else:
                        if file_hash_value not in duplicates:
                            duplicates[file_hash_value] = []
                            duplicates[file_hash_value].append(full_path)
                        else:
                            duplicates[file_hash_value].append(full_path)
                except Exception as e:
                    print(f"\nError hashing {full_path}: {e}")
                    nb_errors += 1

                current_step += 1
                progress_bar['value'] = current_step / total * 100
                self.window.update_idletasks()
        
        if is_src: 
            self.all_src_files = all_files
            self.src_duplicates = duplicates
            self._src_is_done = True
            self.src_progress['value'] = 100
            self.src_progress.config(bootstyle="success")
        else:
            self.all_dst_files = all_files
            self.dst_duplicates = duplicates
            self._dst_is_done = True
            self.dst_progress['value'] = 100
            self.dst_progress.config(bootstyle="success")


    def copy_files_with_progress(self):
        total = 0
        for hash_value, path in self.all_src_files.items():
            if hash_value not in self.all_dst_files:
                total += 1

        self.copy_progress_label.config(text=f"Copying {total} files...")
        current_step = 0
        
        for hash_value, path in self.all_src_files.items():
            if hash_value not in self.all_dst_files:
                src_file = self.all_src_files[hash_value]
                file_name = os.path.basename(src_file)
                dst_file = os.path.join(self.dst_folder, file_name)
                try:
                    shutil.copy2(src_file, dst_file)
                    new_hash = self.hash_alg(dst_file)
                    if new_hash != hash_value:
                        print(f"Hash mismatch for {src_file}. Expected {hash_value}, got {new_hash}.")
                except Exception as e:
                    print(f"Error copying {src_file}: {e}")

                current_step += 1
                self.copy_progress['value'] = current_step / total * 100
                self.window.update_idletasks()
        
        self.copy_progress.config(bootstyle="success")
        self.copy_progress_label.config(text=f"Copied {current_step} files successfully !")

class RenameWindow:
    def __init__(self, window):
        for widget in window.winfo_children():
            widget.destroy()
        self.window = window
        self.window.title("Rename Files")
        self.window.geometry("450x300")

        self.folder = None

        frame = ttk.Frame(self.window, padding=20)
        frame.pack(expand=True)

        ttk.Button(frame, text="Select Folder", bootstyle="primary", command=self.choose_folder).pack(pady=10)
        self.folder_label = ttk.Label(frame, text="No folder selected", wraplength=400)
        self.folder_label.pack()

        self.rename_progress = ttk.Progressbar(frame, length=350, bootstyle="info-striped")
        self.rename_progress.pack(pady=10)

        ttk.Button(frame, text="Start Rename", bootstyle="success", command=self.start_rename).pack(pady=15)

    def choose_folder(self):
        self.folder = filedialog.askdirectory()
        if self.folder:
            self.folder_label.config(text=self.folder)

    def start_rename(self):
        if not self.folder:
            messagebox.showerror("Error", "Please select a folder.")
            return
        thread = threading.Thread(target=self.move_and_rename_files, args=(self.folder,))
        thread.start()

    def move_and_rename_files(self, folder):
        os.makedirs(os.path.join(folder, "temp"), exist_ok=False)

        self.rename_progress.config(bootstyle="info-striped")
        self.rename_progress['value'] = 0
        total_files = count_files_recursive(folder)
        current = 0
        if total_files == 0:
            self.rename_progress['value'] = 100
            self.rename_progress.config(bootstyle="success")
            return
        for root, dirs, files in os.walk(folder):
            for file in files:
                src_path = os.path.join(root, file)
            
                # Get file modification time
                timestamp = os.path.getmtime(src_path)
                dt = datetime.fromtimestamp(timestamp)

                # Build destination folder path: YYYY/MM
                year_folder = dt.strftime("%Y")
                month_folder = dt.strftime("%m")
                dst_folder = os.path.join(folder, year_folder, month_folder)
                os.makedirs(dst_folder, exist_ok=True)

                # Build new filename: YYYY_MM_DD_HH_MM_SS + original extension
                extension = os.path.splitext(file)[1]  # includes dot, e.g. ".jpg"
                new_name = dt.strftime("%Y_%m_%d_%H_%M_%S") + extension
                dst_path = os.path.join(dst_folder, new_name)
                shutil.move(src_path, os.path.join(folder, "temp", file))
                
                # If the new filename exists, add a counter suffix to avoid overwrite
                counter = 1
                base_name = new_name[:-len(extension)]
                while os.path.exists(dst_path):
                    new_name = f"{base_name}--{counter}{extension}"
                    dst_path = os.path.join(dst_folder, new_name)
                    counter += 1
                # Move and rename file
                shutil.move(os.path.join(folder, "temp", file), dst_path)

                current += 1
                self.rename_progress['value'] = current / total_files * 100
                self.window.update_idletasks()

        os.rmdir(os.path.join(folder, "temp"))

        remove_empty_folders(folder)
        
        self.rename_progress['value'] = 100
        self.rename_progress.config(bootstyle="success")
                

if __name__ == "__main__":
    app = ttk.Window(themename="flatly")  # Try "darkly", "superhero", or "cyborg" for dark themes
    FileManagerApp(app)
    app.mainloop()
