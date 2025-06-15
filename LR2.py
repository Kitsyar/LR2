import os
import hashlib
from collections import Counter
import tkinter as tk
from tkinter import filedialog, messagebox

def select_file_gui(title="Виберіть файл", filetypes=(("Текстові файли", "*.txt"), ("Усі файли", "*.*"))):
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
    root.destroy()
    return file_path

def analyze_log_file(log_file_path):
    response_codes = {}

    if not log_file_path:
        return None

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_num, line in enumerate(file, 1):
                parts = line.strip().split()
                if len(parts) >= 9:
                    try:
                        code = int(parts[8])
                        response_codes[code] = response_codes.get(code, 0) + 1
                    except ValueError:
                        print(f"Рядок {line_num}: Некоректний HTTP код у '{line.strip()}'")
                        continue
                else:
                    pass

    except FileNotFoundError:
        print(f"Файл не знайдено: {log_file_path}")
        messagebox.showerror("Помилка файлу", f"Файл не знайдено: {log_file_path}")
        return None
    except IOError as e:
        print(f"Неможливо прочитати файл: {log_file_path}. Причина: {e}")
        messagebox.showerror("Помилка файлу", f"Неможливо прочитати файл: {log_file_path}\nПричина: {e}")
        return None
    except Exception as e:
        print(f"Сталася непередбачена помилка при читанні файлу {log_file_path}: {e}")
        messagebox.showerror("Невідома помилка", f"Сталася непередбачена помилка: {e}")
        return None

    return response_codes

def generate_file_hashes(file_paths):
    file_hashes = {}
    if not file_paths:
        print("Немає файлів для хешування.")
        return file_hashes

    for f_path in file_paths:
        try:
            with open(f_path, 'rb') as f:
                bytes_content = f.read()
                readable_hash = hashlib.sha256(bytes_content).hexdigest()
                file_hashes[f_path] = readable_hash
        except FileNotFoundError:
            print(f"Файл для хешування не знайдено: {f_path}")
            messagebox.showerror("Помилка хешування", f"Файл для хешування не знайдено: {f_path}")
        except IOError as e:
            print(f"Неможливо прочитати файл для хешування: {f_path}. Причина: {e}")
            messagebox.showerror("Помилка хешування", f"Неможливо прочитати файл для хешування: {f_path}\nПричина: {e}")
        except Exception as e:
            print(f"Сталася непередбачена помилка при хешуванні {f_path}: {e}")
            messagebox.showerror("Невідома помилка", f"Сталася непередбачена помилка при хешуванні {f_path}: {e}")
    return file_hashes

def filter_ips(input_file_path, output_file_path):
    all_ip_counts = Counter()

    if not input_file_path:
        return

    try:
        with open(input_file_path, 'r', encoding='utf-8', errors='ignore') as infile:
            for line_num, line in enumerate(infile, 1):
                parts = line.strip().split()
                if parts:
                    ip_address = parts[0]
                    all_ip_counts[ip_address] += 1
    except FileNotFoundError:
        print(f"Вхідний файл для фільтрації IP не знайдено: {input_file_path}")
        messagebox.showerror("Помилка файлу", f"Вхідний файл для фільтрації IP не знайдено: {input_file_path}")
        return
    except IOError as e:
        print(f"Неможливо прочитати вхідний файл для фільтрації IP: {input_file_path}. Причина: {e}")
        messagebox.showerror("Помилка файлу", f"Неможливо прочитати вхідний файл для фільтрації IP: {input_file_path}\nПричина: {e}")
        return
    except Exception as e:
        print(f"Сталася непередбачена помилка при читанні файлу {input_file_path}: {e}")
        messagebox.showerror("Невідома помилка", f"Сталася непередбачена помилка: {e}")
        return

    try:
        with open(output_file_path, 'w', encoding='utf-8') as outfile:
            outfile.write("Результати аналізу IP-адрес:\n")
            total_ips = 0
            for ip, count in all_ip_counts.most_common():
                outfile.write(f"{ip} - {count}\n")
                total_ips += count
            outfile.write(f"\nЗагальна кількість всіх IP-адрес: {total_ips}\n")
        print(f"Результати фільтрації IP-адрес збережено у: {output_file_path}")
        messagebox.showinfo("Успіх", f"Результати фільтрації IP-адрес збережено у: {output_file_path}")
    except IOError as e:
        print(f"Неможливо записати у вихідний файл: {output_file_path}. Причина: {e}")
        messagebox.showerror("Помилка запису", f"Неможливо записати у вихідний файл: {output_file_path}\nПричина: {e}")
    except Exception as e:
        print(f"Сталася непередбачена помилка при записі у файл {output_file_path}: {e}")
        messagebox.showerror("Невідома помилка", f"Сталася непередбачена помилка при записі у файл {output_file_path}: {e}")

if __name__ == "__main__":
    print("--- Завдання 1: Аналізатор лог-файлів ---")
    messagebox.showinfo("Вибір файлу", "Будь ласка, виберіть лог-файл (наприклад, apache_logs.txt) для Завдання 1.")
    log_file_path = select_file_gui(title="Виберіть лог-файл (apache_logs.txt)", filetypes=(("Текстові файли", "*.txt"), ("Усі файли", "*.*")))

    if log_file_path:
        log_analysis_results = analyze_log_file(log_file_path)
        if log_analysis_results:
            print("\nРезультати аналізу HTTP-кодів відповідей:")
            result_str = "\n".join([f"Код {code}: {count} входжень" for code, count in log_analysis_results.items()])
            print(result_str)
            messagebox.showinfo("Результати аналізу логу", f"Аналіз завершено:\n{result_str}")
    else:
        print("Вибір лог-файлу скасовано або файл не обрано. Пропускаємо Завдання 1.")

    print("\n--- Завдання 2: Генератор хеш-файлів ---")
    messagebox.showinfo("Вибір файлів для хешування", "Будь ласка, виберіть один або декілька файлів для хешування (Завдання 2).")
    files_to_hash = filedialog.askopenfilenames(title="Виберіть файли для хешування", filetypes=(("Усі файли", "*.*"), ("Текстові файли", "*.txt")))

    if files_to_hash:
        hashes = generate_file_hashes(list(files_to_hash))
        print("\nРезультати хешування файлів:")
        hash_result_str = ""
        for file, h in hashes.items():
            print(f"Файл: {file}\n  SHA-256 хеш: {h}")
            hash_result_str += f"Файл: {os.path.basename(file)}\n  Хеш: {h}\n\n"
        if hash_result_str:
            messagebox.showinfo("Результати хешування", f"Хешування завершено:\n{hash_result_str}")
    else:
        print("Вибір файлів для хешування скасовано або файли не обрано. Пропускаємо Завдання 2.")

    print("\n--- Завдання 3: Фільтрація IP-адресів ---")
    if not log_file_path:
        messagebox.showinfo("Вибір файлу", "Будь ласка, виберіть лог-файл для Завдання 3 (якщо він не був обраний раніше).")
        log_file_path = select_file_gui(title="Виберіть лог-файл для Завдання 3", filetypes=(("Текстові файли", "*.txt"), ("Усі файли", "*.*")))

    if log_file_path:
        output_filtered_ips_file = "filtered_ips.txt"
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        output_filtered_ips_file_full_path = os.path.join(current_script_dir, output_filtered_ips_file)

        filter_ips(log_file_path, output_filtered_ips_file_full_path)
    else:
        print("Не вдалося визначити вхідний файл для Завдання 3. Пропускаємо Завдання 3.")

    print("\n--- Усі завдання виконано ---")
    messagebox.showinfo("Завершення", "Усі завдання виконано. Перевірте консоль та згенеровані файли.")
