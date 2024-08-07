import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import requests
import csv
 
 
 
 
# Security Headers Information
SECURITY_HEADERS_INFO = {
  'Strict-Transport-Security': {
      'description': 'Ensures HTTPS is used.',
      'expected': 'max-age=63072000; includeSubDomains; preload',
      'recommendation': 'Add Strict-Transport-Security to enforce HTTPS.',
      'advice': 'This header is critical for enforcing HTTPS across your site. It helps prevent man-in-the-middle attacks.'
  },
  'Content-Security-Policy': {
      'description': 'Prevents cross-site scripting attacks.',
      'expected': None,
      'recommendation': 'Add Content-Security-Policy to control resource loading.',
      'advice': 'Implementing a strong CSP can significantly reduce XSS vulnerabilities by controlling resource loading.'
  },
  'X-Content-Type-Options': {
      'description': 'Prevents MIME-type sniffing.',
      'expected': 'nosniff',
      'recommendation': 'Add X-Content-Type-Options with nosniff value.',
      'advice': 'This header prevents browsers from interpreting files as something else, reducing the risk of malicious code execution.'
  },
  'X-Frame-Options': {
      'description': 'Prevents clickjacking.',
      'expected': 'DENY',
      'recommendation': 'Add X-Frame-Options to prevent clickjacking.',
      'advice': 'Clickjacking protection ensures your site is not embedded in iframes, avoiding potential clickjacking attacks.'
  },
  'X-XSS-Protection': {
      'description': 'Enables XSS filtering.',
      'expected': '1; mode=block',
      'recommendation': 'Add X-XSS-Protection with mode=block.',
      'advice': 'While modern browsers handle XSS well, this header can offer additional protection for older browsers.'
  },
  'Referrer-Policy': {
      'description': 'Controls referrer information.',
      'expected': 'no-referrer',
      'recommendation': 'Add Referrer-Policy with no-referrer value.',
      'advice': 'A strict referrer policy protects user privacy by minimizing the information shared with third parties.'
  },
  'Permissions-Policy': {
      'description': 'Manages permissions like geolocation.',
      'expected': None,
      'recommendation': 'Add Permissions-Policy to control feature permissions.',
      'advice': 'This policy helps you control which features and APIs your site can access, protecting user data.'
  },
  'Expect-CT': {
      'description': 'Ensures valid certificate transparency.',
      'expected': 'max-age=86400, enforce',
      'recommendation': 'Add Expect-CT for certificate transparency.',
      'advice': 'Using Expect-CT ensures that your site’s certificates are logged, helping to detect unauthorized certificates.'
  }
}
 
 
 
 
def check_security_headers():
  urls = [url.strip() for url in url_entry.get().split(',') if url.strip()]
  if not urls:
      messagebox.showwarning("Input Error", "Please enter one valid URL at least.")
      return
 
 
 
 
  results_text.delete(1.0, tk.END)
  for url in urls:
      try:
          response = requests.get(url, timeout=10)
          headers = response.headers
          results = analyze_headers(headers)
          display_results(url, results)
      except requests.RequestException as e:
          messagebox.showerror("Request Error", f"Failed to reach {url}: {e}")
 
 
 
 
def analyze_headers(headers):
  results = {}
  for header, details in SECURITY_HEADERS_INFO.items():
      actual_value = headers.get(header)
      expected_value = details['expected']
      results[header] = {
          'status': 'Present' if actual_value else 'Missing',
          'actual_value': actual_value or 'None',
          'match': actual_value == expected_value if expected_value else 'N/A',
          'description': details['description'],
          'recommendation': details['recommendation'] if actual_value != expected_value else None,
          'advice': details['advice']
      }
  return results
 
 
 
 
def display_results(url, results):
  results_text.insert(tk.END, f"Security Headers for {url}:\n\n")
  for header, info in results.items():
      results_text.insert(tk.END, f"Header: {header}\nStatus: {info['status']}\nActual Value: {info['actual_value']}\n")
      results_text.insert(tk.END, f"Match Expected: {info['match']}\nDescription: {info['description']}\n")
      if info['recommendation']:
          results_text.insert(tk.END, f"Recommendation: {info['recommendation']}\n")
      results_text.insert(tk.END, f"Advice: {info['advice']}\n" + "-" * 80 + "\n")
      highlight_status(info['status'])
 
 
 
 
def highlight_status(status):
  start_index, end_index = 'end-7l', 'end-1l'
  tag, color = ('missing', 'red') if status == "Missing" else ('present', 'green')
  results_text.tag_add(tag, start_index, end_index)
  results_text.tag_config(tag, background=color, foreground='white')
 
 
 
 
def save_results_csv():
  results = results_text.get(1.0, tk.END).strip()
  if not results:
      messagebox.showwarning("Save Error", "No results to save.")
      return
 
 
 
 
  filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
  if filename:
      try:
          with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
              csvwriter = csv.writer(csvfile)
              csvwriter.writerow(['URL', 'Header', 'Status', 'Actual Value', 'Match Expected', 'Description', 'Recommendation', 'Advice'])
              parse_and_write_results(csvwriter, results)
          messagebox.showinfo("Success", "Results saved successfully as CSV")
      except Exception as e:
          messagebox.showerror("File Error", f"Failed to save the results: {e}")
 
 
 
 
def parse_and_write_results(csvwriter, results):
   lines = results.split("\n")
   current_url = ""
   for line in lines:
       if line.startswith("Security Headers for"):
           current_url = line.split(" ")[-1].strip(':')
       elif line.startswith("Header:"):
           try:
               header = line.split(": ")[1]
               status = lines[lines.index(line) + 1].split(": ")[1]
               actual_value = lines[lines.index(line) + 2].split(": ")[1]
               match_expected = lines[lines.index(line) + 3].split(": ")[1]
               description = lines[lines.index(line) + 4].split(": ")[1]
               # Check if the recommendation line is present
               recommendation_line = lines[lines.index(line) + 5]
               recommendation = recommendation_line.split(": ")[1] if "Recommendation:" in recommendation_line else ""
               # Ensure advice line exists
               advice_line = lines[lines.index(line) + 5] if not recommendation else lines[lines.index(line) + 6]
               advice = advice_line.split(": ")[1] if "Advice:" in advice_line else ""
               csvwriter.writerow([current_url, header, status, actual_value, match_expected, description, recommendation, advice])
           except IndexError:
               print(f"Error: Missing information for header {header}")
               continue
 
 
 
 
def show_help():
  help_text = (
      "Security Header Checker Help\n\n"
      "1. Enter URLs: If you You Input one or more URLs Make Sure They are separated by commas.\n"
      "2. Check Security Headers: Simply Click the button to analyze the security headers.\n"
      "3. Save Results: Save the analysis results as CSV files.\n\n"
      "Security Headers:\n"
      "- Strict-Transport-Security: Enforces HTTPS.\n"
      "- Content-Security-Policy: Controls resource loading.\n"
      "- X-Content-Type-Options: Prevents MIME-type sniffing.\n"
      "- X-Frame-Options: Prevents clickjacking.\n"
      "- X-XSS-Protection: Enables XSS filtering.\n"
      "- Referrer-Policy: Controls referrer information.\n"
      "- Permissions-Policy: Manages permissions.\n"
      "- Expect-CT: Ensures certificate transparency.\n\n"
      "Advice:\n"
      "For each header, Please follow the given advice to improve The security settings.\n"
      "Use the recommendations to implement the missing headers for enhanced protection."
  )
  messagebox.showinfo("Help", help_text)
 
 
 
 
# Main Tkinter Application
if __name__ == "__main__":
  root = tk.Tk()
  root.title("Security Header Checker - The Pycodes")
  root.geometry("1000x700")
 
 
  # Frame for URL input and buttons
  frame = ttk.Frame(root)
  frame.pack(pady=10)
 
 
  # URL Entry
  ttk.Label(frame, text="Enter URLs (comma-separated):").grid(row=0, column=0, padx=5)
  url_entry = ttk.Entry(frame, width=80)
  url_entry.grid(row=0, column=1, padx=5)
 
 
  # Check Button
  ttk.Button(frame, text="Check Security Headers", command=check_security_headers).grid(row=0, column=2, padx=5)
 
 
  # Results Display
  results_text = scrolledtext.ScrolledText(root, width=120, height=25, wrap=tk.WORD)
  results_text.pack(pady=10)
 
 
  # Save Buttons Frame
  save_frame = ttk.Frame(root)
  save_frame.pack(pady=10)
 
 
  # Save as CSV Button
  ttk.Button(save_frame, text="Save Results as CSV", command=save_results_csv).grid(row=0, column=0, padx=5)
 
 
  # Help Button
  ttk.Button(save_frame, text="Help", command=show_help).grid(row=0, column=1, padx=5)
 
 
  root.mainloop()
