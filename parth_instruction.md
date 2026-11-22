# Parth: run the tests on your MacBook

You only copy and paste commands into Terminal. No coding. About 30 minutes in total, most of it downloads.
Keep the MacBook plugged in with the lid open while it runs.

## 1. Install Python and Git (once)

1. Python 3.13: open https://www.python.org/downloads/macos/ , click the newest **Python 3.13.x** link, download the
   **macOS 64-bit universal2 installer** (.pkg), open it and click through Continue, Agree, Install.
2. Git: open **Terminal** (press Cmd + Space, type `Terminal`, press Enter) and paste:

   ```
   xcode-select --install
   ```

   Click **Install** in the window that appears. If it says the tools are already installed, that's fine.

## 2. Download the code

```
cd ~/Desktop
git clone https://github.com/Gokul0211/Defense-in-Depth-Architecture-for-Secure-Conversational-AI.git sentinel
```

## 3. Add the test pack

I'll send you **parth_pack.zip**. Save it in your Downloads folder, then paste:

```
unzip -o ~/Downloads/parth_pack.zip -d ~/Desktop/sentinel
```

## 4. Install the libraries (once, about 10 minutes)

```
cd ~/Desktop/sentinel
python3.13 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt -r requirements-eval.txt -c parth_constraints.txt pytest pytest-asyncio
```

## 5. Run everything (about 10 minutes)

```
cd ~/Desktop/sentinel
source .venv/bin/activate
python parth_run.py
```

It runs 8 jobs one after another and prints a line for each. If it stops for any reason (closed lid, restart), paste
the same three lines again: it continues where it stopped.

## 6. Send the results back

When it prints **SEND THIS FILE BACK**, send me this file (WhatsApp or Google Drive):

```
~/Desktop/sentinel/parth_results.zip
```

Send it even if a job says WITH PROBLEMS.

## If something goes wrong

- `command not found: python3.13`: step 1 did not finish; run the Python installer again.
- A red error in step 4: take a screenshot and send it to me.
- Don't edit or delete any file in the folder.
