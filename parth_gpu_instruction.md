# Parth: the GPU runs on your MacBook (round 2)

This round runs the real experiments on your Mac's GPU. Like last time, you only paste commands into Terminal. You
need about **40 GB of free disk**. Keep the MacBook **plugged in with the lid open** the whole time, and **close Chrome
and other apps** while it runs: the model needs most of the Mac's memory. It takes a day or more and can run overnight.
If it stops (closed lid, restart, Ctrl+C), paste the step 4 commands again and it carries on from where it stopped.

## Already started? (it stopped on 23 Nov: "Check this Mac", then "the L3 judge ... out of memory")

Both stops were my script, not your Mac, and both are fixed. If you edited `parth_gpu_run.py` yourself (the `sed`
command), that's fine: `git stash` below puts your edit aside. This block is safe to paste again any time I send a fix.
Open **Terminal** and paste:

```
cd ~/Desktop/sentinel
git stash
git pull
rm -f parth_gpu_run.py.bak
source .venv/bin/activate
pip install -r parth_gpu_requirements.txt
python parth_gpu_run.py
```

The first line it prints should say **runner 2026-11-23c**, then "Code update gpu-patch-1 applied". It skips the steps
that are already done and carries on; one comparison step runs again with the update. Then go on with step 5 below.

From now on it may print **fresh process N (the Apple GPU's memory is cleared this way)** during long steps. That's
normal: the step saves its progress, restarts itself and carries on.

## 1. Get the new code

Open **Terminal** (Cmd + Space, type `Terminal`, press Enter) and paste:

```
cd ~/Desktop/sentinel
git stash
git pull
```

## 2. Download the data pack

I'll send you **parth_gpu_pack.zip** (about 8.7 GB) on Google Drive. Download it and leave it in your **Downloads**
folder. Don't unzip it: the script does that. If Google Drive warns that it can't scan the file for viruses, click
**Download anyway**. (If your Mac unzipped it by itself into a `parth_gpu_pack` folder, leave that folder in Downloads:
the script reads it too.)

## 3. Add the libraries (once, about 2 minutes)

```
cd ~/Desktop/sentinel
source .venv/bin/activate
pip install -r parth_gpu_requirements.txt
```

## 4. Run everything

```
cd ~/Desktop/sentinel
source .venv/bin/activate
python parth_gpu_run.py
```

It works through 21 steps and prints a line for each one, plus "still running" every 10 minutes during long steps.
To see which steps are finished, open a second Terminal window and paste:

```
cd ~/Desktop/sentinel && source .venv/bin/activate && python parth_gpu_run.py status
```

## 5. Send the results back

When it prints **SEND THIS FILE BACK**, send me this file (Google Drive or WhatsApp):

```
~/Desktop/sentinel/parth_gpu_results.zip
```

If it prints **STOPPED** and **SEND THIS FILE BACK**, send the same file anyway, plus a screenshot of the Terminal
window. Don't run it again until I reply. If it prints **STOPPED** with a `pip install` line to paste instead, paste
that line, then run step 4 again: nothing needs to be sent.

## If something goes wrong

- `git pull` shows an error: send me a screenshot.
- `parth_gpu_pack.zip not found`: the zip isn't in Downloads. Move it there and run step 4 again.
- `not enough free disk`: free some space (about 40 GB is needed), then run step 4 again.
- The Mac gets warm: that's normal. A MacBook Air has no fan, so it slows itself down when hot; it still finishes.
  It helps to keep it on a hard, flat surface (not a bed or a cushion).
- Don't edit, move or delete anything in the `sentinel` folder: if something breaks, send me the screenshot and the
  results file, and I'll send a fix that `git pull` brings. Once you've sent the results, you can delete
  `parth_gpu_pack.zip` from Downloads.
