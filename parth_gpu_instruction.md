# Parth: the GPU runs on your MacBook (round 2)

This round runs the real experiments on your Mac's GPU. Like last time, you only paste commands into Terminal. You
need about **40 GB of free disk**. Keep the MacBook **plugged in with the lid open** the whole time. It takes a day or
more and can run overnight. If it stops (closed lid, restart, Ctrl+C), paste the step 4 commands again and it carries on
from where it stopped.

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
**Download anyway**.

## 3. Add two libraries (once, about 1 minute)

```
cd ~/Desktop/sentinel
source .venv/bin/activate
pip install sentencepiece==0.2.2 protobuf==5.29.6
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

If it prints **STOPPED**, send the same file anyway. Don't run it again until I reply.

## If something goes wrong

- `git pull` shows an error: send me a screenshot.
- `parth_gpu_pack.zip not found`: the zip isn't in Downloads. Move it there and run step 4 again.
- `not enough free disk`: free some space (about 40 GB is needed), then run step 4 again.
- The Mac gets warm and the fans spin: that's normal.
- Don't edit, move or delete anything in the `sentinel` folder. Once you've sent the results, you can delete
  `parth_gpu_pack.zip` from Downloads.
