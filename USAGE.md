# PyNikto Usage Guide

## Quick Start on Kali Linux

### Step 1: Navigate to the Correct Directory

```bash
# If you cloned multiple times, go to the main directory
cd ~/pynikto

# Or if you're in a nested directory, go up
cd ~/pynikto/pynikto/pynikto  # Wrong - too nested!
cd ~/pynikto  # Correct - main directory
```

### Step 2: Activate Virtual Environment

```bash
# Activate the virtual environment
source venv/bin/activate

# You should see (venv) at the start of your prompt
# Example: (venv)─(kali㉿kali)-[~/pynikto]
```

### Step 3: Run PyNikto

```bash
# Check version
python3 nikto.py -Version

# Run a scan
python3 nikto.py -host example.com

# Scan with HTTPS
python3 nikto.py -host example.com -port 443 -ssl
```

## Common Mistakes

### ❌ Wrong Commands

```bash
# DON'T use these:
py pynikto          # Wrong - 'py' is not the command
pynikto             # Wrong - no such command
python nikto.py     # Might work, but use python3
```

### ✅ Correct Commands

```bash
# DO use these:
python3 nikto.py -Version
python3 nikto.py -host example.com
python3 nikto.py -host example.com -port 80
```

## Directory Structure

After cloning, you should have:

```
~/pynikto/              # Main directory (where you should be)
├── nikto.py           # Main script
├── api.py
├── requirements.txt
├── venv/              # Virtual environment (created during install)
│   └── ...
├── plugins/
├── databases/
└── ...
```

**You should be in**: `~/pynikto/` (not nested deeper)

## Complete Workflow Example

```bash
# 1. Clone (only once!)
git clone https://github.com/sudo-zenjy/pynikto.git
cd pynikto

# 2. Install (if not done already)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Use PyNikto
source venv/bin/activate  # Activate venv
python3 nikto.py -host scanme.nmap.org -port 80

# 4. When done
deactivate  # Deactivate venv (optional)
```

## Quick Reference

| Task | Command |
|------|---------|
| Activate venv | `source venv/bin/activate` |
| Check version | `python3 nikto.py -Version` |
| Basic scan | `python3 nikto.py -host example.com` |
| HTTPS scan | `python3 nikto.py -host example.com -ssl` |
| Custom port | `python3 nikto.py -host example.com -port 8080` |
| With crawling | `python3 nikto.py -host example.com -crawl` |
| JSON output | `python3 nikto.py -host example.com -Format json -output results.json` |
| Deactivate venv | `deactivate` |

## Troubleshooting

### "Command not found" or "No such file"
- Make sure you're in the `pynikto` directory: `cd ~/pynikto`
- Check file exists: `ls nikto.py`

### "Module not found" errors
- Activate virtual environment: `source venv/bin/activate`
- Install dependencies: `pip install -r requirements.txt`

### "Permission denied"
- Make script executable: `chmod +x nikto.py`
- Or just use: `python3 nikto.py` (no need for ./)

### Wrong directory
- Check where you are: `pwd`
- Go to correct directory: `cd ~/pynikto`
- List files: `ls` (should see `nikto.py`)

---

**Remember**: 
- Always activate venv: `source venv/bin/activate`
- Use `python3 nikto.py` (not `py pynikto`)
- Make sure you're in the `pynikto` directory
