# ScamShield AI
**Detect. Understand. Stay Safe.**

A cybersecurity-awareness MVP that analyses suspicious messages with **Gemma 4 E2B running locally through Ollama**.

## Architecture

- Streamlit frontend (`app.py`)
- Python analysis layer (`analyzer.py`)
- Ollama local HTTP API (`/api/chat`)
- Model: `gemma4:e2b`
- No Gemini API and no cloud LLM integration

## Laptop 1 — AI backend

1. Install Ollama and download the model:
   ```powershell
   ollama pull gemma4:e2b
   ```
2. Verify:
   ```powershell
   ollama run gemma4:e2b "Explain phishing in two sentences."
   ```
3. Allow Ollama to listen on the local network. In PowerShell, run this in the same terminal session:
   ```powershell
   $env:OLLAMA_HOST="0.0.0.0:11434"
   ollama serve
   ```
   If Ollama is already running as a Windows background app/service, quit it from the system tray first, then run the commands above. Keep this terminal open.
4. Find Laptop 1's IPv4 address:
   ```powershell
   ipconfig
   ```
   Note the IPv4 Address for the active Wi-Fi/Ethernet adapter.
5. Allow inbound TCP port 11434 in Windows Defender Firewall only on a trusted private network. Do not expose this port to the public internet.

## Laptop 2 — Streamlit frontend

1. Copy this project folder to Laptop 2 or clone the GitHub repository.
2. Open the folder in VS Code. In PowerShell:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
3. Set Laptop 1's IP address (replace the example):
   ```powershell
   $env:OLLAMA_BASE_URL="http://192.168.1.10:11434"
   $env:OLLAMA_MODEL="gemma4:e2b"
   ```
4. Start the app:
   ```powershell
   streamlit run app.py
   ```
5. Open the local Streamlit URL printed in the terminal, usually `http://localhost:8501`.

For a one-laptop demo, leave `OLLAMA_BASE_URL` unset; it defaults to `http://127.0.0.1:11434`.

## Features

- Colour-coded risk banner, exact-quote evidence, safe actions, uncertainties
- Scam catalogue and Indian cyber-help pages
- Large-text and high-contrast accessibility options

## Testing accuracy

29 fictional test messages (scams, normal messages and unclear ones) live in `tests/test_messages.json`. With Ollama running:

```powershell
.\.venv\Scripts\python.exe run_tests.py
.\.venv\Scripts\python.exe run_tests.py --ids S02 L01   # only some messages
```

It prints PASS/FAIL per message, counts missed scams and false alarms, and saves results to `tests/results/`.

## Files

- `app.py` — polished Streamlit interface, scanner, catalogue, and official resources
- `analyzer.py` — Ollama connection, prompt, JSON parsing, and evidence validation
- `requirements.txt` — Python dependencies

## Safety and limitations

- The score is an indicative awareness score, not a probability of fraud.
- The app cannot prove fraud or authenticate a sender.
- Evidence quotations are checked against the original message; invalid quotations are removed.
- Model output may still be incomplete or wrong. Independently verify claims.
- Do not paste passwords, OTPs, PINs, or unnecessary personal information.
- Messages are sent to the configured Ollama server. With the default local configuration, analysis runs on your machine; with a two-laptop setup, text is sent over your local network to Laptop 1.
- This is a hackathon MVP, not a certified security product.

## Troubleshooting

- **Cannot connect to Ollama:** ensure `ollama serve` is running and the configured IP/port is correct.
- **Model not found:** on Laptop 1 run `ollama list` and `ollama pull gemma4:e2b`.
- **Laptop 2 cannot connect:** check both laptops are on the same trusted network, Windows firewall allows TCP 11434 on Private networks, and Laptop 1's IP has not changed.
