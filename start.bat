@echo off
cd /d "%~dp0"
echo Starting from: %cd%
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m streamlit run app.py
) else (
  echo.
  echo No .venv folder found here.
  echo Open PowerShell in this folder and run:  py -m venv .venv
  echo Then:  .venv\Scripts\python.exe -m pip install -r requirements.txt
)
echo.
pause
