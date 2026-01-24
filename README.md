# StarResonanceMahjongAutoAna

StarResonanceMahjongAutoAna is a Windows-based analysis and automation pipeline
for **Star Resonance Mahjong** data.

This project focuses on:
- Network packet capture and preprocessing
- Binary data extraction and analysis
- Automated analysis pipelines for Mahjong-related protocols

The project itself does **not** modify the game client and is intended
for **analysis, research, and personal automation purposes only**.

---

## Features

- Packet capture pipeline based on Windows network interfaces
- Binary (`.bin`) extraction from network traffic
- Protocol-aware data analysis tools
- Modular pipeline design for further extension

---

## Requirements

- Windows 10 / 11 (64-bit)
- Python 3.12+ (for source usage)
- Administrator privileges (required for packet capture)
- Npcap installed (WinPcap-compatible mode recommended)

---

## External Dependency (Third-party Executable)

This project **calls an external executable** developed by a third party:

- **mahjong-helper**
  - Author: Σndless
  - License: MIT
  - Official repository: https://github.com/EndlessCheng/mahjong-helper

### Important Notes

- `mahjong-helper.exe` is **NOT included** in this repository.
- This project does **not** modify, embed, or redistribute the executable by default.
- Users must download the executable **separately from the official source**
  and place it in the expected location (e.g. the same directory or a configured path).

The original MIT License is preserved in:

