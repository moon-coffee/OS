# ImplusOS Repo

# Overview
This repo is my homemade OS tree.

* Cannot build in non-interactive environment

<img width="960" height="540" alt="ImplusOS" src="https://github.com/moon-coffee/ImplusOS/blob/7d2ea7a94544d773c83d8c35323cbd7ac8e2e37d/Docs/Image/ImplusOS.png" />

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Static Badge](https://img.shields.io/badge/Repo-3.6MB-blue)
![Static Badge](https://img.shields.io/badge/Implus-OS-blue)


# How to make?
1, Install chaintools
  ```bash
  sudo apt install -y build-essential pkg-config git make cmake
  sudo apt install -y gcc-multilib g++-multilib
  sudo apt install -y gcc-x86-64-linux-gnu g++-x86-64-linux-gnu
  sudo apt install -y nasm
  sudo apt install -y binutils
  sudo apt install -y gnu-efi
  sudo apt install -y parted
  sudo apt install -y qemu-system-x86
  sudo apt install -y gdb
  ```

2, Make
  ```bash
  make
  make run
  ```

3, Complete

# Target Platform

  Linux (Ubuntu.. etc) Only

# Notes

  * VirtIO GPU Driver Support

  * Intel UHD Graphics 9th GPU Driver Support

  * FrameBuffer Generic GPU Driver Added
  
  * Serial Output Support

  * PCI Output Support

  * PS2 Mouse & Keyboard Support
  
  * FAT32 Driver Support
