###################
Tentang Aplikasi
###################

Aplikasi packet sniffing ini merupakan tugas akhir yang diajukan oleh penulis untuk memenuhi syarat kelulusan sebagai mahasiswa S-1 Teknik Informatika Unpad.
aplikasi ini hanya bisa digunakan di sistem operasi berbasis linux karena pembuatan aplikasi menggunakan teknik socket programming yang mengandalkan library socket dari kernel linux.

*******************
Release Information
*******************

This repo contains finished project.

**************************
Changelog and New Features
**************************
V 1.0

- Jumlah packet yang ditangkap ditentukan oleh user
- Penyimpanan log ke file txt
- menload log langsung di aplikasi tanpa perlu membuka file txt
- counter jumlah packet yang berhasil dicapture

V 1.1

- Menampilkan warning jika tombol load log file diklik namun file log.txt tidak tersedia

*******************
Requirements
*******************
- gcc and gtk3lib-devel package are installed on the machine.

************
Installation
************
Run the makefile and then execute the ./packetsniffing from terminal.



