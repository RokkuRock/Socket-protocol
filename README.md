# Socket Programming

Self-project with MIT-license, containing simple practices across platforms, currently including **Windows 10**, and linux **ubuntu** distro. All of the practices are written in pure C library providing client and server data transmission.


# UDP
- Standard Library Practice
- Linux Ubuntu [22.04.2 LTS]
- Microsoft Windows [10.0.19045.3086]

# TCP
- winClient
- Ubuntu Server / Client
- Linux Ubuntu [22.04.2 LTS]
- Microsoft Windows [10.0.19045.3086]

# LogDigestLibuv_linux
- LogParse Server
  - Host for receiving multiple log strings, and use I/O to write and save strings as log data in xml format
  - Generate xml file according to current timestamp
- Single / Multithreaded Server host
  - Asynchronous processing using libuv library
  - Threadpool exercise (thread_manager)
- LogDigest API Integration
  - Integrate Ubuntu client and LogDigest API to send real-world log data formats
  - Support Common Log formats, including syslog, multilog, and windows_event_log structured data

# Building Environment:
- Using vcpkg (windows 10)for library management for include path, bin (uv.dll), include (uv, uv.h) , lib (uv.lib,) 
- Include "logdigest.h", "cJSON.h" in your working directory
- gcc compile with "logdigest.c", "cJSON.c", "-luv",
- Sample "arg" for windows 10 environment (task.json)
  -  "args": [
				"-g",
                "${file}",
                "-o",
                "${fileDirname}\\${fileBasenameNoExtension}.exe",
                "-I",
                "C:\\vcpkg\\installed\\x64-windows\\include",
                "-L",
                "C:\\vcpkg\\installed\\x64-windows\\lib",
                "-luv",
                "-lws2_32",
                "-liphlpapi",
                "-luserenv",
    ],
- Sample "arg" for linux ubuntu building environment (task.json)
  - "args": [
				"-fdiagnostics-color=always",
				"-g",
				"${file}",
				"-o",
				"${fileDirname}/${fileBasenameNoExtension}",
				"-luv",
				"logdigest.c",
				"cJSON.c",
			], 
