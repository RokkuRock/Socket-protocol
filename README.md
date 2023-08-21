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
  - Host for receiving multiple log strings, and use I/O to write and save log data into xml format
  - Generate xml file according to current timestamp
- Single / Multithreaded Server host
  - Asynchronous processing using libuv library
  - Threadpool exercise
- LogDigest API Integration
  - Combine Ubuntu client and LogDigest API to send real-world log data
  - Common Log formats, including syslog, multilog, and window_event_log structured data

# Building Environment:
- vcpkg for include path, bin (uv.dll, uv.lib,)
- logdigest.h
