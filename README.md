# [findcrypt3](https://github.com/polymorf/findcrypt-yara/tree/master).
## Updated fork, findcrypt3 for [yara-python](https://yara.readthedocs.io/en/latest/yarapython.html#yara.StringMatchInstance) > 4.2.3

IDA pro plugin to find crypto constants (and more)

### Before using findcrypt3, do not forget to throw findcrypt3.rules into the local folder with IDA plugins (IDA\plugins).

![bot](https://github.com/polymorf/findcrypt-yara/raw/master/screen.png)

## Installation Notes
If [yara](https://virustotal.github.io/yara/) is not already installed on your system, install the `yara-python` package with `pip`.

**Do not** install the `yara` pip package; it is not compatible with this plugin.

## User-defined rules

Custom rule files can be stored in :
 - `$HOME/.idapro/plugins/findcrypt-yara/*.rules` under Linux and MacOS.
- `%APPDATA%\\Roaming\\Hex-Rays\\IDA Pro\\plugin\\findcrypt-yara\\*.rules` under Windows.
