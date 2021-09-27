# ResourceWrapper
Reduce disk usage by enabling applications to load modern high compression ratio formats.

# Build
Run following commands in Native Tools Command Prompt:
```
meson setup build --buildtype=release --backend=vs
meson compile -C build
```
ResourceWrapper.dll will be found in "build\src"

# How to use
## Compress application
Compress png / wav files into webp / flac and put them in the original directory.
(e.g.: "Data\Graphics\picture.png" -> "Data\Graphics\picture.webp")

## Run
Make sure your application and ResourceWrapper.dll architecture match.  
Use rundll32.exe to run ResourceWrapper:
```
rundll32.exe ResourceWrapper.dll,Run %PATH_TO_GAME_EXE%
```
ResourceWrapper will intercept the CreateFile() call and generate the required file.
