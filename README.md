# send-audio-reolink

Small **Python 3** utility that sends audio (e.g. MP3 from a URL) to a **Reolink** doorbell / camera using **ONVIF RTSP audio backchannel** (the same idea as [go2rtc](https://github.com/AlexxIT/go2rtc)’s two-way audio path: `DESCRIBE` with `Require: www.onvif.org/ver20/backchannel`, Digest auth on every RTSP request, `SETUP` for all SDP tracks, `PLAY`, then **G.711** RTP in **1024-byte** frames over **TCP interleaved** transport).

**Repository:** [github.com/paulopmt1/send-audio-reolink](https://github.com/paulopmt1/send-audio-reolink)

```bash
git clone git@github.com:paulopmt1/send-audio-reolink.git
cd send-audio-reolink
```

## Requirements

- **Python 3.9+**
- **ffmpeg** on your `PATH`
- Camera on the **same LAN** (or routable to you), firmware with **ONVIF Profile T / backchannel** where applicable

## Usage

```bash
python3 send_audio.py \
  --camera 'rtsp://USER:PASSWORD@192.168.1.50:554/Preview_01_sub' \
  --url 'https://samplelib.com/mp3/sample-3s.mp3'
```

**Lower latency** (recommended for short clips / doorbell chimes; omits `-re` and uses minimal probing):

```bash
python3 send_audio.py \
  --camera 'rtsp://USER:PASSWORD@192.168.1.50:554/Preview_01_sub' \
  --url 'https://samplelib.com/mp3/sample-3s.mp3' \
  --low-latency
```

**RTSP trace** (stderr):

```bash
python3 send_audio.py \
  --camera 'rtsp://USER:PASSWORD@192.168.1.50:554/Preview_01_sub' \
  --url 'https://samplelib.com/mp3/sample-3s.mp3' \
  --debug
```

### `--camera`

Use the same **sub-stream** (or main) RTSP URL you use in go2rtc / NVR, including **username and password** in the URL. Example paths (names vary by model):

- `.../Preview_01_sub`
- `.../h264Preview_01_main`

### `--url`

Any input **ffmpeg** can decode from `-i` (HTTPS MP3, local file path, etc.). Local files avoid HTTPS/TLS startup delay.

## Security

- Avoid committing real **credentials**; prefer environment or shell history hygiene.
- **Rotate** the camera password if it was ever pasted into a shared log or ticket.

## Limitations

- Long audio with `--low-latency` may be sent **faster than real-time** (decoder runs at full speed); use default mode (without `--low-latency`) for paced streaming.
- Behaviour depends on **firmware** and SDP (PCMA vs PCMU); the script picks the backchannel track from the SDP.

## License

MIT
