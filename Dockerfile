FROM ubuntu:18.04

WORKDIR /cratetorrent

COPY /target/release/cratetorrent-cli .

CMD ./cratetorrent-cli --listen "${LISTEN}" --seeds "${SEEDS}" --metainfo "${METAINFO_PATH}" --download-dir "${DOWNLOAD_DIR}"
