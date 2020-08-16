#!/bin/bash

# This test sets up two transmission seeders and a cratetorrent leecher and
# asserts that cratetorrent downloads a single 1 MiB file from both seeds
# correctly.

set -e

source common.sh

# start the seeds (if not already running)
./start_transmission_seed.sh --name "${seed_container}" --ip "${seed_ip}"
./start_transmission_seed.sh --name "${seed2_container}" --ip "${seed_ip}"

torrent_name=1mb-test.txt
# the seeded file
src_path="${assets_dir}/${torrent_name}"
# and its metainfo
metainfo_path="${src_path}.torrent"
metainfo_cont_path="/cratetorrent/${torrent_name}.torrent"

################################################################################
# 1. Env setup
################################################################################

# start seeding the torrent, if it doesn't exist yet
if [ ! -f "${src_path}" ]; then
    echo "Starting seeding of torrent ${torrent_name} seeding"
    torrent_size=$(( 1024 * 1024 )) # 1 MiB
    # first, we need to generate a random file
    ./create_random_file.sh --path "${src_path}" --size "${torrent_size}"
    # then start seeding it by both seeds
    ./seed_new_torrent.sh \
        --name "${torrent_name}" \
        --path "${src_path}" \
        --seed "${seed_container}"
    ./seed_new_torrent.sh \
        --name "${torrent_name}" \
        --path "${src_path}" \
        --seed "${seed2_container}"
fi

# sanity check that after starting the seeding, the source files
# were properly generated
if [ ! -f "${metainfo_path}" ]; then
    echo "Error: metainfo ${metainfo_path} does not exist!"
    exit "${metainfo_not_found}"
fi
if [ ! -f "${src_path}" ]; then
    echo "Error: source file ${src_path} does not exist!"
    exit "${source_not_found}"
fi

################################################################################
# 2. Download
################################################################################

# where we download the torrent (the same path is used on both the host and in
# the container)
download_dir=/tmp/cratetorrent

# initialize download directory to state expected by the cratetortent-cli
if [ -d "${download_dir}" ]; then
    echo "Clearing download directory ${download_dir}"
    sudo rm -rf "${download_dir}"/*
elif [ -f "${download_dir}" ]; then
    echo "Error: file found where download directory ${download_dir} is supposed to be"
    exit "${dest_in_use}"
elif [ ! -d "${download_dir}" ]; then
    echo "Creating download directory ${download_dir}"
    mkdir -p "${download_dir}"
fi

# provide way to override the log level but default to tracing everything in the
# cratetorrent lib and binary
rust_log=${RUST_LOG:-cratetorrent=trace,cratetorrent_cli=trace}

# start cratetorrent leech container, which will run till the torrent is
# downloaded or an error occurs
time docker run \
    -ti \
    --rm \
    --env SEEDS="${seed_addr},${seed2_addr}" \
    --env METAINFO_PATH="${metainfo_cont_path}" \
    --env DOWNLOAD_DIR="${download_dir}" \
    --env RUST_LOG="${rust_log}" \
    --mount type=bind,src="${metainfo_path}",dst="${metainfo_cont_path}" \
    --mount type=bind,src="${download_dir}",dst="${download_dir}" \
    cratetorrent-cli

################################################################################
# 3. Verification
################################################################################

# the final download destination on the host
download_path="${download_dir}/${torrent_name}"

# first check if the file was downloaded in the expected path
if [ ! -f "${download_path}" ]; then
    echo "FAILURE: downloaded file ${download_path} does not exist!"
    exit "${download_not_found}"
fi

# assert that the downloaded file is the same as the original
verify_file "${src_path}" "${download_path}"

echo
echo "SUCCESS: downloaded file matches source file"
