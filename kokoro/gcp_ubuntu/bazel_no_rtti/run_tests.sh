#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# TESTING LOCALLY:
# First install Docker (go/installdocker). We need sudoless Docker.
# Next, the following commands install tink-cc into a new temporary directory
# and set TINK_BASE_DIR to tell the script which directory to use:
# $ export TINK_BASE_DIR="$(mktemp -d)"
# $ cd ${TINK_BASE_DIR}
# $ git clone sso://ise-crypto-internal/tink-cc tink_cc
# You can also patch a CL/PR with the command you find in the top right of the
# GOB review page.
#
# Next, set the container image to the one you want to use.
# $ export CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-cc-base:latest"
# If you want to try with a new docker image, you can build it with
# $ docker buildx build <full path for folder containing Dockerfile>
# This outputs a hash you can use:
# $ export CONTAINER_IMAGE="sha256:<hash>".
# Run the script:
# $ sh tink_cc/kokoro/gcp_ubuntu/bazel_no_rtti/run_tests.sh

# Generated with openssl rand -hex 10
echo "================================================================================"
echo "Tink Script ID: 534f5ab0007021b44815 (quickly find the script from logs)"
echo "================================================================================"
set -euox pipefail

if [[ ! -v TINK_BASE_DIR ]] ; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
fi
readonly TINK_BASE_DIR
echo "TINK_BASE_DIR is ${TINK_BASE_DIR}"
if [[ ! -v CONTAINER_IMAGE ]] ; then
  source \
    "${TINK_BASE_DIR}/tink_cc/kokoro/testutils/cc_test_container_images.sh"
  CONTAINER_IMAGE="${TINK_CC_BASE_IMAGE}"
fi
readonly CONTAINER_IMAGE
echo "CONTAINER_IMAGE is ${CONTAINER_IMAGE}"

cd "${TINK_BASE_DIR}/tink_cc"

# Keep the remote-cache credential out of the checkout. The checkout is
# bind-mounted into the build container and transferred back as a job
# artifact, so a key written here would outlive the job.
readonly CACHE_KEY_DIR="$(mktemp -d /tmp/tink-cache-key.XXXXXX)"
trap 'rm -rf "${CACHE_KEY_DIR}" /tmp/env_variables.txt' EXIT
: > /tmp/env_variables.txt
CACHE_KEY_MOUNT=()
if [[ -v TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET ]]; then
  # The build runs as an unprivileged user inside the container; make the
  # read-only mount readable without making it writable.
  install -m 444 "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" "${CACHE_KEY_DIR}/cache_key"
  cat <<EOF > /tmp/env_variables.txt
BAZEL_REMOTE_CACHE_NAME=${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/${TINK_CC_BASE_IMAGE_HASH}
EOF
  CACHE_KEY_MOUNT=(
    --mount "type=bind,src=${CACHE_KEY_DIR}/cache_key,dst=/tmp/cache_key,readonly"
  )
fi
readonly CACHE_KEY_MOUNT

### =========================================== EMBEDDED SCRIPT: _do_run_test.sh
### The _do_run_test.sh script will run as "tinkuser"
cat <<'EOF' > _do_run_test.sh
#!/bin/bash
set -euo pipefail

cd /home/tinkuser/tink_cc/

CACHE_FLAGS=()
if [[ -n "${BAZEL_REMOTE_CACHE_NAME:-}" ]]; then
  CACHE_FLAGS+=("--remote_cache=https://storage.googleapis.com/${BAZEL_REMOTE_CACHE_NAME}")
  CACHE_FLAGS+=("--google_credentials=/tmp/cache_key")
  # Avoid downloading cached intermediate/top-level build outputs unless needed
  # by a local action.
  CACHE_FLAGS+=("--remote_download_minimal")
fi
readonly CACHE_FLAGS

echo "---------- CHECKING RTTI TYPE IDS"
./tools/check_rtti_type_ids.sh tink

# More targets will be added as -fno-rtti support expands, eventually replacing
# this list with '...'.
readonly TARGETS=(
  "//tink:key"
  "//tink:parameters"
  "//tink/internal:rtti"
  "//tink/internal:rtti_test"
  "//tink/internal:util"
  "//tink/mac:aes_cmac_key"
  "//tink/mac:aes_cmac_parameters"
  "//tink/mac:aes_cmac_parameters_test"
  "//tink/mac:hmac_key"
  "//tink/mac:hmac_parameters"
  "//tink/mac:hmac_parameters_test"
  "//tink/mac:mac_key"
  "//tink/mac:mac_parameters"
  "//tools:check_rtti_type_ids_test"
)

# --nobuild_tests_only ensures non-test targets in TARGETS are built too.
echo "---------- BUILDING AND TESTING WITH -fno-rtti"
time bazelisk test --nobuild_tests_only \
  --cxxopt=-fno-rtti --cxxopt=-DTINK_USE_CUSTOM_RTTI \
  "${CACHE_FLAGS[@]}" -- "${TARGETS[@]}"
EOF
### ======================================================= END: _do_run_test.sh

chmod +x _do_run_test.sh

### =========================== EMBEDDED SCRIPT: _cp_switch_user_and_run_test.sh
### The _cp_switch_user_and_run_test.sh script will cp the build tree to a
### directory readable for tinkuser then execute _do_run_test.sh.
cat <<'EOF' > _cp_switch_user_and_run_test.sh
set -euo pipefail

echo "=== COPYING /tink_orig_dir to /home/tinkuser"

cp -r /tink_orig_dir/tink_cc /home/tinkuser
chown --recursive tinkuser:tinkgroup /home/tinkuser/tink_cc

su tinkuser /usr/bin/bash -c "/home/tinkuser/tink_cc/_do_run_test.sh"
exit
EOF
### ======================================= END: _cp_switch_user_and_run_test.sh


chmod +x _cp_switch_user_and_run_test.sh

if [[ ! -z "${TINK_GCR_SERVICE_KEY:-}" ]]; then
  gcloud auth activate-service-account --key-file="${TINK_GCR_SERVICE_KEY}"
  gcloud config set project tink-test-infrastructure
  gcloud auth configure-docker us-docker.pkg.dev --quiet
fi

echo "-- PULLING DOCKER IMAGE"
time docker pull "${CONTAINER_IMAGE}"

echo "-- RUNNING DOCKER"
# The host executes this driver from the checkout. Keep the automation
# directory read-only so container code cannot append to it.
time docker run \
  --network="host" \
  --mount type=bind,src="${TINK_BASE_DIR}",dst=/tink_orig_dir \
  --mount type=bind,src="${TINK_BASE_DIR}/tink_cc/kokoro",dst=/tink_orig_dir/tink_cc/kokoro,readonly \
  "${CACHE_KEY_MOUNT[@]}" \
  --env-file /tmp/env_variables.txt \
  --rm \
  "${CONTAINER_IMAGE}" \
  bash -c "/tink_orig_dir/tink_cc/_cp_switch_user_and_run_test.sh"
