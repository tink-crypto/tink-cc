// Copyright 2017 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/util/test_util.h"

#include <stdarg.h>
#include <stdlib.h>

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <ios>
#include <iostream>
#include <memory>  // IWYU pragma: keep
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/keyset_handle.h"
#include "tink/util/protobuf_helper.h"
#include "proto/tink.pb.h"

using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace test {

std::string ReadTestFile(absl::string_view filename) {
  std::string full_filename = absl::StrCat(test::TmpDir(), "/", filename);
  std::ifstream input_stream(full_filename, std::ios::binary);
  if (!input_stream) {
    std::clog << "Cannot open file " << full_filename << '\n';
    exit(1);
  }
  std::stringstream buffer;
  buffer << input_stream.rdbuf();
  return buffer.str();
}

absl::StatusOr<std::string> HexDecode(absl::string_view hex) {
  std::string decoded;
  const bool result = absl::HexStringToBytes(hex, &decoded);
  if (!result) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Failed to decode hex: ", hex));
  }
  return decoded;
}

std::string HexDecodeOrDie(absl::string_view hex) {
  return HexDecode(hex).value();
}

std::string HexEncode(absl::string_view bytes) {
  std::string hexchars = "0123456789abcdef";
  std::string res(bytes.size() * 2, static_cast<char>(255));
  for (size_t i = 0; i < bytes.size(); ++i) {
    uint8_t c = static_cast<uint8_t>(bytes[i]);
    res[2 * i] = hexchars[c / 16];
    res[2 * i + 1] = hexchars[c % 16];
  }
  return res;
}

std::string TmpDir() {
  // Try the following environment variables in order:
  //  - TEST_TMPDIR: Set by `bazel test`.
  //  - TMPDIR: Set by some Tink tests.
  //  - TEMP, TMP: Set on Windows; they contain the tmp dir's path.
  for (const std::string& tmp_env_variable :
       {"TEST_TMPDIR", "TMPDIR", "TEMP", "TMP"}) {
    const char* env = getenv(tmp_env_variable.c_str());
    if (env && env[0] != '\0') {
      return env;
    }
  }
  // Tmp dir on Linux/macOS.
  return "/tmp";
}

void AddKeyData(const google::crypto::tink::KeyData& key_data, uint32_t key_id,
                google::crypto::tink::OutputPrefixType output_prefix,
                google::crypto::tink::KeyStatusType key_status,
                google::crypto::tink::Keyset* keyset) {
  Keyset::Key* key = keyset->add_key();
  key->set_output_prefix_type(output_prefix);
  key->set_key_id(key_id);
  key->set_status(key_status);
  *key->mutable_key_data() = key_data;
}

void AddKey(const std::string& key_type, uint32_t key_id,
            const portable_proto::MessageLite& new_key,
            google::crypto::tink::OutputPrefixType output_prefix,
            google::crypto::tink::KeyStatusType key_status,
            google::crypto::tink::KeyData::KeyMaterialType material_type,
            google::crypto::tink::Keyset* keyset) {
  google::crypto::tink::KeyData key_data;
  key_data.set_type_url(key_type);
  key_data.set_key_material_type(material_type);
  key_data.set_value(new_key.SerializeAsString());
  AddKeyData(key_data, key_id, output_prefix, key_status, keyset);
}

void AddTinkKey(const std::string& key_type, uint32_t key_id,
                const portable_proto::MessageLite& key,
                google::crypto::tink::KeyStatusType key_status,
                google::crypto::tink::KeyData::KeyMaterialType material_type,
                google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::TINK, key_status,
         material_type, keyset);
}

void AddLegacyKey(const std::string& key_type, uint32_t key_id,
                  const portable_proto::MessageLite& key,
                  google::crypto::tink::KeyStatusType key_status,
                  google::crypto::tink::KeyData::KeyMaterialType material_type,
                  google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::LEGACY, key_status,
         material_type, keyset);
}

void AddRawKey(const std::string& key_type, uint32_t key_id,
               const portable_proto::MessageLite& key,
               google::crypto::tink::KeyStatusType key_status,
               google::crypto::tink::KeyData::KeyMaterialType material_type,
               google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::RAW, key_status,
         material_type, keyset);
}

absl::Status ZTestUniformString(absl::string_view bytes) {
  double expected = bytes.size() * 8.0 / 2.0;
  double stddev = std::sqrt(static_cast<double>(bytes.size()) * 8.0 / 4.0);
  uint64_t num_set_bits = 0;
  for (uint8_t byte : bytes) {
    // Counting the number of bits set in byte:
    while (byte != 0) {
      num_set_bits++;
      byte = byte & (byte - 1);
    }
  }
  // Check that the number of bits is within 10 stddevs.
  if (abs(static_cast<double>(num_set_bits) - expected) < 10.0 * stddev) {
    return absl::OkStatus();
  }
  return absl::Status(
      absl::StatusCode::kInternal,
      absl::StrCat("Z test for uniformly distributed variable out of bounds; "
                   "Actual number of set bits was ",
                   num_set_bits, " expected was ", expected,
                   " 10 * standard deviation is 10 * ", stddev, " = ",
                   10.0 * stddev));
}

std::string Rotate(absl::string_view bytes) {
  std::string result(bytes.size(), '\0');
  for (size_t i = 0; i < bytes.size(); i++) {
    result[i] = (static_cast<uint8_t>(bytes[i]) >> 1) |
                (bytes[(i == 0 ? bytes.size() : i) - 1] << 7);
  }
  return result;
}

absl::Status ZTestCrosscorrelationUniformStrings(absl::string_view bytes1,
                                                 absl::string_view bytes2) {
  if (bytes1.size() != bytes2.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Strings are not of equal length");
  }
  std::string crossed(bytes1.size(), '\0');
  for (size_t i = 0; i < bytes1.size(); i++) {
    crossed[i] = bytes1[i] ^ bytes2[i];
  }
  return ZTestUniformString(crossed);
}

absl::Status ZTestAutocorrelationUniformString(absl::string_view bytes) {
  std::string rotated(bytes);
  std::vector<int> violations;
  for (size_t i = 1; i < bytes.size() * 8; i++) {
    rotated = Rotate(rotated);
    auto status = ZTestCrosscorrelationUniformStrings(bytes, rotated);
    if (!status.ok()) {
      violations.push_back(i);
    }
  }
  if (violations.empty()) {
    return absl::OkStatus();
  }
  return absl::Status(
      absl::StatusCode::kInternal,
      absl::StrCat("Autocorrelation exceeded 10 standard deviation at ",
                   violations.size(),
                   " indices: ", absl::StrJoin(violations, ", ")));
}

absl::StatusOr<std::unique_ptr<KeysetHandle>> FakeKeysetDeriver::DeriveKeyset(
    absl::string_view salt) const {
  Keyset::Key key;
  key.mutable_key_data()->set_type_url(
      absl::StrCat(name_.size(), ":", name_, salt));
  key.set_status(google::crypto::tink::KeyStatusType::UNKNOWN_STATUS);
  key.set_key_id(119);
  key.set_output_prefix_type(
      google::crypto::tink::OutputPrefixType::UNKNOWN_PREFIX);

  Keyset keyset;
  *keyset.add_key() = key;
  keyset.set_primary_key_id(119);
  ABSL_ASSIGN_OR_RETURN(KeysetHandle handle,
                        CleartextKeysetHandle::GetKeysetHandleOrError(
                            keyset, InsecureSecretKeyAccess::Get()));
  return std::make_unique<KeysetHandle>(std::move(handle));
}

}  // namespace test
}  // namespace tink
}  // namespace crypto
