// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/internal/testing/wycheproof_util.h"

#include <cstddef>
#include <fstream>
#include <iterator>
#include <string>

#include "google/protobuf/struct.pb.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/json/json.h"
#include "google/protobuf/util/json_util.h"
#include "tink/internal/test_file_util.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace wycheproof_testing {

using ::crypto::tink::subtle::EllipticCurveType;
using ::crypto::tink::subtle::HashType;
using ::google::protobuf::util::JsonParseOptions;
using ::google::protobuf::util::JsonStringToMessage;

std::string GetBytesFromHexValue(const google::protobuf::Value& val) {
  std::string s(val.string_value());
  if (s.size() % 2 != 0) {
    // ECDH private key may have odd length.
    s = "0" + s;
  }
  return crypto::tink::test::HexDecodeOrDie(s);
}

absl::StatusOr<google::protobuf::Struct> ReadTestVectorsV1(
    const std::string& filename) {
  std::string test_vectors_path = crypto::tink::internal::RunfilesPath(
      absl::StrCat("testvectors_v1/", filename));

  std::ifstream input_stream;
  input_stream.open(test_vectors_path);
  std::string input_string =
      std::string(std::istreambuf_iterator<char>(input_stream), {});

  google::protobuf::Struct proto;
  JsonParseOptions json_parse_options;
  absl::Status status =
      JsonStringToMessage(input_string, &proto, json_parse_options);
  if (!status.ok()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid JSON");
  }
  return proto;
}

HashType GetHashTypeFromValue(const google::protobuf::Value &val) {
  std::string md(val.string_value());
  if (md == "SHA-1") {
    return HashType::SHA1;
  } else if (md == "SHA-256") {
    return HashType::SHA256;
  } else if (md == "SHA-384") {
    return HashType::UNKNOWN_HASH;
  } else if (md == "SHA-512") {
    return HashType::SHA512;
  } else {
    return HashType::UNKNOWN_HASH;
  }
}

EllipticCurveType GetEllipticCurveTypeFromValue(
    const google::protobuf::Value &val) {
  std::string curve(val.string_value());
  if (curve == "secp256r1") {
    return EllipticCurveType::NIST_P256;
  } else if (curve == "secp384r1") {
    return EllipticCurveType::NIST_P384;
  } else if (curve == "secp521r1") {
    return EllipticCurveType::NIST_P521;
  } else {
    return EllipticCurveType::UNKNOWN_CURVE;
  }
}

std::string GetIntegerFromHexValue(const google::protobuf::Value &val) {
  std::string hex(val.string_value());
  // Since val is a hexadecimal integer it can have an odd length.
  if (hex.size() % 2 == 1) {
    // Avoid a leading 0 byte.
    if (hex[0] == '0') {
      hex = std::string(hex, 1, hex.size() - 1);
    } else {
      hex = "0" + hex;
    }
  }
  return crypto::tink::test::HexDecode(hex).value();
}

}  // namespace wycheproof_testing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
