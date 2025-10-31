// Copyright 2020 Google LLC
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
// [START digital-signature-example]
// A utility for signing and verifying files using digital signatures.
#include <iostream>
#include <memory>
#include <ostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/config/global_registry.h"
#include "util/util.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/signature_config.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, mode, "", "Mode of operation (sign|verify)");
ABSL_FLAG(std::string, input_filename, "", "Filename to operate on");
ABSL_FLAG(std::string, signature_filename, "", "Path to the signature file");

namespace {

using ::crypto::tink::KeysetHandle;
using ::crypto::tink::PublicKeySign;
using ::crypto::tink::PublicKeyVerify;

constexpr absl::string_view kSign = "sign";
constexpr absl::string_view kVerify = "verify";

void ValidateParams() {
  // [START_EXCLUDE]
  CHECK(absl::GetFlag(FLAGS_mode) == kSign ||
        absl::GetFlag(FLAGS_mode) == kVerify)
      << "Invalid mode; must be `" << kSign << "` or `" << kVerify << "`"
      << '\n';
  CHECK(!absl::GetFlag(FLAGS_keyset_filename).empty())
      << "Keyset file must be specified";
  CHECK(!absl::GetFlag(FLAGS_input_filename).empty())
      << "Input file must be specified";
  CHECK(!absl::GetFlag(FLAGS_signature_filename).empty())
      << "Signature file must be specified";
  // [END_EXCLUDE]
}

}  // namespace

namespace tink_cc_examples {

// Digital signature example CLI implementation.
absl::Status DigitalSignatureCli(absl::string_view mode,
                                 const std::string& keyset_filename,
                                 const std::string& input_filename,
                                 const std::string& signature_filename) {
  absl::Status result = crypto::tink::SignatureConfig::Register();
  if (!result.ok()) return result;

  // Read the keyset from file.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadJsonCleartextKeyset(keyset_filename);
  if (!keyset_handle.ok()) return keyset_handle.status();

  // Read the input.
  absl::StatusOr<std::string> input_file_content = ReadFile(input_filename);
  if (!input_file_content.ok()) return input_file_content.status();

  if (mode == kSign) {
    absl::StatusOr<std::unique_ptr<PublicKeySign>> public_key_sign =
        (*keyset_handle)
            ->GetPrimitive<crypto::tink::PublicKeySign>(
                crypto::tink::ConfigGlobalRegistry());
    if (!public_key_sign.ok()) return public_key_sign.status();

    absl::StatusOr<std::string> signature =
        (*public_key_sign)->Sign(*input_file_content);
    if (!signature.ok()) return signature.status();

    return WriteToFile(*signature, signature_filename);
  } else {  // mode == kVerify
    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> public_key_verify =
        (*keyset_handle)
            ->GetPrimitive<crypto::tink::PublicKeyVerify>(
                crypto::tink::ConfigGlobalRegistry());
    if (!public_key_verify.ok()) return public_key_verify.status();

    // Read the signature.
    absl::StatusOr<std::string> signature_file_content =
        ReadFile(signature_filename);
    if (!signature_file_content.ok()) return signature_file_content.status();

    return (*public_key_verify)
        ->Verify(*signature_file_content, *input_file_content);
  }
}

}  // namespace tink_cc_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string keyset_filename = absl::GetFlag(FLAGS_keyset_filename);
  std::string input_filename = absl::GetFlag(FLAGS_input_filename);
  std::string signature_filename = absl::GetFlag(FLAGS_signature_filename);

  std::clog << "Using keyset in " << keyset_filename << " to " << mode;
  if (mode == kSign) {
    std::clog << " file " << input_filename
              << "; the resulting signature is written to "
              << signature_filename << '\n';
  } else {  // mode == kVerify
    std::clog << " the signature in " << signature_filename
              << " over the content of " << input_filename << '\n';
  }

  ABSL_CHECK_OK(tink_cc_examples::DigitalSignatureCli(
      mode, keyset_filename, input_filename, signature_filename));
  return 0;
}
// [END digital-signature-example]
