// Copyright 2024 Google LLC
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

#include "tink/json/internal/tink_type_resolver.h"

#include <string>

#include "google/protobuf/descriptor.pb.h"
#include "absl/log/check.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/descriptor_database.h"
#include "google/protobuf/util/type_resolver.h"
#include "google/protobuf/util/type_resolver_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::google::protobuf::DescriptorPool;
using ::google::protobuf::FileDescriptorProto;
using ::google::protobuf::SimpleDescriptorDatabase;
using ::google::protobuf::util::NewTypeResolverForDescriptorPool;
using ::google::protobuf::util::TypeResolver;

const char kTypeUrlPrefix[] = "type.googleapis.com";

// Base64-encoded serialized FileDescriptorProto of tink.proto, without
// source_code_info.
const char kTinkFileDescBase64[] =
    "CiF0aGlyZF9wYXJ0eS90aW5rL3Byb3RvL3RpbmsucHJvdG8SEmdvb2dsZS5jcnlwdG8udGluay"
    "JaCgtLZXlUZW1wbGF0ZRIQCgh0eXBlX3VybBgBIAEoCRINCgV2YWx1ZRgCIAEoDBIqChJvdXRw"
    "dXRfcHJlZml4X3R5cGUYAyABMhBPdXRwdXRQcmVmaXhUeXBlIugBCgdLZXlEYXRhEhAKCHR5cG"
    "VfdXJsGAEgASgJEisKBXZhbHVlGAIgASgMQhy6PhkSCRAACgVjdHlwZRoMU1RSSU5HX1BJRUNF"
    "EigKEWtleV9tYXRlcmlhbF90eXBlGAMgATIPS2V5TWF0ZXJpYWxUeXBlInQKD0tleU1hdGVyaW"
    "FsVHlwZRIXChNVTktOT1dOX0tFWU1BVEVSSUFMEAASDQoJU1lNTUVUUklDEAESFgoSQVNZTU1F"
    "VFJJQ19QUklWQVRFEAISFQoRQVNZTU1FVFJJQ19QVUJMSUMQAxIKCgZSRU1PVEUQBCKpAQoGS2"
    "V5c2V0EhYKDnByaW1hcnlfa2V5X2lkGAEgASgNEg4KA2tleRgCIAMyA0tleRp3CgNLZXkSFwoI"
    "a2V5X2RhdGEYASABMgdLZXlEYXRhEhsKBnN0YXR1cxgCIAEyDUtleVN0YXR1c1R5cGUSDgoGa2"
    "V5X2lkGAMgASgNEioKEm91dHB1dF9wcmVmaXhfdHlwZRgEIAEyEE91dHB1dFByZWZpeFR5cGUi"
    "swEKCktleXNldEluZm8SFgoOcHJpbWFyeV9rZXlfaWQYASABKA0SFwoIa2V5X2luZm8YAiADMg"
    "dLZXlJbmZvGnQKB0tleUluZm8SEAoIdHlwZV91cmwYASABKAkSGwoGc3RhdHVzGAIgATINS2V5"
    "U3RhdHVzVHlwZRIOCgZrZXlfaWQYAyABKA0SKgoSb3V0cHV0X3ByZWZpeF90eXBlGAQgATIQT3"
    "V0cHV0UHJlZml4VHlwZSJKCg9FbmNyeXB0ZWRLZXlzZXQSGAoQZW5jcnlwdGVkX2tleXNldBgC"
    "IAEoDBIdCgtrZXlzZXRfaW5mbxgDIAEyCktleXNldEluZm8qTQoNS2V5U3RhdHVzVHlwZRISCg"
    "5VTktOT1dOX1NUQVRVUxAAEgsKB0VOQUJMRUQQARIMCghESVNBQkxFRBACEg0KCURFU1RST1lF"
    "RBADKlIKEE91dHB1dFByZWZpeFR5cGUSEgoOVU5LTk9XTl9QUkVGSVgQABIICgRUSU5LEAESCg"
    "oGTEVHQUNZEAISBwoDUkFXEAMSCwoHQ1JVTkNIWRAEQsEBuj4wEhAQAAoMamF2YV9wYWNrYWdl"
    "Ohxjb20uZ29vZ2xlLmNyeXB0by50aW5rLnByb3Rvuj4fEhcQAAoTamF2YV9tdWx0aXBsZV9maW"
    "xlcxoEdHJ1Zbo+"
    "RxIOEAAKCmdvX3BhY2thZ2U6NWdpdGh1Yi5jb20vdGluay1jcnlwdG8vdGluay1nby92Mi9wcm"
    "90by90aW5rX2dvX3Byb3Rvuj4fEhUQAAoRb2JqY19jbGFzc19wcmVmaXg6BlRJTktQQmIGcHJv"
    "dG8z";

FileDescriptorProto TinkFileDescProto() {
  std::string serialized_file_desc;
  CHECK(absl::Base64Unescape(kTinkFileDescBase64, &serialized_file_desc));
  FileDescriptorProto file_desc_proto;
  file_desc_proto.ParseFromString(serialized_file_desc);
  return file_desc_proto;
}

TypeResolver* CreateTinkTypeResolver() {
  static SimpleDescriptorDatabase* database = new SimpleDescriptorDatabase();
  database->Add(TinkFileDescProto());
  static const DescriptorPool* pool = new DescriptorPool(database);
  return NewTypeResolverForDescriptorPool(kTypeUrlPrefix, pool);
}

}  // namespace

TypeResolver* GetTinkTypeResolver() {
  static TypeResolver* resolver = CreateTinkTypeResolver();
  return resolver;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
