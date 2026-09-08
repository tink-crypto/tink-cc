// Copyright 2019 Google LLC
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
#ifndef TINK_CORE_TEMPLATE_UTIL_H_
#define TINK_CORE_TEMPLATE_UTIL_H_

#include <cstddef>
#include <tuple>
#include <type_traits>

#include "absl/meta/type_traits.h"

namespace crypto {
namespace tink {

// A list of types
template <typename... P>
struct List {};

namespace internal {

// A helper class template which decides if the TestType occurs in the Tuple
// For example, OccursInTuple<int, std::tuple<float, float>>::value == false,
// and OccursInTuple<int, std::tuple<float, int>>::value == true. Not intended
// to be used directly.

// First declare the template which always takes two parameters.
template <typename TestType, typename Tuple>
struct OccursInTuple;

template <typename TestType, typename... Ts>
struct OccursInTuple<TestType, std::tuple<Ts...>>
    : std::bool_constant<(std::is_same_v<TestType, Ts> || ...)> {};

// The class HasDuplicates. Defines ::value as true in case the given list has
// a duplicate, false otherwise.
template <typename... Args>
struct HasDuplicates;

// Empty list has no duplicates.
template <>
struct HasDuplicates<> : std::false_type {};

// Non-empty list has a duplicate if the first appears in the rest, or if the
// rest has a duplicate.
template <typename First, typename... Rest>
struct HasDuplicates<First, Rest...>
    : std::bool_constant<((std::is_same_v<First, Rest> || ...) ||
                          HasDuplicates<Rest...>::value)> {};

// The class IndexOf. Defines ::value as zero-based index of first element of
// type T in the List.
template <typename T, typename List>
struct IndexOf;
template <typename T, typename... Elements>
struct IndexOf<T, List<T, Elements...>>
    : public std::integral_constant<std::size_t, 0> {};
template <typename T, typename E, typename... Elements>
struct IndexOf<T, List<E, Elements...>>
    : public std::integral_constant<std::size_t,
                                    1 + IndexOf<T, List<Elements...>>::value> {
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_TEMPLATE_UTIL_H_
