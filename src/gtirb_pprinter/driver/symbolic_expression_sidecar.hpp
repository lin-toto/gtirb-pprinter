#ifndef GTIRB_PPRINTER_SYMBOLIC_EXPRESSION_SIDECAR_HPP
#define GTIRB_PPRINTER_SYMBOLIC_EXPRESSION_SIDECAR_HPP

#include <cstdint>
#include <string>

namespace gtirb {
class Context;
class IR;
}

struct SymbolicExpressionSidecarResult {
  bool Success{false};
  uint64_t Groups{0};
  uint64_t Expressions{0};
  uint64_t Sizes{0};
  std::string Error;
};

SymbolicExpressionSidecarResult restoreSymbolicExpressionSidecar(
    gtirb::Context& Context, gtirb::IR& Ir, const std::string& Path);

#endif
