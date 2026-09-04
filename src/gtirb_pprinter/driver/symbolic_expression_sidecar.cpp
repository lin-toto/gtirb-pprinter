#include "symbolic_expression_sidecar.hpp"

#include <gtirb/ByteInterval.hpp>
#include <gtirb/Casting.hpp>
#include <gtirb/IR.hpp>
#include <gtirb/Node.hpp>
#include <gtirb/Symbol.hpp>
#include <gtirb_pprinter/AuxDataSchema.hpp>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <string>

namespace {

constexpr std::array<unsigned char, 8> Magic = {'G', 'T', 'I', 'R',
                                                 'B', 'S', 'E', '1'};

struct GzCloser {
  void operator()(gzFile_s* File) const {
    if (File) {
      gzclose(reinterpret_cast<gzFile>(File));
    }
  }
};
using UniqueGzFile = std::unique_ptr<gzFile_s, GzCloser>;

bool readExact(gzFile File, void* Buffer, size_t Size, std::string& Error) {
  auto* Current = static_cast<unsigned char*>(Buffer);
  while (Size != 0) {
    unsigned int Chunk = static_cast<unsigned int>(
        std::min<size_t>(Size, std::numeric_limits<unsigned int>::max()));
    int Got = gzread(File, Current, Chunk);
    if (Got <= 0) {
      int Code = Z_OK;
      const char* Message = gzerror(File, &Code);
      std::ostringstream Stream;
      Stream << "truncated or unreadable sidecar";
      if (Message && *Message) {
        Stream << ": " << Message;
      }
      Error = Stream.str();
      return false;
    }
    Current += Got;
    Size -= static_cast<size_t>(Got);
  }
  return true;
}

bool readU8(gzFile File, uint8_t& Value, std::string& Error) {
  return readExact(File, &Value, sizeof(Value), Error);
}

bool readU16(gzFile File, uint16_t& Value, std::string& Error) {
  std::array<unsigned char, 2> Bytes{};
  if (!readExact(File, Bytes.data(), Bytes.size(), Error)) {
    return false;
  }
  Value = static_cast<uint16_t>(Bytes[0]) |
          (static_cast<uint16_t>(Bytes[1]) << 8);
  return true;
}

bool readU64(gzFile File, uint64_t& Value, std::string& Error) {
  std::array<unsigned char, 8> Bytes{};
  if (!readExact(File, Bytes.data(), Bytes.size(), Error)) {
    return false;
  }
  Value = 0;
  for (unsigned int I = 0; I < Bytes.size(); ++I) {
    Value |= static_cast<uint64_t>(Bytes[I]) << (I * 8);
  }
  return true;
}

bool readI64(gzFile File, int64_t& Value, std::string& Error) {
  uint64_t Bits = 0;
  if (!readU64(File, Bits, Error)) {
    return false;
  }
  std::memcpy(&Value, &Bits, sizeof(Value));
  return true;
}

bool readUuid(gzFile File, gtirb::UUID& Uuid, std::string& Error) {
  std::array<unsigned char, 16> Bytes{};
  if (!readExact(File, Bytes.data(), Bytes.size(), Error)) {
    return false;
  }
  std::copy(Bytes.begin(), Bytes.end(), Uuid.begin());
  return true;
}

template <typename T>
T* nodeByUuid(gtirb::Context& Context, const gtirb::UUID& Uuid) {
  return gtirb::dyn_cast_or_null<T>(gtirb::Node::getByUUID(Context, Uuid));
}

bool readAttributes(gzFile File, uint16_t Count,
                    gtirb::SymAttributeSet& Attributes, std::string& Error) {
  for (uint16_t I = 0; I < Count; ++I) {
    uint16_t Attribute = 0;
    if (!readU16(File, Attribute, Error)) {
      return false;
    }
    Attributes.insert(static_cast<gtirb::SymAttribute>(Attribute));
  }
  return true;
}

} // namespace

SymbolicExpressionSidecarResult restoreSymbolicExpressionSidecar(
    gtirb::Context& Context, gtirb::IR&, const std::string& Path) {
  SymbolicExpressionSidecarResult Result;
  UniqueGzFile File(reinterpret_cast<gzFile_s*>(gzopen(Path.c_str(), "rb")));
  if (!File) {
    Result.Error = "could not open symbolic-expression sidecar: " + Path;
    return Result;
  }
  gzFile RawFile = reinterpret_cast<gzFile>(File.get());

  std::array<unsigned char, 8> Header{};
  if (!readExact(RawFile, Header.data(), Header.size(), Result.Error) ||
      Header != Magic) {
    if (Result.Error.empty()) {
      Result.Error = "invalid symbolic-expression sidecar magic";
    }
    return Result;
  }

  uint64_t GroupCount = 0;
  uint64_t ExpectedExpressions = 0;
  if (!readU64(RawFile, GroupCount, Result.Error) ||
      !readU64(RawFile, ExpectedExpressions, Result.Error)) {
    return Result;
  }

  for (uint64_t Group = 0; Group < GroupCount; ++Group) {
    gtirb::UUID IntervalUuid;
    uint64_t RecordCount = 0;
    if (!readUuid(RawFile, IntervalUuid, Result.Error) ||
        !readU64(RawFile, RecordCount, Result.Error)) {
      return Result;
    }
    auto* Interval = nodeByUuid<gtirb::ByteInterval>(Context, IntervalUuid);
    if (!Interval || !Interval->getSection() ||
        !Interval->getSection()->getModule()) {
      Result.Error = "sidecar references an absent or detached byte interval";
      return Result;
    }
    auto* Module = Interval->getSection()->getModule();
    auto* Sizes =
        Module->getAuxData<gtirb::schema::SymbolicExpressionSizes>();
    if (!Sizes) {
      Module->addAuxData<gtirb::schema::SymbolicExpressionSizes>({});
      Sizes = Module->getAuxData<gtirb::schema::SymbolicExpressionSizes>();
    }

    for (uint64_t Record = 0; Record < RecordCount; ++Record) {
      uint64_t Offset = 0;
      uint8_t Kind = 0;
      uint8_t HasSize = 0;
      uint16_t AttributeCount = 0;
      uint64_t Size = 0;
      int64_t Addend = 0;
      if (!readU64(RawFile, Offset, Result.Error) ||
          !readU8(RawFile, Kind, Result.Error) ||
          !readU8(RawFile, HasSize, Result.Error) ||
          !readU16(RawFile, AttributeCount, Result.Error) ||
          !readU64(RawFile, Size, Result.Error) ||
          !readI64(RawFile, Addend, Result.Error)) {
        return Result;
      }
      if (Kind > 1 || HasSize > 1 || Offset >= Interval->getSize()) {
        Result.Error = "invalid symbolic-expression sidecar record";
        return Result;
      }
      if (Interval->getSymbolicExpression(Offset)) {
        Result.Error = "sidecar would replace an existing symbolic expression";
        return Result;
      }

      gtirb::SymAttributeSet Attributes;
      if (Kind == 0) {
        gtirb::UUID SymbolUuid;
        if (!readUuid(RawFile, SymbolUuid, Result.Error)) {
          return Result;
        }
        auto* Symbol = nodeByUuid<gtirb::Symbol>(Context, SymbolUuid);
        if (!Symbol ||
            !readAttributes(RawFile, AttributeCount, Attributes, Result.Error)) {
          if (Result.Error.empty()) {
            Result.Error = "sidecar references an absent symbol";
          }
          return Result;
        }
        Interval->addSymbolicExpression(
            Offset, gtirb::SymAddrConst{Addend, Symbol, Attributes});
      } else {
        int64_t Scale = 0;
        gtirb::UUID Symbol1Uuid;
        gtirb::UUID Symbol2Uuid;
        if (!readI64(RawFile, Scale, Result.Error) ||
            !readUuid(RawFile, Symbol1Uuid, Result.Error) ||
            !readUuid(RawFile, Symbol2Uuid, Result.Error)) {
          return Result;
        }
        auto* Symbol1 = nodeByUuid<gtirb::Symbol>(Context, Symbol1Uuid);
        auto* Symbol2 = nodeByUuid<gtirb::Symbol>(Context, Symbol2Uuid);
        if (!Symbol1 || !Symbol2 ||
            !readAttributes(RawFile, AttributeCount, Attributes, Result.Error)) {
          if (Result.Error.empty()) {
            Result.Error = "sidecar references an absent symbol";
          }
          return Result;
        }
        Interval->addSymbolicExpression(
            Offset,
            gtirb::SymAddrAddr{Scale, Addend, Symbol1, Symbol2, Attributes});
      }

      if (HasSize) {
        gtirb::Offset SizeOffset(Interval->getUUID(), Offset);
        if (Sizes->count(SizeOffset)) {
          Result.Error = "sidecar would replace an existing expression size";
          return Result;
        }
        Sizes->emplace(SizeOffset, Size);
        ++Result.Sizes;
      }
      ++Result.Expressions;
    }
    ++Result.Groups;
  }

  if (Result.Groups != GroupCount ||
      Result.Expressions != ExpectedExpressions) {
    Result.Error = "symbolic-expression sidecar count mismatch";
    return Result;
  }
  unsigned char Extra = 0;
  int Got = gzread(RawFile, &Extra, 1);
  if (Got != 0) {
    Result.Error = Got > 0 ? "trailing sidecar data" : "sidecar read failure";
    return Result;
  }
  Result.Success = true;
  return Result;
}
