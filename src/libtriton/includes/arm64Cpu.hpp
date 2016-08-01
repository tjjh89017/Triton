//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_ARM64CPU_HPP
#define TRITON_ARM64CPU_HPP

#include <map>
#include <set>
#include <tuple>
#include <vector>

#include "cpuInterface.hpp"
#include "instruction.hpp"
#include "memoryAccess.hpp"
#include "registerOperand.hpp"
#include "tritonTypes.hpp"
#include "arm64Semantics.hpp"



//! The Triton namespace
namespace triton {
/*!
 *  \addtogroup triton
 *  @{
 */

  //! The Architecture namespace
  namespace arch {
  /*!
   *  \ingroup triton
   *  \addtogroup arch
   *  @{
   */

    //! The arm64 namespace
    namespace arm64 {
    /*!
     *  \ingroup arch
     *  \addtogroup arm64
     *  @{
     */

      //! \class arm64Cpu
      /*! \brief This class is used to describe the arm64 (64-bits) spec. */
      class arm64Cpu : public CpuInterface {

        protected:

          /*! \brief map of address -> concrete value
           *
           * \description
           * **item1**: memory address<br>
           * **item2**: concrete value
           */
          std::map<triton::uint64, triton::uint8> memory;

          //! Concrete value of x0
          triton::uint8 x0[QWORD_SIZE];
          //! Concrete value of x1
          triton::uint8 x1[QWORD_SIZE];
          //! Concrete value of x2
          triton::uint8 x2[QWORD_SIZE];
          //! Concrete value of x3
          triton::uint8 x3[QWORD_SIZE];
          //! Concrete value of x4
          triton::uint8 x4[QWORD_SIZE];
          //! Concrete value of x5
          triton::uint8 x5[QWORD_SIZE];
          //! Concrete value of x6
          triton::uint8 x6[QWORD_SIZE];
          //! Concrete value of x7
          triton::uint8 x7[QWORD_SIZE];
          //! Concrete value of x8
          triton::uint8 x8[QWORD_SIZE];
          //! Concrete value of x9
          triton::uint8 x9[QWORD_SIZE];
          //! Concrete value of x10
          triton::uint8 x10[QWORD_SIZE];
          //! Concrete value of x11
          triton::uint8 x11[QWORD_SIZE];
          //! Concrete value of x12
          triton::uint8 x12[QWORD_SIZE];
          //! Concrete value of x13
          triton::uint8 x13[QWORD_SIZE];
          //! Concrete value of x14
          triton::uint8 x14[QWORD_SIZE];
          //! Concrete value of x15
          triton::uint8 x15[QWORD_SIZE];
          //! Concrete value of x16
          triton::uint8 x16[QWORD_SIZE];
          //! Concrete value of x17
          triton::uint8 x17[QWORD_SIZE];
          //! Concrete value of x18
          triton::uint8 x18[QWORD_SIZE];
          //! Concrete value of x19
          triton::uint8 x19[QWORD_SIZE];
          //! Concrete value of x20
          triton::uint8 x20[QWORD_SIZE];
          //! Concrete value of x21
          triton::uint8 x21[QWORD_SIZE];
          //! Concrete value of x22
          triton::uint8 x22[QWORD_SIZE];
          //! Concrete value of x23
          triton::uint8 x23[QWORD_SIZE];
          //! Concrete value of x24
          triton::uint8 x24[QWORD_SIZE];
          //! Concrete value of x25
          triton::uint8 x25[QWORD_SIZE];
          //! Concrete value of x26
          triton::uint8 x26[QWORD_SIZE];
          //! Concrete value of x27
          triton::uint8 x27[QWORD_SIZE];
          //! Concrete value of x28
          triton::uint8 x28[QWORD_SIZE];
          //! Concrete value of x29
          triton::uint8 x29[QWORD_SIZE];
          //! Concrete value of x30
          triton::uint8 x30[QWORD_SIZE];

          // TODO full register set

        public:
          arm64Cpu();
          //! Constructor by copy.
          arm64Cpu(const arm64Cpu& other);
          ~arm64Cpu();

          //! Copies a arm64Cpu class.
          void copy(const arm64Cpu& other);

          void init(void);
          void clear(void);
          bool isFlag(triton::uint32 regId) const;
          bool isRegister(triton::uint32 regId) const;
          bool isRegisterValid(triton::uint32 regId) const;

          // TODO Remove x86 specs

          //! Returns true if regId is a GRP.
          bool isGPR(triton::uint32 regId) const;

          //! Returns true if regId is a MMX register.
          bool isMMX(triton::uint32 regId) const;

          //! Returns true if regId is a SSE register.
          bool isSSE(triton::uint32 regId) const;

          //! Returns true if regId is a AVX-256 (YMM) register.
          bool isAVX256(triton::uint32 regId) const;

          //! Returns true if regId is a AVX-512 (ZMM) register.
          bool isAVX512(triton::uint32 regId) const;

          //! Returns true if regId is a control (cr) register.
          bool isControl(triton::uint32 regId) const;

          //! Returns true if regId is a Segment.
          bool isSegment(triton::uint32 regId) const;

          std::tuple<std::string, triton::uint32, triton::uint32, triton::uint32> getRegisterInformation(triton::uint32 reg) const;
          std::set<triton::arch::Register*> getAllRegisters(void) const;
          std::set<triton::arch::Register*> getParentRegisters(void) const;
          triton::uint512 getConcreteMemoryValue(const triton::arch::MemoryAccess& mem) const;
          std::vector<triton::uint8> getConcreteMemoryAreaValue(triton::uint64 baseAddr, triton::usize size) const;
          triton::uint512 getConcreteRegisterValue(const triton::arch::Register& reg) const;
          triton::uint32 invalidRegister(void) const;
          triton::uint32 numberOfRegisters(void) const;
          triton::uint32 registerBitSize(void) const;
          triton::uint32 registerSize(void) const;
          triton::uint8 getConcreteMemoryValue(triton::uint64 addr) const;
          void buildSemantics(triton::arch::Instruction& inst) const;
          void disassembly(triton::arch::Instruction& inst) const;
          void setConcreteMemoryValue(triton::uint64 addr, triton::uint8 value);
          void setConcreteMemoryValue(const triton::arch::MemoryAccess& mem);
          void setConcreteMemoryAreaValue(triton::uint64 baseAddr, const std::vector<triton::uint8>& values);
          void setConcreteMemoryAreaValue(triton::uint64 baseAddr, const triton::uint8* area, triton::usize size);
          void setConcreteRegisterValue(const triton::arch::Register& reg);
          bool isMemoryMapped(triton::uint64 baseAddr, triton::usize size=1);
          void unmapMemory(triton::uint64 baseAddr, triton::usize size=1);

          //! Copies a arm64Cpu class.
          void operator=(const arm64Cpu& other);
      };

    /*! @} End of arm64 namespace */
    };
  /*! @} End of arch namespace */
  };
/*! @} End of triton namespace */
};

#endif  /* !ARM64CPU_HPP */
